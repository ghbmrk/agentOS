package childproc

// REQ: CRED-1, ARC-1

import (
	"context"
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The canaries are synthetic (CLAUDE.md): an owner number in the
// reserved fictional range and a token-shaped string nothing issues.
const (
	ownerCanary = "+15550100999"
	tokenCanary = "canary-tok-6f1d0c2a9b"
)

// surface is childproc's whole exported API. A new entry point (a
// ProcAttr-taking start, an accessor) is a reviewed change to this list
// (brief D1, D2).
var surface = []string{
	"Cmd", "Cmd.CombinedOutput", "Cmd.Kill", "Cmd.Output", "Cmd.Pid", "Cmd.Run", "Cmd.Signal",
	"Cmd.Start", "Cmd.StdinPipe", "Cmd.StdoutPipe", "Cmd.Wait",
	"Command", "Env", "ErrNoEnv", "ErrWaitDelay", "ExitError", "ExitError.Error", "ExitError.ExitCode",
	"LookPath", "NewEnv", "Options",
}

// checkPkg type-checks the non-test Go files of dir, or src when given,
// with the stdlib source importer (no new module).
func checkPkg(t *testing.T, dir string, src map[string]string) *types.Package {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	if src == nil {
		names, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, n := range names {
			if strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, n, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
	} else {
		for n, s := range src {
			f, err := parser.ParseFile(fset, n, s, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, f)
		}
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check("childproc", fset, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestTheHandleIsOpaque(t *testing.T) {
	pkg := checkPkg(t, ".", nil)
	if bad := leaks(pkg); len(bad) > 0 {
		t.Fatalf("childproc's API yields what it must not (brief D1):\n%s", strings.Join(bad, "\n"))
	}
	if got := exported(pkg); !slices.Equal(got, surface) {
		t.Fatalf("childproc's exported API changed; review it against D1 and D2, then update surface:\ngot  %q\nwant %q", got, surface)
	}
}

func TestOpaqueCheckCatchesALeak(t *testing.T) {
	pkg := checkPkg(t, "", map[string]string{"x.go": `package childproc
import ("os/exec"; "reflect"; "unsafe")
type A struct{ exec.Cmd }
type B struct{ C *exec.Cmd }
type D struct{ c *exec.Cmd }
func (d *D) Cmd() *exec.Cmd { return d.c }
func (d *D) Any() any { return d.c }
func (d *D) V() reflect.Value { return reflect.ValueOf(d.c) }
func (d *D) P() unsafe.Pointer { return unsafe.Pointer(d.c) }
func (d *D) M() map[string][]func() *exec.Cmd { return nil }
type I interface{ Get() *exec.Cmd }
func New() exec.Cmd { return exec.Cmd{} }
type e struct{ *exec.Cmd }
type F struct{ e }
type G struct{ d *D }
func (G) ok() *exec.Cmd { return nil }
`})
	got := leaks(pkg)
	for _, want := range []string{"A: embeds", "B.C", "D.Cmd", "D.Any", "D.V", "D.P", "D.M", "I.Get", "New", "F: embeds"} {
		if !slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, want) }) {
			t.Errorf("no leak reported for %s; got %q", want, got)
		}
	}
	for _, s := range got {
		if strings.HasPrefix(s, "G") {
			t.Errorf("an unexported method or field was reported: %s", s)
		}
	}
}

// leaks walks every exported identifier's type and reports an os/exec
// type, an embedded one, or an accessor that could yield one (any or an
// empty interface, reflect.Value, unsafe.Pointer).
func leaks(pkg *types.Package) []string {
	var bad []string
	seen := map[types.Type]bool{}
	var walk func(where string, t types.Type, result bool)
	walk = func(where string, t types.Type, result bool) {
		switch t := types.Unalias(t).(type) {
		case *types.Basic:
			if t.Kind() == types.UnsafePointer {
				bad = append(bad, where+": unsafe.Pointer")
			}
		case *types.Pointer:
			walk(where, t.Elem(), result)
		case *types.Slice:
			walk(where, t.Elem(), result)
		case *types.Array:
			walk(where, t.Elem(), result)
		case *types.Chan:
			walk(where, t.Elem(), result)
		case *types.Map:
			walk(where, t.Key(), result)
			walk(where, t.Elem(), result)
		case *types.Signature:
			for v := range t.Params().Variables() {
				walk(where, v.Type(), false)
			}
			for v := range t.Results().Variables() {
				walk(where, v.Type(), true)
			}
		case *types.Interface:
			if t.Empty() && result {
				bad = append(bad, where+": any")
			}
			for m := range t.Methods() {
				walk(where+"."+m.Name(), m.Type(), true)
			}
		case *types.Struct:
			for f := range t.Fields() {
				if f.Embedded() {
					if execTyped(f.Type()) {
						bad = append(bad, where+": embeds "+f.Type().String())
					}
					walk(where, f.Type(), result)
				} else if f.Exported() {
					walk(where+"."+f.Name(), f.Type(), result)
				}
			}
		case *types.Named:
			if o := t.Obj(); o.Pkg() != nil && o.Pkg().Path() == "os/exec" {
				bad = append(bad, where+": "+t.String())
				return
			}
			if o := t.Obj(); o.Pkg() != nil && o.Pkg().Path() == "reflect" && o.Name() == "Value" {
				bad = append(bad, where+": reflect.Value")
				return
			}
			if t.Obj().Pkg() != pkg || seen[t] {
				return
			}
			seen[t] = true
			walk(where, t.Underlying(), result)
			for m := range t.Methods() {
				if m.Exported() {
					walk(t.Obj().Name()+"."+m.Name(), m.Type(), true)
				}
			}
		}
	}
	scope := pkg.Scope()
	for _, n := range scope.Names() {
		o := scope.Lookup(n)
		if !o.Exported() {
			continue
		}
		switch o.(type) {
		case *types.TypeName:
			if execTyped(o.Type().Underlying()) {
				bad = append(bad, n+": "+o.Type().Underlying().String())
			}
			walk(n, o.Type(), false)
		default:
			walk(n, o.Type(), true)
		}
	}
	sort.Strings(bad)
	return bad
}

// execTyped reports a type that is, or points to, an os/exec type.
func execTyped(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "os/exec"
}

// exported lists the package's exported names and exported methods.
func exported(pkg *types.Package) []string {
	var out []string
	scope := pkg.Scope()
	for _, n := range scope.Names() {
		o := scope.Lookup(n)
		if !o.Exported() {
			continue
		}
		out = append(out, n)
		if tn, ok := o.(*types.TypeName); ok {
			ms := types.NewMethodSet(types.NewPointer(tn.Type()))
			for s := range ms.Methods() {
				if s.Obj().Exported() && s.Obj().Pkg() == pkg {
					out = append(out, n+"."+s.Obj().Name())
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestTheEnvironmentIsDeniedByDefault(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", ownerCanary)
	t.Setenv("SOME_API_TOKEN", tokenCanary)
	for _, tc := range []struct {
		name string
		env  Env
	}{
		{"zero Env", Env{}},
		{"key not allowlisted", NewEnv("PATH=/bin", "LD_PRELOAD=/x.so")},
		{"AGENTOS_ key", NewEnv("AGENTOS_OWNER=" + ownerCanary)},
		{"AGENTOS_ key, any value", NewEnv("AGENTOS_X=1")},
		{"owner number under an allowed key", NewEnv("HOME=" + ownerCanary)},
		{"owner number inside an allowed value", NewEnv("HOME=/run/" + ownerCanary + "/x")},
		{"credential value under an allowed key", NewEnv("TMPDIR=" + tokenCanary)},
		{"no =", NewEnv("PATH")},
		{"empty key", NewEnv("=x")},
		{"NUL", NewEnv("PATH=/bin\x00HOME=/")},
		{"duplicate key", NewEnv("PATH=/bin", "PATH=/usr/bin")},
		{"a filtered copy of the daemon's own environment", NewEnv(own("PATH", "AGENTOS_OWNER")...)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Command(context.Background(), tc.env, Options{}, "/bin/true")
			err := c.Run()
			if err == nil {
				t.Fatal("started")
			}
			if !strings.Contains(err.Error(), "childproc") {
				t.Fatalf("not refused by the check: %v", err)
			}
			if c.Pid() > 0 {
				t.Fatalf("a process started: pid %d", c.Pid())
			}
		})
	}
	if !errors.Is(Command(context.Background(), Env{}, Options{}, "/bin/true").Run(), ErrNoEnv) {
		t.Error("a zero Env is not ErrNoEnv")
	}
}

// own picks keys from the process's environment, as a filter of
// os.Environ would.
func own(keys ...string) []string {
	var out []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if slices.Contains(keys, k) {
			out = append(out, kv)
		}
	}
	return out
}

// A configured path is not a secret: a child's HOME may lie under one.
func TestAConfiguredPathIsNotASecret(t *testing.T) {
	t.Setenv("AGENTOS_STATE_DIR", "/var/lib/agentos-test")
	t.Setenv("AGENTOS_MODEM_UID", "1001")
	if err := NewEnv("HOME=/var/lib/agentos-test/fuzz/run1", "PATH=/usr/bin:/bin", "GOFLAGS=-p=1001x").check(); err != nil {
		t.Fatal(err)
	}
	if err := NewEnv("GOFLAGS=1001").check(); err == nil {
		t.Fatal("a short secret matched whole was not refused")
	}
}

func TestNilContextPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	var ctx context.Context
	Command(ctx, NewEnv(), Options{}, "/bin/true")
}

func TestTheChildSeesExactlyTheBuiltEnvironment(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", ownerCanary)
	t.Setenv("SOME_API_TOKEN", tokenCanary)
	kv := []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent"}
	env := NewEnv(kv...)
	kv[1] = "HOME=" + ownerCanary // the caller's slice changes after NewEnv
	got := seenEnv(t, env)
	if want := []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin"}; !slices.Equal(got, want) {
		t.Fatalf("child env %q, want %q", got, want)
	}
}

func TestAnEmptyEnvIsEmpty(t *testing.T) {
	t.Setenv("AGENTOS_OWNER", ownerCanary)
	if got := seenEnv(t, NewEnv()); len(got) != 0 {
		t.Fatalf("child env %q, want none", got)
	}
}

func TestErrorsCarryNoExecType(t *testing.T) {
	ctx := context.Background()
	errs := map[string]error{
		"exit":    Command(ctx, NewEnv(), Options{}, "/bin/false").Run(),
		"missing": Command(ctx, NewEnv(), Options{}, "/nonexistent/x").Run(),
		"lookup":  Command(ctx, NewEnv(), Options{}, "no-such-binary-anywhere").Run(),
	}
	_, errs["lookpath"] = LookPath("no-such-binary-anywhere")
	for name, err := range errs {
		if err == nil {
			t.Fatalf("%s: no error", name)
		}
		for e := err; e != nil; e = errors.Unwrap(e) {
			if p := reflect.TypeOf(e); strings.Contains(p.String(), "exec.") || pkgPath(p) == "os/exec" {
				t.Errorf("%s: error chain holds %v", name, p)
			}
		}
	}
	var ee *ExitError
	if !errors.As(errs["exit"], &ee) || ee.ExitCode() != 1 {
		t.Errorf("exit: %v is not an ExitError with code 1", errs["exit"])
	}
	if errors.As(errs["missing"], &ee) {
		t.Error("a start failure is an ExitError")
	}
	c := Command(ctx, NewEnv(), Options{}, "/bin/cat")
	in, err := c.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{in, out} {
		if p := pkgPath(reflect.TypeOf(v)); p == "os/exec" {
			t.Errorf("a pipe is an os/exec value: %T", v)
		}
	}
}

func pkgPath(t reflect.Type) string {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.PkgPath()
}

// seenEnv starts env(1) through childproc with env and returns what it
// printed, sorted.
func seenEnv(t *testing.T, env Env) []string {
	t.Helper()
	out, err := Command(context.Background(), env, Options{}, "/usr/bin/env").Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(out))
	sort.Strings(got)
	return got
}
