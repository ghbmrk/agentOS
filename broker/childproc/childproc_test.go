package childproc

// REQ: CRED-1, ARC-1

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/types"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// The canaries are synthetic (CLAUDE.md): an owner number in the
// reserved fictional range and a token-shaped string nothing issues.
const (
	ownerCanary = "+15550100999"
	tokenCanary = "canary-tok-6f1d0c2a9b"
)

// surface is childproc's whole exported API, each name with its type or
// signature: a changed result is as much a reviewed change as a new
// entry point (brief D1, D2; #651 L3 1).
var surface = []string{
	"Cmd.CombinedOutput: func() ([]byte, error)",
	"Cmd.Kill: func() error",
	"Cmd.Output: func() ([]byte, error)",
	"Cmd.Pid: func() int",
	"Cmd.Run: func() error",
	"Cmd.Signal: func(sig os.Signal) error",
	"Cmd.Start: func() error",
	"Cmd.StdinPipe: func() (io.WriteCloser, error)",
	"Cmd.StdoutPipe: func() (io.ReadCloser, error)",
	"Cmd.Wait: func() error",
	"Cmd: struct{c *os/exec.Cmd; env Env}",
	"Command: func(ctx context.Context, env Env, o Options, name string, args ...string) *Cmd",
	"Env: struct{pairs []string; built bool}",
	"ErrNoEnv: error",
	"ErrWaitDelay: error",
	"ExitError.Error: func() string",
	"ExitError.ExitCode: func() int",
	"ExitError: struct{msg string; code int}",
	"LookPath: func(file string) (string, error)",
	"NewEnv: func(kv ...string) Env",
	"Options: struct{Dir string; Stdin io.Reader; Stdout io.Writer; Stderr io.Writer; SysProcAttr *syscall.SysProcAttr; ExtraFiles []*os.File; WaitDelay time.Duration; KillGroup bool; OnCancel func()}",
}

var (
	loadOnce sync.Once
	loaded   *lintload.Loaded
	loadErr  error
)

// checkPkg returns package childproc as the shared lint loader type-checks
// it, failing on a file of it the loader leaves unread, or src type-checked
// against the same export data when given.
func checkPkg(t *testing.T, src map[string]string) *types.Package {
	t.Helper()
	loadOnce.Do(func() {
		loaded, loadErr = lintload.Load(".", lintload.Build{Also: []string{"fmt", "io", "os/exec", "reflect", "unsafe"}}, ".")
		if loadErr == nil && len(loaded.Packages) != 1 {
			loadErr = fmt.Errorf("loaded %d packages, want childproc alone", len(loaded.Packages))
		}
	})
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if src == nil {
		if unread, err := lintload.Unread(loaded); err != nil || len(unread) != 0 {
			t.Fatalf("files the check does not read: %q (%v)", unread, err)
		}
		return loaded.Packages[0].Types
	}
	var files []*ast.File
	for n, s := range src {
		f, err := parser.ParseFile(loaded.Fset, n, s, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	pkg, _, err := loaded.Check("childproc", files)
	if err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestTheHandleIsOpaque(t *testing.T) {
	pkg := checkPkg(t, nil)
	if bad := leaks(pkg); len(bad) > 0 {
		t.Fatalf("childproc's API yields what it must not (brief D1):\n%s", strings.Join(bad, "\n"))
	}
	if got := exported(pkg); !slices.Equal(got, surface) {
		t.Fatalf("childproc's exported API changed; review it against D1 and D2, then update surface:\ngot  %q\nwant %q", got, surface)
	}
}

func TestOpaqueCheckCatchesALeak(t *testing.T) {
	pkg := checkPkg(t, map[string]string{"x.go": `package childproc
import ("fmt"; "io"; "os/exec"; "reflect"; "unsafe")
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
type Starter interface{ Start() error; Run() error }
func (d *D) Raw() Starter { return d.c }
func (d *D) Str() fmt.Stringer { return d.c }
func (d *D) Unwrapper() interface{ Error() string; Unwrap() error } { return nil }
func (d *D) Each(f func(any)) {}
func (d *D) In(f func() any) {}
func (d *D) W() io.Writer { return nil }
func (d *D) Err() error { return nil }
type K struct{ X fmt.Stringer }
func Z() K { return K{} }
type H struct{ Hook interface{ Put(any) } }
func (d *D) Out(p *any) {}
func (d *D) Ch(c chan<- fmt.Stringer) {}
func (d *D) Fill(m map[string]any) {}
func (d *D) Slots(s []any) {}
func (d *D) Visit(v interface{ Put(any) }) {}
func (d *D) Sink() interface{ Put(any) } { return nil }
func (d *D) Feed() chan<- fmt.Stringer { return nil }
func (d *D) Recv(c <-chan fmt.Stringer) {}
`})
	got := leaks(pkg)
	for _, want := range []string{"A: embeds", "B.C", "D.Cmd", "D.Any", "D.V", "D.P", "D.M", "I.Get", "New", "F: embeds",
		// D1's interface clause (#651 L3 1, Security 4a 2): an interface
		// an os/exec type satisfies, and any handed to a callback.
		"D.Raw", "D.Str", "D.Unwrapper", "D.Each",
		// A type walked first as a declaration, then as a result.
		"Z.X",
		// An interface the caller supplies has its methods called by the
		// package, so their arguments flow out; and what a parameter
		// points to or carries, the package can write (#659 L3 2,
		// Security 4a 2).
		"H.Hook.Put", "D.Visit", "D.Out", "D.Ch", "D.Fill", "D.Slots"} {
		if !slices.ContainsFunc(got, func(s string) bool { return strings.HasPrefix(s, want) }) {
			t.Errorf("no leak reported for %s; got %q", want, got)
		}
	}
	for _, s := range got {
		if strings.HasPrefix(s, "G") {
			t.Errorf("an unexported method or field was reported: %s", s)
		}
		// error is exempt: TestErrorsCarryNoExecType holds it at run time.
		// An any the caller's callback returns flows in, not out; so do
		// the arguments to a method of an interface the package returns,
		// a value the caller sends on a channel the package returns, and
		// a value the package receives.
		for _, ok := range []string{"D.W", "D.Err", "D.In", "D.Sink", "D.Feed", "D.Recv"} {
			if strings.HasPrefix(s, ok+":") {
				t.Errorf("reported, but yields no os/exec value: %s", s)
			}
		}
	}
}

// A changed result type changes the pin, not only a new name (#651 L3 1).
func TestTheSurfacePinsSignatures(t *testing.T) {
	pkg := checkPkg(t, map[string]string{"x.go": `package childproc
import "fmt"
type C struct{ X int }
func (C) Raw() fmt.Stringer { return nil }
`})
	want := []string{"C.Raw: func() fmt.Stringer", "C: struct{X int}"}
	if got := exported(pkg); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// leaks walks every exported identifier's type and reports an os/exec
// type, an embedded one, or an accessor that could yield one (any or an
// empty interface, an interface an os/exec type satisfies, reflect.Value,
// unsafe.Pointer). result marks a value that flows out of the package: a
// result, an argument the package passes to a caller's callback or to a
// method of an interface the caller supplies, or a value the package can
// write through what a parameter points to or carries.
func leaks(pkg *types.Package) []string {
	var bad []string
	// A type is walked once per direction: as a declaration its fields
	// flow in, as a result they flow out.
	type visit struct {
		t      types.Type
		result bool
	}
	seen := map[visit]bool{}
	execTypes := execTypes(pkg)
	// satisfied reports the os/exec type an interface result could hold.
	// error is exempt: every start returns one, and scrub maps each
	// os/exec error to childproc's (TestErrorsCarryNoExecType).
	satisfied := func(t types.Type) string {
		it, ok := t.Underlying().(*types.Interface)
		if !ok || it.Empty() || types.Identical(t, types.Universe.Lookup("error").Type()) {
			return ""
		}
		for _, x := range execTypes {
			if types.Implements(x, it) {
				return x.String()
			}
		}
		return ""
	}
	var walk func(where string, t types.Type, result bool)
	walk = func(where string, t types.Type, result bool) {
		if result {
			if x := satisfied(types.Unalias(t)); x != "" {
				bad = append(bad, where+": an interface "+x+" satisfies")
				return
			}
		}
		switch t := types.Unalias(t).(type) {
		case *types.Basic:
			if t.Kind() == types.UnsafePointer {
				bad = append(bad, where+": unsafe.Pointer")
			}
		// What a pointer, slice or map reaches is shared: either side
		// may write it for the other to read, so it flows both ways (an
		// out-param such as *any; #659 L3 2, Security 4a 2).
		case *types.Pointer:
			walk(where, t.Elem(), false)
			walk(where, t.Elem(), true)
		case *types.Slice:
			walk(where, t.Elem(), false)
			walk(where, t.Elem(), true)
		case *types.Array:
			walk(where, t.Elem(), result)
		case *types.Chan:
			// A value goes from whoever holds the send end to whoever
			// holds the receive end.
			switch t.Dir() {
			case types.SendOnly:
				walk(where, t.Elem(), !result)
			case types.RecvOnly:
				walk(where, t.Elem(), result)
			default:
				walk(where, t.Elem(), false)
				walk(where, t.Elem(), true)
			}
		case *types.Map:
			for _, r := range []bool{false, true} {
				walk(where, t.Key(), r)
				walk(where, t.Elem(), r)
			}
		case *types.Signature:
			// A parameter flows the other way from its signature: a
			// callback's arguments flow out.
			for v := range t.Params().Variables() {
				walk(where, v.Type(), !result)
			}
			for v := range t.Results().Variables() {
				walk(where, v.Type(), result)
			}
		case *types.Interface:
			if t.Empty() && result {
				bad = append(bad, where+": any")
			}
			// The side that implements an interface is the one the
			// value flows to, so a method's arguments flow with the
			// interface value: one the caller supplies has the package
			// call it, passing values out (#659 L3 2, Security 4a 2).
			for m := range t.Methods() {
				walk(where+"."+m.Name(), m.Type(), result)
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
			if t.Obj().Pkg() != pkg || seen[visit{t, result}] {
				return
			}
			seen[visit{t, result}] = true
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

// execTypes are the exported os/exec named types and pointers to them,
// as pkg imports them; none if it does not import os/exec.
func execTypes(pkg *types.Package) []types.Type {
	var out []types.Type
	for _, im := range pkg.Imports() {
		if im.Path() != "os/exec" {
			continue
		}
		for _, n := range im.Scope().Names() {
			if tn, ok := im.Scope().Lookup(n).(*types.TypeName); ok && tn.Exported() {
				out = append(out, tn.Type(), types.NewPointer(tn.Type()))
			}
		}
	}
	return out
}

// execTyped reports a type that is, or points to, an os/exec type.
func execTyped(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "os/exec"
}

// exported lists the package's exported names and exported methods, each
// with its type: a type's underlying type, a func's or method's signature.
func exported(pkg *types.Package) []string {
	var out []string
	q := types.RelativeTo(pkg)
	scope := pkg.Scope()
	for _, n := range scope.Names() {
		o := scope.Lookup(n)
		if !o.Exported() {
			continue
		}
		if tn, ok := o.(*types.TypeName); ok {
			out = append(out, n+": "+types.TypeString(tn.Type().Underlying(), q))
			ms := types.NewMethodSet(types.NewPointer(tn.Type()))
			for s := range ms.Methods() {
				if s.Obj().Exported() && s.Obj().Pkg() == pkg {
					out = append(out, n+"."+s.Obj().Name()+": "+types.TypeString(s.Type(), q))
				}
			}
			continue
		}
		out = append(out, n+": "+types.TypeString(o.Type(), q))
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
		{"a filtered copy of the daemon's environment that keeps AGENTOS_OWNER", NewEnv(own("PATH", "AGENTOS_OWNER")...)},
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

// A malformed entry may be a bare secret passed without its key: the
// refusal names its index, never its text (#651 UX 3).
func TestAMalformedEntryIsNotPrinted(t *testing.T) {
	for _, kv := range []string{tokenCanary, "=" + tokenCanary} {
		err := NewEnv("PATH=/bin", kv).check()
		if err == nil || strings.Contains(err.Error(), tokenCanary) || !strings.Contains(err.Error(), "entry 1") {
			t.Errorf("%q: %v", kv, err)
		}
	}
}

// A refused environment is refused before a pipe is made, so a refused
// start leaves no pipe open (r8b: browser's driver takes both pipes).
func TestARefusedEnvironmentMakesNoPipe(t *testing.T) {
	c := Command(context.Background(), NewEnv("LD_PRELOAD=/x.so"), Options{}, "/bin/cat")
	if _, err := c.StdinPipe(); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("StdinPipe: %v", err)
	}
	if _, err := c.StdoutPipe(); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Errorf("StdoutPipe: %v", err)
	}
}

// OnCancel runs when the context ends, before the child is killed
// (r8b: gvisor's Exec kills the command inside the sandbox from it).
func TestOnCancelRunsBeforeTheKill(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	called := make(chan bool, 1)
	c := Command(ctx, NewEnv(), Options{OnCancel: func() { called <- true }}, "/bin/sleep", "30")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	cancel()
	var ee *ExitError
	if err := c.Wait(); !errors.As(err, &ee) || ee.ExitCode() != -1 {
		t.Fatalf("wait: %v, want a killed child", err)
	}
	select {
	case <-called:
	default:
		t.Fatal("OnCancel was not called")
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
