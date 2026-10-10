package core

// REQ: ARC-1
//
// The trusted core is the list in core.txt (SIM-core, D-095). A package
// outside the core and its wiring may call a core function or method only
// when core.txt marks it open (the journal's Submit, reads, sanctioned
// interfaces) or allows that package by name; anything else is a write
// path into the core and fails here. The check type-checks each package
// against the compiler's export data, so a call through an embedded field
// or a method value counts as much as a direct call. An interface the
// package declares counts too: when a core type satisfies it, each core
// method behind the interface's methods is reachable through it.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modPrefix = "github.com/ghbmrk/agentos/broker/"

// moduleRoot is broker/, where go list runs; the test runs in broker/core.
const moduleRoot = ".."

type list struct {
	core, wiring map[string]bool
	open         []string
	allow        map[string][]string // non-core package -> symbols
}

func readList(t *testing.T) list {
	t.Helper()
	f, err := os.Open("core.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	l := list{core: map[string]bool{}, wiring: map[string]bool{}, allow: map[string][]string{}}
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		w := strings.Fields(line)
		switch {
		case w[0] == "core" && len(w) == 2:
			l.core[w[1]] = true
		case w[0] == "wiring" && len(w) == 2:
			l.wiring[w[1]] = true
		case w[0] == "open" && len(w) == 2:
			l.open = append(l.open, w[1])
		case w[0] == "allow" && len(w) > 4 && w[3] == "--":
			l.allow[w[1]] = append(l.allow[w[1]], w[2])
		default:
			t.Fatalf("core.txt:%d: unreadable line %q", n, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(l.core) == 0 {
		t.Fatal("core.txt names no core package")
	}
	return l
}

// matches reports whether sym (pkg.Func or pkg.Type.Method) is covered by
// pattern (exact, pkg.Type.* or pkg.*).
func matches(pattern, sym string) bool {
	if p, ok := strings.CutSuffix(pattern, ".*"); ok {
		return strings.HasPrefix(sym, p+".")
	}
	return pattern == sym
}

func covered(patterns []string, sym string) bool {
	for _, p := range patterns {
		if matches(p, sym) {
			return true
		}
	}
	return false
}

type listed struct {
	ImportPath      string
	Dir             string
	Export          string
	CompiledGoFiles []string
	DepOnly         bool
	Error           *struct{ Err string }
}

// load runs go list on patterns with their dependencies and returns the
// packages the patterns name and an importer over everyone's export data.
func load(t *testing.T, fset *token.FileSet, patterns ...string) ([]listed, types.Importer) {
	t.Helper()
	args := append([]string{"list", "-export", "-compiled", "-deps",
		"-json=ImportPath,Dir,Export,CompiledGoFiles,DepOnly,Error"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = moduleRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	export := map[string]string{}
	var targets []listed
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listed
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		export[p.ImportPath] = p.Export
		if !p.DepOnly {
			targets = append(targets, p)
		}
	}
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		e, ok := export[path]
		if !ok || e == "" {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(e)
	})
	return targets, imp
}

// symbol names a core function or method as core.txt does, or "" when obj
// is not one.
func symbol(obj types.Object, core map[string]bool) string {
	f, ok := obj.(*types.Func)
	if !ok || f.Pkg() == nil {
		return ""
	}
	pkg, ok := strings.CutPrefix(f.Pkg().Path(), modPrefix)
	if !ok || !core[pkg] {
		return ""
	}
	f = f.Origin()
	recv := f.Type().(*types.Signature).Recv()
	if recv == nil {
		return pkg + "." + f.Name()
	}
	rt := recv.Type()
	if p, ok := rt.(*types.Pointer); ok {
		rt = p.Elem()
	}
	if n, ok := rt.(*types.Named); ok {
		return pkg + "." + n.Obj().Name() + "." + f.Name()
	}
	// A method of an unnamed interface: name it by the method alone, which
	// no open line covers, so it counts as a write path.
	return pkg + ".?." + f.Name()
}

// writePaths type-checks the non-test files of each package patterns name,
// other than core and wiring packages, and returns one line per package
// and write path it calls that core.txt does not open or allow.
func writePaths(t *testing.T, l list, patterns ...string) []string {
	t.Helper()
	fset := token.NewFileSet()
	// Load the core with the patterns, so every core type is in hand for
	// the interface pass whatever the patterns import.
	all := append([]string{}, patterns...)
	for p := range l.core {
		all = append(all, "./"+p)
	}
	targets, imp := load(t, fset, all...)
	coreTypes := namedTypes(t, imp, l.core)
	var found []string
	for _, p := range targets {
		pkg, ok := strings.CutPrefix(p.ImportPath, modPrefix)
		if !ok || l.core[pkg] || l.wiring[pkg] {
			continue
		}
		var files []*ast.File
		for _, name := range p.CompiledGoFiles {
			if !filepath.IsAbs(name) {
				name = filepath.Join(p.Dir, name)
			}
			af, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, af)
		}
		info := &types.Info{Uses: map[*ast.Ident]types.Object{}, Types: map[ast.Expr]types.TypeAndValue{}}
		if _, err := (&types.Config{Importer: imp}).Check(p.ImportPath, fset, files, info); err != nil {
			t.Fatalf("type-check %s: %v", p.ImportPath, err)
		}
		seen := map[string]bool{}
		for id, obj := range info.Uses {
			sym := symbol(obj, l.core)
			if sym == "" || covered(l.open, sym) || covered(l.allow[pkg], sym) {
				continue
			}
			if !seen[sym] {
				seen[sym] = true
				found = append(found, fmt.Sprintf("%s calls core write path %s (%s)", pkg, sym, fset.Position(id.Pos())))
			}
		}
		for expr, tv := range info.Types {
			if _, ok := expr.(*ast.InterfaceType); !ok {
				continue
			}
			iface, ok := tv.Type.Underlying().(*types.Interface)
			if !ok {
				continue
			}
			for _, sym := range throughInterface(iface, coreTypes, l.core) {
				if covered(l.open, sym) || covered(l.allow[pkg], sym) || seen[sym] {
					continue
				}
				seen[sym] = true
				found = append(found, fmt.Sprintf("%s reaches core write path %s through an interface (%s)", pkg, sym, fset.Position(expr.Pos())))
			}
		}
	}
	sort.Strings(found)
	return found
}

// namedTypes returns every non-generic, non-interface named type the core
// packages declare.
func namedTypes(t *testing.T, imp types.Importer, core map[string]bool) []*types.Named {
	t.Helper()
	var named []*types.Named
	for p := range core {
		tp, err := imp.Import(modPrefix + p)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range tp.Scope().Names() {
			tn, ok := tp.Scope().Lookup(name).(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			n, ok := tn.Type().(*types.Named)
			if !ok || n.TypeParams().Len() > 0 || types.IsInterface(n) {
				continue
			}
			named = append(named, n)
		}
	}
	return named
}

// throughInterface returns the core methods reachable through iface: for
// each core type T where T or *T satisfies it, the core method behind each
// of iface's methods.
func throughInterface(iface *types.Interface, coreTypes []*types.Named, core map[string]bool) []string {
	if !iface.IsMethodSet() || iface.NumMethods() == 0 {
		return nil
	}
	var syms []string
	for _, n := range coreTypes {
		ptr := types.NewPointer(n)
		if !types.Implements(n, iface) && !types.Implements(ptr, iface) {
			continue
		}
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			obj, _, _ := types.LookupFieldOrMethod(ptr, false, m.Pkg(), m.Name())
			if sym := symbol(obj, core); sym != "" {
				syms = append(syms, sym)
			}
		}
	}
	return syms
}

func TestNoWritePathOutsideTheCore(t *testing.T) {
	for _, f := range writePaths(t, readList(t), "./...") {
		t.Error(f + "; submit an intent instead, or open or allow it in broker/core/core.txt with a reason")
	}
}

// A package that writes grants directly fails the check; its Submit does not.
func TestAFixtureThatWritesGrantsFails(t *testing.T) {
	found := writePaths(t, readList(t), "./core/testdata/writesgrants")
	if len(found) != 1 || !strings.HasPrefix(found[0], "core/testdata/writesgrants calls core write path grants.Gate.Decide ") {
		t.Fatalf("want exactly the fixture's grants.Gate.Decide call, got %q", found)
	}
}

// A package that declares an interface a core type satisfies through a
// write path fails the check, with no call to the core at all.
func TestAFixtureThatDecidesThroughAnInterfaceFails(t *testing.T) {
	found := writePaths(t, readList(t), "./core/testdata/decidesgrants")
	if len(found) != 1 || !strings.HasPrefix(found[0], "core/testdata/decidesgrants reaches core write path grants.Gate.Decide through an interface ") {
		t.Fatalf("want exactly the fixture's grants.Gate.Decide interface, got %q", found)
	}
}

// Each list entry names a real package or symbol, so a rename cannot leave
// a stale open line that a new function of the same name would inherit.
func TestEveryCoreListEntryExists(t *testing.T) {
	l := readList(t)
	var pats []string
	for _, set := range []map[string]bool{l.core, l.wiring} {
		for p := range set {
			pats = append(pats, "./"+p)
		}
	}
	for p := range l.allow {
		pats = append(pats, "./"+p)
	}
	sort.Strings(pats)
	fset := token.NewFileSet()
	_, imp := load(t, fset, pats...) // fails on a package that does not exist
	syms := append([]string{}, l.open...)
	for _, s := range l.allow {
		syms = append(syms, s...)
	}
	for _, s := range syms {
		pkg, rest, _ := strings.Cut(s, ".")
		if !l.core[pkg] {
			t.Errorf("core.txt: %s is not in a core package", s)
			continue
		}
		tp, err := imp.Import(modPrefix + pkg)
		if err != nil {
			t.Fatal(err)
		}
		if rest == "*" {
			continue
		}
		name, method, isMethod := strings.Cut(rest, ".")
		obj := tp.Scope().Lookup(name)
		switch {
		case obj == nil:
			t.Errorf("core.txt: %s: %s.%s does not exist", s, pkg, name)
		case !isMethod:
			if _, ok := obj.(*types.Func); !ok {
				t.Errorf("core.txt: %s is not a function", s)
			}
		case method == "*":
			if _, ok := obj.(*types.TypeName); !ok {
				t.Errorf("core.txt: %s: %s is not a type", s, name)
			}
		default:
			m, _, _ := types.LookupFieldOrMethod(types.NewPointer(obj.Type()), true, tp, method)
			if _, ok := m.(*types.Func); !ok {
				t.Errorf("core.txt: %s is not a method", s)
			}
		}
	}
}
