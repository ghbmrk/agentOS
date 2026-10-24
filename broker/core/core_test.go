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
	"path"
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

// An allow line covers only the package it names: one written for another
// package leaves each fixture flagged, and one written for the
// fixture clears it, so the first result is the scoping and not a broken
// allow.
func TestAnAllowLineCoversOnlyItsPackage(t *testing.T) {
	// writesgrants calls the write path; decidesgrants reaches it through an
	// interface, which writePaths checks separately.
	for _, fixture := range []string{"core/testdata/writesgrants", "core/testdata/decidesgrants"} {
		for _, c := range []struct {
			pkg  string
			want int
		}{{"control", 1}, {fixture, 0}} {
			l := readList(t)
			l.allow[c.pkg] = append(l.allow[c.pkg], "grants.Gate.Decide")
			if found := writePaths(t, l, "./"+fixture); len(found) != c.want {
				t.Errorf("%s, allow %s grants.Gate.Decide: want %d finding(s), got %q", fixture, c.pkg, c.want, found)
			}
		}
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

// fixture reports whether a package core.txt allows is a test fixture: a
// *test package, or the kernel's seeded harness. core.txt grants fixtures
// wildcards on the grounds that only tests import them.
func fixture(pkg string) bool {
	return strings.HasSuffix(path.Base(pkg), "test") || pkg == "kernel/sim"
}

// goDirs returns the directories under root that patterns name ("./dir"
// or "./dir/..."), keeping each that holds a .go file. Unlike go list it
// keeps a package whose files the host build excludes. A "..." walk skips
// testdata, vendor, nested modules and directories go ignores, as go list
// does.
func goDirs(t *testing.T, root string, patterns ...string) []string {
	t.Helper()
	var dirs []string
	for _, pat := range patterns {
		top, walk := strings.CutSuffix(pat, "/...")
		top = filepath.Join(root, filepath.FromSlash(top))
		if !walk {
			if hasGo(top) {
				dirs = append(dirs, top)
			}
			continue
		}
		err := filepath.WalkDir(top, func(dir string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return err
			}
			name := d.Name()
			if dir != top && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && dir != filepath.Clean(root) {
				return filepath.SkipDir
			}
			if hasGo(dir) {
				dirs = append(dirs, dir)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return dirs
}

func hasGo(dir string) bool {
	names, _ := filepath.Glob(filepath.Join(dir, "*.go"))
	return len(names) > 0
}

// fileImports returns the import paths of every non-test file in dir,
// whatever its build constraints: go list sees one GOOS and tag set, and
// a shipped build may use another (cmd/agentos-egress is built with -tags
// agentos_e2e). cgo files and //go:build ignore scripts count too.
func fileImports(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	fset := token.NewFileSet()
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range f.Imports {
			if p := strings.Trim(spec.Path.Value, `"`); p != "C" {
				paths = append(paths, p)
			}
		}
	}
	return paths
}

// resolve maps import paths to the directories the go command builds them
// from in the module at root, using go list -find: the go command, not this
// test, applies vendor/, replace, go.work and the standard library. Build
// constraints do not change where a path resolves, only which files count,
// and fileImports reads those all. A standard package maps to "", and a
// path the go command cannot place fails the test.
func resolve(t *testing.T, root string, paths []string) map[string]string {
	t.Helper()
	args := append([]string{"list", "-e", "-find", "-f", "{{.ImportPath}}\t{{.Dir}}\t{{.Standard}}\t:{{if .Error}}{{.Error.Err}}{{end}}"}, paths...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	dirs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "\t", 4)
		switch {
		case len(f) != 4:
			t.Fatalf("go list: unreadable line %q", line)
		case f[2] == "true":
			dirs[f[0]] = ""
		case f[1] == "":
			t.Fatalf("import %q resolves to no directory: %s", f[0], strings.TrimPrefix(f[3], ":"))
		default:
			dirs[f[0]] = filepath.Clean(f[1])
		}
	}
	for _, p := range paths {
		if _, ok := dirs[p]; !ok {
			t.Fatalf("go list did not report import %q", p)
		}
	}
	return dirs
}

// fixtureImports returns one line per package that patterns name in the
// module at root, other than the
// fixtures themselves, whose non-test files reach a fixture core.txt
// allows, directly or through any package the go command would build,
// vendored and replaced ones included. Fixtures are matched by directory,
// so no second path to the same files hides one.
func fixtureImports(t *testing.T, root string, l list, patterns ...string) []string {
	t.Helper()
	abs := func(dir string) string {
		a, err := filepath.Abs(dir)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	fixtures := map[string]string{} // directory -> fixture package
	for pkg := range l.allow {
		if fixture(pkg) {
			fixtures[abs(filepath.Join(root, filepath.FromSlash(pkg)))] = pkg
		}
	}
	roots := goDirs(t, root, patterns...)
	// Build the graph of every directory the roots reach, resolving each
	// round's new import paths in one go list call.
	edges := map[string][]string{} // directory -> directories it imports
	where := map[string]string{}   // import path -> directory, "" for std
	frontier := []string{}
	for _, d := range roots {
		frontier = append(frontier, abs(d))
	}
	for len(frontier) > 0 {
		imports := map[string][]string{}
		var unknown []string
		for _, d := range frontier {
			if _, done := edges[d]; done {
				continue
			}
			edges[d] = nil
			if fixtures[d] != "" {
				continue // a fixture's own imports are its business
			}
			imports[d] = fileImports(t, d)
			for _, p := range imports[d] {
				if _, ok := where[p]; !ok {
					where[p] = "?"
					unknown = append(unknown, p)
				}
			}
		}
		if len(unknown) > 0 {
			for p, d := range resolve(t, root, unknown) {
				if d != "" {
					d = abs(d)
				}
				where[p] = d
			}
		}
		frontier = nil
		for d, ps := range imports {
			for _, p := range ps {
				if dep := where[p]; dep != "" {
					edges[d] = append(edges[d], dep)
					frontier = append(frontier, dep)
				}
			}
		}
	}
	var found []string
	for _, r := range roots {
		start := abs(r)
		if fixtures[start] != "" {
			continue
		}
		rel, err := filepath.Rel(abs(root), start)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.ToSlash(rel)
		seen := map[string]bool{start: true}
		queue := []string{start}
		for len(queue) > 0 {
			d := queue[0]
			queue = queue[1:]
			for _, dep := range edges[d] {
				if seen[dep] {
					continue
				}
				seen[dep] = true
				if fx := fixtures[dep]; fx != "" {
					found = append(found, fmt.Sprintf("%s imports test fixture %s outside its _test.go files", name, fx))
					continue
				}
				queue = append(queue, dep)
			}
		}
	}
	sort.Strings(found)
	return found
}

// REQ: ARC-1
// The wildcards core.txt grants loops/loopstest and kernel/sim hold only
// while no shipped package imports them (#2848).
func TestFixturesAreImportedOnlyByTests(t *testing.T) {
	l := readList(t)
	var n int
	for p := range l.allow {
		if fixture(p) {
			n++
		}
	}
	if n == 0 {
		t.Fatal("core.txt allows no test fixture; drop this check or fix fixture()")
	}
	for _, f := range fixtureImports(t, moduleRoot, l, "./...") {
		t.Error(f + "; move the import into a _test.go file")
	}
}

// A package that imports loopstest from a non-test file fails, directly,
// through a package in between, or from a file the host build leaves out;
// one that imports it only from a _test.go file passes.
func TestAFixtureImportedOutsideATestFails(t *testing.T) {
	l := readList(t)
	for _, c := range []struct {
		pkg  string
		want int
	}{
		{"core/testdata/importsloopstest", 1},
		{"core/testdata/viaimportsloopstest", 1},
		{"core/testdata/tagimportsloopstest", 1},
		{"core/testdata/goosimportsloopstest", 1},
		{"core/testdata/testimportsloopstest", 0},
	} {
		found := fixtureImports(t, moduleRoot, l, "./"+c.pkg)
		if len(found) != c.want {
			t.Errorf("%s: want %d finding(s), got %q", c.pkg, c.want, found)
		}
		for _, f := range found {
			if !strings.HasPrefix(f, c.pkg+" imports test fixture loops/loopstest ") {
				t.Errorf("%s: unexpected finding %q", c.pkg, f)
			}
		}
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

// writeFiles writes each file under root, making its directories.
func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// The go command, not the check, decides where an import resolves. In a
// scratch vendored module, a fixture reached through a dotless replaced
// module fails, and so does one reached through the root vendor/ copy that
// a nested vendor/ decoy would shadow if the check resolved paths itself.
func TestAFixtureReachedThroughVendorFails(t *testing.T) {
	root := t.TempDir()
	const plant = "package %s\n\nimport _ \"example.com/m/fix/fixtest\"\n"
	writeFiles(t, root, map[string]string{
		"go.mod": "module example.com/m\n\ngo 1.21\n\nrequire (\n\thop v0.0.0\n\texample.com/vhop v0.0.0\n)\n\n" +
			"replace hop => ./third_party/hop\n\nreplace example.com/vhop => ./third_party/vhop\n",
		"fix/fixtest/fixtest.go":                   "package fixtest\n",
		"third_party/hop/go.mod":                   "module hop\n\ngo 1.21\n",
		"third_party/hop/hop.go":                   fmt.Sprintf(plant, "hop"),
		"third_party/vhop/go.mod":                  "module example.com/vhop\n\ngo 1.21\n",
		"third_party/vhop/vhop.go":                 fmt.Sprintf(plant, "vhop"),
		"dotless/dotless.go":                       "package dotless\n\nimport _ \"hop\"\n",
		"shadowed/shadowed.go":                     "package shadowed\n\nimport _ \"example.com/vhop\"\n",
		"shadowed/vendor/example.com/vhop/vhop.go": "package vhop\n",
		"clean/clean.go":                           "package clean\n\nimport _ \"strings\"\n",
	})
	cmd := exec.Command("go", "mod", "vendor")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod vendor: %v\n%s", err, out)
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "")
	l := list{allow: map[string][]string{"fix/fixtest": {"kernel.*"}}}
	got := fixtureImports(t, root, l, "./...")
	want := []string{
		"dotless imports test fixture fix/fixtest outside its _test.go files",
		"shadowed imports test fixture fix/fixtest outside its _test.go files",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("want\n%s\ngot\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
}
