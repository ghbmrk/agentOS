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
// method behind the interface's methods is reachable through it. The
// check runs once for each build the repo ships (builds), so a file behind
// a build tag, another GOOS or cgo is checked as much as the host's.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
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

// A build is one set of the tag, GOOS and cgo settings go list runs under.
type build struct {
	name    string
	env     []string // added to the environment
	flags   []string
	overlay string // a go -overlay file, or ""
	// partial: the module does not build whole under this GOOS, so a
	// package that does not compile here is skipped. No binary for this
	// GOOS can link it, so none ships its files.
	partial bool
}

// builds are the settings the repo ships under: the host's with cgo on (CI
// runs go test -race, which needs the C toolchain), image.yml's
// agentos_e2e build of cmd/agentos-egress with image/infer.sh's
// infer_llamacpp build of cmd/agentos-infer (no file needs one tag without
// the other), and a non-linux GOOS, which compiles each !linux file.
var builds = []build{
	{name: "host+cgo", env: []string{"CGO_ENABLED=1"}},
	{name: "agentos_e2e", env: []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}, flags: []string{"-tags=agentos_e2e,infer_llamacpp"}},
	{name: "darwin", env: []string{"GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0"}, partial: true},
}

// load lists patterns under b with their dependencies through the shared
// lint loader and type-checks the packages they name. Under a partial build
// it leaves out each package that does not compile.
func load(t *testing.T, b build, patterns ...string) *lintload.Loaded {
	t.Helper()
	lb := lintload.Build{Env: b.env, Flags: b.flags, Partial: b.partial}
	if b.overlay != "" {
		lb.Flags = append(append([]string{}, b.flags...), "-overlay="+b.overlay)
	}
	l, err := lintload.Load(moduleRoot, lb, patterns...)
	if err != nil {
		t.Fatal(err)
	}
	return l
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

// writePaths type-checks under b the non-test files of each package
// patterns name, other than core and wiring packages, and returns one line
// per package and write path it calls that core.txt does not open or allow.
func writePaths(t *testing.T, l list, b build, patterns ...string) []string {
	found, _ := writePathsLoaded(t, l, b, patterns...)
	return found
}

// writePathsLoaded is writePaths, also returning the load, for Unread.
func writePathsLoaded(t *testing.T, l list, b build, patterns ...string) ([]string, *lintload.Loaded) {
	t.Helper()
	// Load the core with the patterns, so every core type is in hand for
	// the interface pass whatever the patterns import.
	all := append([]string{}, patterns...)
	for p := range l.core {
		all = append(all, "./"+p)
	}
	ld := load(t, b, all...)
	fset := ld.Fset
	coreTypes := namedTypes(t, ld.Importer, l.core, b.partial)
	var found []string
	for _, p := range ld.Packages {
		pkg, ok := strings.CutPrefix(p.Path, modPrefix)
		if !ok || l.core[pkg] || l.wiring[pkg] {
			continue
		}
		info := p.Info
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
	return found, ld
}

// namedTypes returns every non-generic, non-interface named type the core
// packages declare. Under a partial build a core package that does not
// compile is left out, as is everything that imports it.
func namedTypes(t *testing.T, imp types.Importer, core map[string]bool, partial bool) []*types.Named {
	t.Helper()
	var named []*types.Named
	for p := range core {
		tp, err := imp.Import(modPrefix + p)
		if err != nil && partial {
			continue
		}
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
	l := readList(t)
	var loads []*lintload.Loaded
	for _, b := range builds {
		t.Run(b.name, func(t *testing.T) {
			found, ld := writePathsLoaded(t, l, b, "./...")
			for _, f := range found {
				t.Error(f + "; submit an intent instead, or open or allow it in broker/core/core.txt with a reason")
			}
			loads = append(loads, ld)
		})
	}
	if t.Failed() {
		return
	}
	// Every file some build of these platforms compiles is read by one of
	// the builds, or named in unreadable.
	unread, err := lintload.Unread(loads...)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs(moduleRoot)
	if err != nil {
		t.Fatal(err)
	}
	left := map[string]bool{}
	for f := range unreadable {
		left[f] = true
	}
	for _, f := range unread {
		rel, _ := filepath.Rel(root, f)
		if unreadable[filepath.ToSlash(rel)] == "" {
			t.Errorf("%s: no build reads it, so its write paths go unchecked; add a build that compiles it", rel)
		}
		delete(left, filepath.ToSlash(rel))
	}
	for f := range left {
		t.Errorf("unreadable lists %s, which a build now reads or which is gone; remove the entry", f)
	}
}

// unreadable are the files no build here can compile, each with why its
// write paths are held by review instead.
var unreadable = map[string]string{
	"cmd/agentos-camdecode/camdecode/h264.go": "cgo against libavcodec, whose headers CI does not install (image/camdecode.sh builds it); the decoder child decodes frames and holds no core package",
	"cmd/agentos-vision/runtime_onnx.go":      "links ONNX Runtime through cgo, which only vision-real.yml installs; the inference child holds no core package",
}

// Each build reads the files only it compiles: a write path in a file
// behind cgo, the agentos_e2e tag or !linux is found under that build and
// no other. The package calls grants.Gate.Decide from all three files, and
// writePaths names a package's write path once, at the first file it reads.
func TestEachBuildChecksItsOwnFiles(t *testing.T) {
	// The overlay fills core/testdata itself, which holds no Go file: cgo
	// runs in the package directory, so it must exist.
	const dir = "core/testdata"
	decide := func(constraint, name string) string {
		src := "package taggedgrants\n\n"
		if constraint != "" {
			src = "//go:build " + constraint + "\n\n" + src
		}
		if name == "Cgo" {
			src += "// int one(void) { return 1; }\nimport \"C\"\n\n"
		}
		return src + fmt.Sprintf("import (\n\t%q\n\t%q\n)\n\nfunc Decide%s(g *grants.Gate, d owner.Decision) { g.Decide(d) }\n", modPrefix+"grants", modPrefix+"owner", name)
	}
	srcs := map[string]string{
		dir + "/doc.go":   "// Package taggedgrants is overlaid by TestEachBuildChecksItsOwnFiles.\npackage taggedgrants\n",
		dir + "/cgo.go":   decide("cgo", "Cgo"),
		dir + "/e2e.go":   decide("agentos_e2e", "E2E"),
		dir + "/other.go": decide("!linux", "Other"),
	}
	want := map[string]string{"host+cgo": "cgo.go", "agentos_e2e": "e2e.go", "darwin": "other.go"}
	if runtime.GOOS != "linux" {
		want["host+cgo"] = "" // other.go compiles on the host too; either file may come first
	}
	ov := overlay(t, srcs)
	l := readList(t)
	for _, b := range builds {
		file, ok := want[b.name]
		if !ok {
			t.Fatalf("no expectation for build %s", b.name)
		}
		b.overlay = ov
		found := writePaths(t, l, b, "./"+dir)
		if len(found) != 1 || !strings.HasPrefix(found[0], dir+" calls core write path grants.Gate.Decide ") ||
			!strings.Contains(found[0], "/"+file+":") {
			t.Errorf("%s: want exactly the grants.Gate.Decide call in %s, got %q", b.name, file, found)
		}
	}
}

// A package that writes grants directly fails the check; its Submit does not.
func TestAFixtureThatWritesGrantsFails(t *testing.T) {
	found := writePaths(t, readList(t), builds[0], "./core/testdata/writesgrants")
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
			if found := writePaths(t, l, builds[0], "./"+fixture); len(found) != c.want {
				t.Errorf("%s, allow %s grants.Gate.Decide: want %d finding(s), got %q", fixture, c.pkg, c.want, found)
			}
		}
	}
}

// A package that declares an interface a core type satisfies through a
// write path fails the check, with no call to the core at all.
func TestAFixtureThatDecidesThroughAnInterfaceFails(t *testing.T) {
	found := writePaths(t, readList(t), builds[0], "./core/testdata/decidesgrants")
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
	var paths []string
	for _, p := range pats {
		paths = append(paths, modPrefix+strings.TrimPrefix(p, "./"))
	}
	ld, err := lintload.Load(moduleRoot, lintload.Build{Also: paths}) // fails on a package that does not exist
	if err != nil {
		t.Fatal(err)
	}
	imp := ld.Importer
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

// fixtures are the allow-line packages core.txt grants on the grounds that
// only tests link them: a name ending in test, and kernel/sim (CORE-fixture-imports-a).
func fixtures(t *testing.T, l list) []string {
	t.Helper()
	var fs []string
	for p := range l.allow {
		if strings.HasSuffix(p, "test") || p == "kernel/sim" {
			fs = append(fs, p)
		}
	}
	sort.Strings(fs)
	if len(fs) == 0 {
		t.Fatal("core.txt allows no test fixture; update fixtures() if they were renamed")
	}
	return fs
}

// overlay writes a go -overlay file that adds each module path file (whose
// directory need not exist), with its source, and returns its path.
func overlay(t *testing.T, srcs map[string]string) string {
	t.Helper()
	tmp := t.TempDir()
	replace := map[string]string{}
	for name, src := range srcs {
		file := filepath.Join(tmp, strings.ReplaceAll(name, "/", "_"))
		if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		abs, err := filepath.Abs(filepath.Join(moduleRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		replace[abs] = file
	}
	o, err := json.Marshal(map[string]map[string]string{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(path, o, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// importing is a package named name that imports path.
func importing(name, path string) string {
	return fmt.Sprintf("package %s\n\nimport _ %q\n\nfunc main() {}\n", name, modPrefix+path)
}

// The enforcement: each fixture's init stops any binary go test did not
// build, so the files carry the rule along every route that reaches them
// (a build tag, another GOOS, a symlinked or vendored copy) without this
// test modelling the route.
func TestAFixtureStopsABinaryGoTestDidNotBuild(t *testing.T) {
	const dir = "core/testdata/linksfixture"
	for _, f := range fixtures(t, readList(t)) {
		t.Run(f, func(t *testing.T) {
			bin := filepath.Join(t.TempDir(), "linksfixture")
			build := exec.Command("go", "build", "-overlay="+overlay(t, map[string]string{dir + "/main.go": importing("main", f)}), "-o", bin, "./"+dir)
			build.Dir = moduleRoot
			if out, err := build.CombinedOutput(); err != nil {
				t.Fatalf("go build: %v\n%s", err, out)
			}
			out, err := exec.Command(bin).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "is a test fixture") {
				t.Fatalf("a binary linking %s ran: err %v, output %q; want its init to panic", f, err, out)
			}
		})
	}
}

// fixtureImporters lists, in the host build of patterns, each package
// outside the fixtures whose non-test files link a fixture.
func fixtureImporters(t *testing.T, fs []string, goFlags []string, patterns ...string) []string {
	t.Helper()
	fixture := map[string]bool{}
	for _, f := range fs {
		fixture[modPrefix+f] = true
	}
	args := append(append([]string{"list"}, goFlags...), "-json=ImportPath,Deps,Error")
	cmd := exec.Command("go", append(args, patterns...)...)
	cmd.Dir = moduleRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var found []string
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p struct {
			ImportPath string
			Deps       []string
			Error      *struct{ Err string }
		}
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.Error != nil {
			t.Fatalf("go list %s: %s", p.ImportPath, p.Error.Err)
		}
		if fixture[p.ImportPath] {
			continue
		}
		for _, d := range p.Deps {
			if fixture[d] {
				found = append(found, fmt.Sprintf("%s links test fixture %s outside its _test.go files", strings.TrimPrefix(p.ImportPath, modPrefix), strings.TrimPrefix(d, modPrefix)))
			}
		}
	}
	return found
}

// The fast pre-filter: in the host build, no package outside the fixtures
// links one from its non-test files. It names the mistake in CI before a
// binary runs; routes it does not model are the guard's to stop.
func TestFixturesAreImportedOnlyByTests(t *testing.T) {
	for _, f := range fixtureImporters(t, fixtures(t, readList(t)), nil, "./...") {
		t.Error(f + "; import it only from _test.go files")
	}
}

// The pre-filter flags a package that links a fixture, directly or through
// another package, and not one that imports it only from a test.
func TestAFixtureImportedOutsideATestFails(t *testing.T) {
	const dir, mid = "core/testdata/importsfixture", "core/testdata/importsfixture/mid"
	fs := fixtures(t, readList(t))
	for _, c := range []struct {
		name string
		srcs map[string]string
		want int
	}{
		{"direct", map[string]string{dir + "/main.go": importing("main", "loops/loopstest")}, 1},
		{"through another package", map[string]string{dir + "/main.go": importing("main", mid), mid + "/main.go": importing("mid", "kernel/sim")}, 2},
		// loops' own tests use loopstest; loops itself must not.
		{"from a test only", map[string]string{dir + "/main.go": importing("main", "loops")}, 0},
	} {
		got := fixtureImporters(t, fs, []string{"-overlay=" + overlay(t, c.srcs)}, "./"+dir+"/...")
		if len(got) != c.want {
			t.Errorf("%s: want %d finding(s), got %q", c.name, c.want, got)
		}
	}
}
