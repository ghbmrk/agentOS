package daemon

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/build/constraint"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// TestEveryChildGetsAnExplicitEnvironment (inference_test.go) type-checks
// each file in a box build (#6201). envLoad loads as load does, in a given
// build; load is left as it is, since mutgate reads any edit to it as
// reaching every test of the package (arc2_test.go's enforcer names it).

// envBuild is a linux build: its GOARCH, whether cgo is on, and its tags.
type envBuild struct {
	arch string
	cgo  bool
	tags []string
}

// envFiles calls check with each non-test .go file under root (vendor/
// and third_party/ included, testdata/ and dot directories not), loaded
// with its package's files in the first linux build that compiles it
// (#6201): amd64 with cgo, amd64 without, then arm64 without (camnode's),
// with as few of the file's own build tags as it needs. A file no such
// build compiles (a !linux file, another platform's vendored file) is in
// no box binary and is not checked. It returns each package that does not
// type-check.
func envFiles(t *testing.T, root string, check func(rel string, l *loaded, i int)) (failed []string) {
	t.Helper()
	dirs := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) && path != root {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			dirs[filepath.Dir(path)] = append(dirs[filepath.Dir(path)], d.Name())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// go/build's knownOS and knownArch, and the tags a build sets itself:
	// never a tag to try.
	set := strings.Fields("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos " +
		"386 amd64 amd64p32 arm armbe arm64 arm64be loong64 mips mipsle mips64 mips64le mips64p32 mips64p32le ppc ppc64 ppc64le riscv riscv64 s390 s390x sparc sparc64 wasm cgo gc gccgo unix")
	context := func(tg envBuild) *build.Context {
		c := build.Default
		c.GOOS, c.GOARCH, c.CgoEnabled, c.BuildTags = "linux", tg.arch, tg.cgo, tg.tags
		return &c
	}
	words := regexp.MustCompile(`[\w.]+`)
	type group struct {
		dir, rel string
		tg       envBuild
		names    []string
		own      map[string]bool
	}
	// Each file's head and the tags its constraint names; a box build sets
	// only tags the module's own files name (srclint pins those to the
	// builds), so a tag only vendor/ or third_party/ names (purego, m68k)
	// is never tried.
	heads, tags, built := map[string]*ast.File{}, map[string][]string{}, map[string]bool{}
	for dir, names := range dirs {
		for _, name := range names {
			file := filepath.Join(dir, name)
			h, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			heads[file] = h
			for _, c := range h.Comments {
				for _, line := range c.List {
					if _, expr, _ := strings.Cut(line.Text, "build"); c.Pos() < h.Package && (constraint.IsGoBuild(line.Text) || constraint.IsPlusBuild(line.Text)) {
						for _, w := range words.FindAllString(expr, -1) {
							if !slices.Contains(set, w) && !strings.Contains(w, ".") && !slices.Contains(tags[file], w) {
								tags[file] = append(tags[file], w)
							}
						}
					}
				}
			}
			rel, _ := filepath.Rel(root, dir)
			if top, _, _ := strings.Cut(filepath.ToSlash(rel), "/"); top != "vendor" && top != "third_party" {
				for _, w := range tags[file] {
					built[w] = true
				}
			}
		}
	}
	var groups []*group
	byKey, byBuild, skipped := map[string]*group{}, map[string][]*ast.File{}, 0
	for _, dir := range slices.Sorted(maps.Keys(dirs)) {
		rel, _ := filepath.Rel(root, dir)
		for _, name := range slices.Sorted(slices.Values(dirs[dir])) {
			// The first build with some of the file's own tags that
			// compiles it.
			try := slices.DeleteFunc(tags[filepath.Join(dir, name)], func(w string) bool { return !built[w] })
			var tg envBuild
			found := false
			for bits := 0; bits < 1<<len(try) && !found; bits++ {
				var on []string
				for j, w := range try {
					if bits>>j&1 == 1 {
						on = append(on, w)
					}
				}
				for _, tg = range []envBuild{{"amd64", true, on}, {"amd64", false, on}, {"arm64", false, on}} {
					if found, _ = context(tg).MatchFile(dir, name); found {
						break
					}
				}
			}
			if !found {
				skipped++
				continue
			}
			pkg := heads[filepath.Join(dir, name)].Name.Name
			key := fmt.Sprint(dir, tg, pkg)
			if byKey[key] == nil {
				g := &group{dir: dir, rel: filepath.ToSlash(rel), tg: tg, own: map[string]bool{}}
				for _, n := range slices.Sorted(slices.Values(dirs[dir])) {
					if ok, _ := context(tg).MatchFile(dir, n); ok && heads[filepath.Join(dir, n)].Name.Name == pkg {
						g.names = append(g.names, n)
						byBuild[fmt.Sprint(tg)] = append(byBuild[fmt.Sprint(tg)], heads[filepath.Join(dir, n)])
					}
				}
				byKey[key] = g
				groups = append(groups, g)
			}
			byKey[key].own[name] = true
		}
	}
	// One go list per build gives every package's imports their export data.
	for _, g := range groups {
		if fs := byBuild[fmt.Sprint(g.tg)]; fs != nil {
			buildExports(t, fs, g.tg)
			delete(byBuild, fmt.Sprint(g.tg))
		}
	}
	t.Logf("%d packages checked; %d files in no linux amd64 or arm64 build", len(groups), skipped)
	for _, g := range groups {
		l := envLoad(t, g.dir, g.names, g.rel, g.tg)
		if l.err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v): does not type-check, so the lint cannot check it: %v", g.rel, g.tg, l.err))
		}
		for i, name := range g.names {
			if g.own[name] {
				check(filepath.ToSlash(filepath.Join(g.rel, name)), l, i)
			}
		}
	}
	return failed
}

// envLoad parses and type-checks the named files of the package in dir as
// package rel in build tg, as load does: its imports from the export data
// go list builds for tg, and cgo's C as FakeImportC leaves it, untyped, so
// a cgo file's own errors do not count.
func envLoad(t *testing.T, dir string, names []string, rel string, tg envBuild) *loaded {
	t.Helper()
	l := &loaded{fset: token.NewFileSet(), info: &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}}
	cgo := map[*token.File]bool{}
	for _, name := range names {
		f, err := parser.ParseFile(l.fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		l.files = append(l.files, f)
		if slices.ContainsFunc(f.Imports, func(im *ast.ImportSpec) bool { return im.Path.Value == `"C"` }) {
			cgo[l.fset.File(f.Pos())] = true
		}
	}
	conf := types.Config{FakeImportC: true, Importer: importer.ForCompiler(l.fset, "gc", buildExports(t, l.files, tg)), Error: func(err error) {
		if te, ok := err.(types.Error); l.err == nil && !(ok && cgo[l.fset.File(te.Pos)]) {
			l.err = err
		}
	}}
	l.pkg, _ = conf.Check(module+rel, l.fset, l.files, l.info)
	return l
}

// envExports maps a build and an import path to its export data file.
var envExports sync.Map

// buildExports is exportData in build tg. A file behind ignore is run
// alone (go run), so its imports are built without that tag.
func buildExports(t *testing.T, fs []*ast.File, tg envBuild) func(string) (io.ReadCloser, error) {
	t.Helper()
	in := fmt.Sprint(tg) + "\t"
	var need []string
	for _, f := range fs {
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if _, ok := envExports.Load(in + p); !ok && p != "unsafe" && p != "C" && !slices.Contains(need, p) {
				need = append(need, p)
			}
		}
	}
	if len(need) > 0 {
		tags := slices.DeleteFunc(slices.Clone(tg.tags), func(w string) bool { return w == "ignore" })
		cmd := exec.Command("go", append([]string{"list", "-e", "-export", "-deps", "-tags=" + strings.Join(tags, ","), "-f", "{{.ImportPath}}\t{{.Export}}"}, need...)...)
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+tg.arch, "CGO_ENABLED="+map[bool]string{true: "1", false: "0"}[tg.cgo])
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -export (%v): %v\n%s", tg, err, stderr.String())
		}
		for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if p, file, ok := strings.Cut(l, "\t"); ok && file != "" {
				envExports.Store(in+p, file)
			}
		}
	}
	return func(path string) (io.ReadCloser, error) {
		file, ok := envExports.Load(in + path)
		if !ok {
			return nil, fmt.Errorf("no export data for %s in %v", path, tg)
		}
		return os.Open(file.(string))
	}
}

// REQ: CRED-1, ARC-1
//
// #6201: the walk checks a file in a linux build that compiles it, its own
// tags set, and reports a package that does not type-check; a file no box
// build compiles (!linux, or behind a tag only vendored code names) is not
// read.
func TestEnvWalkChecksEveryBoxBuild(t *testing.T) {
	root := t.TempDir()
	for name, c := range map[string]string{
		"a/a.go":        "package a\nfunc A() {}\n",
		"a/tagged.go":   "//go:build envtag\n\npackage a\nimport \"os/exec\"\nfunc T() { exec.Command(\"x\").Run() }\n",
		"a/other.go":    "//go:build !linux\n\npackage a\nimport \"os/exec\"\nfunc O() { exec.Command(\"x\").Run() }\n",
		"a/gen.go":      "//go:build ignore\n\npackage main\nimport \"os/exec\"\nfunc main() { exec.Command(\"x\").Run() }\n",
		"b/b.go":        "package b\nfunc B() int { return \"x\" }\n",
		"vendor/v/v.go": "//go:build purego\n\npackage v\nimport \"os/exec\"\nfunc V() { exec.Command(\"x\").Run() }\n",
	} {
		if err := os.MkdirAll(filepath.Join(root, filepath.Dir(name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	failed := envFiles(t, root, func(rel string, l *loaded, i int) {
		noEnv, _ := childEnv(l, i)
		got = append(got, fmt.Sprint(rel, noEnv))
	})
	slices.Sort(got)
	if want := "a/a.go[] a/gen.go[main] a/tagged.go[T] b/b.go[]"; strings.Join(got, " ") != want {
		t.Errorf("checked %q, want %q", got, want)
	}
	if len(failed) != 1 || !strings.HasPrefix(failed[0], "b (") {
		t.Errorf("type errors %q, want b's alone", failed)
	}
}
