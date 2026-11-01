package lintload

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// REQ: KRN-2

func module(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["go.mod"] = "module example.test/m\n\ngo 1.22\n"
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

var linux = Build{Env: []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0"}}

// A loaded package resolves its imports through export data, so a use is
// the object it names whatever spells it.
func TestLoadResolvesImports(t *testing.T) {
	dir := module(t, map[string]string{
		"a/a.go": "package a\n\nimport pathops \"os\"\n\nfunc F(p string) error { return pathops.Remove(p) }\n",
	})
	l, err := Load(dir, linux, "./a")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Packages) != 1 || l.Packages[0].Path != "example.test/m/a" {
		t.Fatalf("packages %v", l.Packages)
	}
	found := false
	for id, obj := range l.Packages[0].Info.Uses {
		if id.Name == "Remove" && obj.Pkg() != nil && obj.Pkg().Path() == "os" {
			found = true
		}
	}
	if !found {
		t.Fatal("pathops.Remove does not resolve to os.Remove")
	}
}

// A type error fails the load; a package that does not compile fails go
// list first, unless the build is partial.
func TestLoadFailsOnATypeError(t *testing.T) {
	dir := module(t, map[string]string{"a/a.go": "package a\n\nvar X int = \"s\"\n"})
	if _, err := Load(dir, linux, "./a"); err == nil || !strings.Contains(err.Error(), "go list") {
		t.Fatalf("got %v, want go list's error", err)
	}
	l, err := Load(dir, Build{Env: linux.Env, Partial: true}, "./a")
	if err != nil || len(l.Packages) != 0 {
		t.Fatalf("partial: got %v, %v, want the package left out", l, err)
	}
}

// Load type-checks every package through check, and check fails on a type
// error: a source the gc compiler passes and go/types refuses would fail the
// load the same way (#4280 1).
func TestCheckFailsOnATypeError(t *testing.T) {
	for src, bad := range map[string]bool{"package a\n\nvar X int = \"s\"\n": true, "package a\n\nvar X int = 1\n": false} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "a.go", src, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, info, err := check(fset, nil, nil, "example.test/m/a", []*ast.File{f})
		if bad != (err != nil) || bad && !strings.Contains(err.Error(), "type-checking example.test/m/a") || !bad && info.Defs == nil {
			t.Errorf("%q: got %v, want an error %v", src, err, bad)
		}
	}
}

// A line directive would make a file read as another wherever a lint names
// files by position (Security R1 on #4443), so the load refuses one.
func TestLoadRefusesALineDirective(t *testing.T) {
	for _, d := range []string{"//line probe.go:1", "/*line probe.go:1*/"} {
		dir := module(t, map[string]string{"a/a.go": "package a\n\n" + d + "\nvar X = 1\n"})
		if _, err := Load(dir, linux, "./a"); err == nil || !strings.Contains(err.Error(), "line directive") {
			t.Errorf("%s: got %v, want the directive refused", d, err)
		}
	}
}

// A partial build leaves out only what does not compile, and Module brings
// in the main module's dependencies.
func TestLoadPartialAndModule(t *testing.T) {
	dir := module(t, map[string]string{
		"bad/bad.go": "package bad\n\nvar X int = \"s\"\n",
		"dep/dep.go": "package dep\n\nconst N = 1\n",
		"top/top.go": "package top\n\nimport \"example.test/m/dep\"\n\nvar _ = dep.N\n",
	})
	paths := func(l *Loaded) []string {
		var out []string
		for _, p := range l.Packages {
			out = append(out, p.Path)
		}
		return out
	}
	l, err := Load(dir, Build{Env: linux.Env, Partial: true}, "./bad", "./top")
	if err != nil || !slices.Equal(paths(l), []string{"example.test/m/top"}) {
		t.Fatalf("partial: got %v, %v, want top alone", l, err)
	}
	l, err = Load(dir, Build{Env: linux.Env, Module: true}, "./top")
	if err != nil || !slices.Equal(paths(l), []string{"example.test/m/dep", "example.test/m/top"}) {
		t.Fatalf("module: got %v, %v, want dep and top", l, err)
	}
}

// Packages with no test variant share one importer, so a lint comparing an
// imported object across them (core's interface pass) sees one object.
func TestLoadSharesImports(t *testing.T) {
	dir := module(t, map[string]string{
		"c/c.go": "package c\n\ntype T struct{}\n",
		"a/a.go": "package a\n\nimport \"example.test/m/c\"\n\nvar V c.T\n",
		"b/b.go": "package b\n\nimport \"example.test/m/c\"\n\nvar V c.T\n",
	})
	l, err := Load(dir, linux, "./a", "./b")
	if err != nil || len(l.Packages) != 2 {
		t.Fatalf("got %v, %v", l, err)
	}
	ta := l.Packages[0].Types.Scope().Lookup("V").Type()
	tb := l.Packages[1].Types.Scope().Lookup("V").Type()
	if ta != tb {
		t.Fatal("a and b see two c.T objects")
	}
	imp, err := l.Importer.Import("example.test/m/c")
	if err != nil || imp.Scope().Lookup("T").Type() != ta {
		t.Fatalf("the load's importer gives another c.T (%v)", err)
	}
}

// reachable tries every subset of up to 12 free tags (cgo among them), and
// counts a file with more as reachable, failing closed.
func TestReachableTagCap(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, n int) {
		var tags []string
		for i := range n {
			tags = append(tags, fmt.Sprintf("t%d", i))
		}
		src := "//go:build (" + strings.Join(tags, " || ") + ") && windows\n\npackage a\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("eleven.go", 11) // 12 free tags with cgo: tried, and no linux build compiles it
	write("twelve.go", 12) // 13: past the cap
	for name, want := range map[string]bool{"eleven.go": false, "twelve.go": true} {
		if got, err := reachable(dir, name, "linux", "amd64"); err != nil || got != want {
			t.Errorf("%s: reachable %v (%v), want %v", name, got, err, want)
		}
	}
}

// Under Tests a package is loaded with its in-package tests, and its
// external test package imports that same source-checked package.
func TestLoadTests(t *testing.T) {
	dir := module(t, map[string]string{
		"a/a.go":        "package a\n\ntype S struct{ stop func() }\n\nfunc (s *S) Run() {}\n",
		"a/a_test.go":   "package a\n\nvar _ = S{stop: func() {}}\n",
		"a/ext_test.go": "package a_test\n\nimport \"example.test/m/a\"\n\nvar _ = new(a.S).Run\n",
	})
	l, err := Load(dir, Build{Env: linux.Env, Tests: true}, "./a")
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Packages) != 2 || l.Packages[0].XTest || !l.Packages[1].XTest || len(l.Packages[0].Files) != 2 {
		t.Fatalf("want the test variant then the external test package, got %d packages", len(l.Packages))
	}
	run := l.Packages[0].Types.Scope().Lookup("S")
	for id, obj := range l.Packages[1].Info.Uses {
		if id.Name == "S" && obj != run {
			t.Fatal("the external test's a.S is not the source-checked a.S")
		}
	}
}

// Unread names each kind of file a lint could pass over (Security R1 on
// #4268), and not a file only another platform or no build compiles.
func TestUnread(t *testing.T) {
	dir := module(t, map[string]string{
		"a/a.go":           "package a\n",
		"a/tagged.go":      "//go:build agentos_x\n\npackage a\n",
		"a/plus.go":        "// +build agentos_y\n\npackage a\n",
		"a/block.go":       "/* header */\n\n//go:build agentos_z\n\npackage a\n",
		"a/both.go":        "//go:build agentos_p && agentos_q\n\npackage a\n",
		"a/cgotag.go":      "//go:build cgo && agentos_r\n\npackage a\n",
		"a/cgo.go":         "package a\n\nimport \"C\"\n",
		"a/asm_amd64.s":    "",
		"a/blob.syso":      "",
		"a/other.go":       "//go:build !linux\n\npackage a\n",
		"a/a_darwin.go":    "package a\n",
		"a/gen.go":         "//go:build ignore\n\npackage main\n",
		"a/tagged_test.go": "//go:build agentos_x\n\npackage a\n",
	})
	l, err := Load(dir, linux, "./a")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Unread(l)
	if err != nil {
		t.Fatal(err)
	}
	for i := range got {
		got[i] = filepath.Base(got[i])
	}
	if want := []string{"asm_amd64.s", "blob.syso", "block.go", "both.go", "cgo.go", "cgotag.go", "plus.go", "tagged.go"}; !slices.Equal(got, want) {
		t.Fatalf("unread %q, want %q", got, want)
	}
	// A cgo build type-checks the cgo file's Go, but not its C.
	withCgo, err := Load(dir, Build{Env: []string{"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1"}}, "./a")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Unread(withCgo); !slices.ContainsFunc(got, func(s string) bool { return strings.HasSuffix(s, "/cgo.go") }) {
		t.Fatalf("unread under cgo %q lacks cgo.go", got)
	}
	// A second build that reads the tagged file covers it.
	tagged, err := Load(dir, Build{Env: linux.Env, Flags: []string{"-tags=agentos_x"}}, "./a")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := Unread(l, tagged); slices.ContainsFunc(got, func(s string) bool { return strings.HasSuffix(s, "/tagged.go") }) {
		t.Fatalf("unread %q includes the file the tagged build read", got)
	}
}

// The loader runs go list, so childproc's gate exempts it; that holds only
// while no non-test file imports it, under any build, which this checks by
// reading every non-test Go file under broker/ (vendor and testdata aside).
func TestOnlyTestsImportTheLoader(t *testing.T) {
	const self = "github.com/ghbmrk/agentos/broker/internal/lintload"
	importers, err := loaderImporters("../..", self)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range importers {
		t.Errorf("%s imports %s; import it only from _test.go files", f, self)
	}
	// The scan sees a tagged non-test importer and a raw-string import, and
	// not a test one.
	dir := module(t, map[string]string{
		"a/a.go":      "//go:build agentos_x\n\npackage a\n\nimport _ \"example.test/m/lintload\"\n",
		"c/c.go":      "package c\n\nimport _ `example.test/m/lintload`\n",
		"b/b_test.go": "package b\n\nimport _ \"example.test/m/lintload\"\n",
	})
	got, err := loaderImporters(dir, "example.test/m/lintload")
	if err != nil || len(got) != 2 || !strings.HasSuffix(got[0], "a/a.go") || !strings.HasSuffix(got[1], "c/c.go") {
		t.Fatalf("synthetic: got %q, %v, want a/a.go and the raw-string c/c.go", got, err)
	}
}

func loaderImporters(root, self string) ([]string, error) {
	var found []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" || strings.HasPrefix(n, ".") && p != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if path, err := strconv.Unquote(im.Path.Value); err != nil || path == self {
				found = append(found, p)
			}
		}
		return nil
	})
	return found, err
}
