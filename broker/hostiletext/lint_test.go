package hostiletext

// REQ: KRN-2

import (
	"bufio"
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// checkName is how a name or label check is named: shape or Shape, name, anything
// ending in Name or NameOK, or valid...Name.... A function with such a name
// counts as a check when its last result is a bool or an error. A check
// under another name is held by review (the bound in reviews/security).
var checkName = regexp.MustCompile(`^([sS]hape|name|[A-Za-z0-9_]*Name|[A-Za-z0-9_]*NameOK|[vV]alid[A-Za-z0-9_]*Name[A-Za-z0-9_]*)$`)

// check is a name check in a broker directory: Recv is its receiver's
// type, empty for a function.
type check struct{ Dir, Recv, Name string }

func (c check) String() string {
	if c.Recv != "" {
		return c.Dir + " " + c.Recv + "." + c.Name
	}
	return c.Dir + " " + c.Name
}

// scan lists the name checks in the non-test Go files under root, and for
// each directory the identifiers its tests pass to hostiletext.Run. It
// skips vendor, third_party, testdata and the skip directories (root-relative).
func scan(root string, skip []string) (checks []check, runs map[string]map[string]bool, imports []string, err error) {
	runs = map[string]map[string]bool{}
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if b := d.Name(); rel != "." && (b == "vendor" || b == "third_party" || b == "testdata" || strings.HasPrefix(b, ".") || slices.Contains(skip, rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(rel))
		if strings.HasSuffix(p, "_test.go") {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "hostiletext" {
						if runs[dir] == nil {
							runs[dir] = map[string]bool{}
						}
						for _, a := range call.Args {
							ast.Inspect(a, func(n ast.Node) bool {
								if id, ok := n.(*ast.Ident); ok {
									runs[dir][id.Name] = true
								}
								return true
							})
						}
					}
				}
				return true
			})
			return nil
		}
		for _, im := range f.Imports {
			if path, _ := strconv.Unquote(im.Path.Value); strings.HasSuffix(path, "/hostiletext") {
				imports = append(imports, rel)
			}
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !checkName.MatchString(fn.Name.Name) || fn.Type.Results == nil {
				continue
			}
			res := fn.Type.Results.List
			last, ok := res[len(res)-1].Type.(*ast.Ident)
			if !ok || last.Name != "bool" && last.Name != "error" {
				continue
			}
			c := check{Dir: dir, Name: fn.Name.Name}
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				t := fn.Recv.List[0].Type
				if s, ok := t.(*ast.StarExpr); ok {
					t = s.X
				}
				if id, ok := t.(*ast.Ident); ok {
					c.Recv = id.Name
				}
			}
			checks = append(checks, c)
		}
		return nil
	})
	return
}

// uncovered is each check no test in its directory passes to Run: the
// check's name, and for a method its receiver's type, must appear in the
// Run call's arguments.
func uncovered(checks []check, runs map[string]map[string]bool) []string {
	var out []string
	for _, c := range checks {
		ids := runs[c.Dir]
		if !ids[c.Name] || c.Recv != "" && !ids[c.Recv] {
			out = append(out, c.String())
		}
	}
	return out
}

// allowLines reads allow.txt: "dir check reason" per line, # comments.
func allowLines(t *testing.T) map[string]string {
	t.Helper()
	b, err := os.ReadFile("allow.txt")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.SplitN(line, " ", 3)
		if len(f) != 3 || strings.TrimSpace(f[2]) == "" {
			t.Fatalf("allow.txt:%d: want \"dir check reason\": %q", n, line)
		}
		k := f[0] + " " + f[1]
		if _, dup := out[k]; dup {
			t.Fatalf("allow.txt:%d: %s listed twice", n, k)
		}
		out[k] = f[2]
	}
	return out
}

// oldCore is the old-core directories (tools/old_core.txt, D-139): frozen
// and being deleted, so no new test goes there.
func oldCore(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../tools/old_core.txt")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if d, ok := strings.CutPrefix(strings.TrimSpace(l), "broker/"); ok {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		t.Fatal("tools/old_core.txt lists no broker directory")
	}
	return out
}

// Every name check in broker/ runs the corpus, or has an allow line with
// its reason; a stale allow line fails (#3901).
func TestEveryNameCheckRunsTheCorpus(t *testing.T) {
	checks, runs, _, err := scan("..", oldCore(t))
	if err != nil {
		t.Fatal(err)
	}
	allow := allowLines(t)
	for _, c := range uncovered(checks, runs) {
		if _, ok := allow[c]; !ok {
			t.Errorf("%s is a name check no test runs through hostiletext.Run: run it there, or add an allow line with the reason", c)
		}
		delete(allow, c)
	}
	for k := range allow {
		t.Errorf("allow.txt: %s is no uncovered name check: delete the line", k)
	}
	// The brief's four checks are covered, not allowed.
	for _, want := range []string{"kernel BackupTarget.shape", "follow NameOK", "enforcer/policy name"} {
		if !slices.ContainsFunc(checks, func(c check) bool { return c.String() == want }) {
			t.Errorf("the scan does not find %s", want)
		}
		if slices.Contains(uncovered(checks, runs), want) {
			t.Errorf("%s does not run the corpus", want)
		}
	}
	if !runs["kernel"]["Named"] {
		t.Error("kernel's tests do not run Named through the corpus")
	}
}

// The scan finds a check by name and result, and sees a test that runs it:
// a synthetic validFooName, method shape and error-returning hostName with
// no Run caller fail; with one, each passes; a getter named Name does not
// count.
func TestScanFindsAnUnrunCheck(t *testing.T) {
	root := t.TempDir()
	write := func(p, src string) {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("foo/foo.go", `package foo
type T struct{ S string }
func validFooName(s string) bool { return s != "" }
func (t T) shape() bool { return t.S != "" }
func hostName(s string) error { return nil }
func (T) Name() string { return "" }
`)
	write("old/old.go", "package old\nfunc validOldName(string) bool { return true }\n")
	write("foo/vendor/v.go", "package v\nfunc vName(string) bool { return true }\n")
	checks, runs, _, err := scan(root, []string{"old"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foo validFooName", "foo T.shape", "foo hostName"}
	if got := uncovered(checks, runs); !slices.Equal(got, want) {
		t.Fatalf("uncovered %q, want %q", got, want)
	}
	write("foo/foo_test.go", `package foo
import ("testing"; "x/hostiletext")
func TestNames(t *testing.T) {
	hostiletext.Run(t, validFooName)
	hostiletext.Run(t, func(s string) bool { return T{s}.shape() })
	hostiletext.Run(t, func(s string) bool { return shape(s) }) // a shape of no T does not cover T.shape twice
}
`)
	checks, runs, _, err = scan(root, []string{"old"})
	if err != nil {
		t.Fatal(err)
	}
	if got := uncovered(checks, runs); !slices.Equal(got, []string{"foo hostName"}) {
		t.Fatalf("after the test, uncovered %q", got)
	}
}

// The corpus is for tests only: no non-test broker file imports it.
func TestOnlyTestsImport(t *testing.T) {
	_, _, imports, err := scan("..", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) != 0 {
		t.Fatalf("non-test files import hostiletext: %q", imports)
	}
}
