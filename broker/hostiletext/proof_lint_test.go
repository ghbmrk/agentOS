package hostiletext

// REQ: KRN-12, DEV-2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The bound on the header and address corpora (REV-PROOF-corpus, #4910): a
// header list or check, and an address check, runs its corpus in a test of
// its own directory, or has a line in allow-corpus.txt with its reason. As
// with the name lint, a check is found by its shape; one of another shape
// is held by review.
//
//   - A header list is a package-level variable named ...Headers.
//   - A header check is a function whose name holds "header" (any case),
//     whose first parameter is a string, and whose last result is a bool or
//     an error.
//   - An address check is a function with a netip.Addr parameter whose last
//     result is a bool or an error.
//
// A test covers one when its identifier appears in the arguments of a
// RunHeaders, RunHeaderValues or RunAddrs call in that directory; for a
// method, with its receiver's type.
var headerCheckName = regexp.MustCompile(`(?i)header`)

// corpusRuns are the corpus entry points a covering call names.
var corpusRuns = []string{"RunHeaders", "RunHeaderValues", "RunAddrs"}

// scanCorpus lists the header lists and checks and the address checks in
// the non-test Go files under root, and for each directory the identifiers
// its tests pass to a corpus run. It skips vendor, third_party, testdata
// and the skip directories (root-relative).
func scanCorpus(root string, skip []string) (checks []check, runs map[string]map[string]bool, err error) {
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
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !slices.Contains(corpusRuns, sel.Sel.Name) {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != "hostiletext" {
					return true
				}
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
				return true
			})
			return nil
		}
		for _, decl := range f.Decls {
			switch decl := decl.(type) {
			case *ast.GenDecl:
				if decl.Tok != token.VAR {
					continue
				}
				for _, spec := range decl.Specs {
					for _, n := range spec.(*ast.ValueSpec).Names {
						if strings.HasSuffix(n.Name, "Headers") {
							checks = append(checks, check{Dir: dir, Name: n.Name})
						}
					}
				}
			case *ast.FuncDecl:
				if decl.Type.Results == nil {
					continue
				}
				res := decl.Type.Results.List
				if last, ok := res[len(res)-1].Type.(*ast.Ident); !ok || last.Name != "bool" && last.Name != "error" {
					continue
				}
				if !headerCheck(decl) && !addrCheck(decl) {
					continue
				}
				c := check{Dir: dir, Name: decl.Name.Name}
				if decl.Recv != nil && len(decl.Recv.List) == 1 {
					t := decl.Recv.List[0].Type
					if s, ok := t.(*ast.StarExpr); ok {
						t = s.X
					}
					if id, ok := t.(*ast.Ident); ok {
						c.Recv = id.Name
					}
				}
				checks = append(checks, c)
			}
		}
		return nil
	})
	return
}

func headerCheck(fn *ast.FuncDecl) bool {
	ps := fn.Type.Params.List
	if !headerCheckName.MatchString(fn.Name.Name) || len(ps) == 0 {
		return false
	}
	id, ok := ps[0].Type.(*ast.Ident)
	return ok && id.Name == "string"
}

func addrCheck(fn *ast.FuncDecl) bool {
	for _, p := range fn.Type.Params.List {
		t := p.Type
		if e, ok := t.(*ast.Ellipsis); ok {
			t = e.Elt
		}
		if s, ok := t.(*ast.SelectorExpr); ok && s.Sel.Name == "Addr" {
			if x, ok := s.X.(*ast.Ident); ok && x.Name == "netip" {
				return true
			}
		}
	}
	return false
}

// uncoveredCorpus is each check no corpus run in its directory names: its
// name, and for a method its receiver's type too.
func uncoveredCorpus(checks []check, runs map[string]map[string]bool) []string {
	var out []string
	for _, c := range checks {
		if ids := runs[c.Dir]; !ids[c.Name] || c.Recv != "" && !ids[c.Recv] {
			out = append(out, c.String())
		}
	}
	return out
}

// Every header list and check and every address check in broker/ runs its
// corpus, or has an allow line with its reason; a stale allow line fails
// (#4910).
func TestEveryHeaderAndAddressCheckRunsItsCorpus(t *testing.T) {
	checks, runs, err := scanCorpus("..", oldCore(t))
	if err != nil {
		t.Fatal(err)
	}
	allow := allowLines(t, "allow-corpus.txt")
	for _, c := range uncoveredCorpus(checks, runs) {
		if _, ok := allow[c]; !ok {
			t.Errorf("%s is a header or address check no test runs through hostiletext.RunHeaders or RunAddrs: run it there, or add a line to allow-corpus.txt with the reason", c)
		}
		delete(allow, c)
	}
	for k := range allow {
		t.Errorf("allow-corpus.txt: %s is no uncovered header or address check: delete the line", k)
	}
	// The brief's checks are found and covered, not allowed.
	for _, want := range []string{"clerk fixedHeaders", "clerk secretHeaders", "clerk/model keyHeaders", "netguard Policy.Check"} {
		if !slices.ContainsFunc(checks, func(c check) bool { return c.String() == want }) {
			t.Errorf("the scan does not find %s", want)
		}
		if slices.Contains(uncoveredCorpus(checks, runs), want) {
			t.Errorf("%s does not run its corpus", want)
		}
	}
	for dir, id := range map[string]string{"kernel/ipform": "Forms"} {
		if !runs[dir][id] {
			t.Errorf("%s's tests do not run %s through the address corpus", dir, id)
		}
	}
}

// The scan finds each shape and sees a test that runs it: a list named
// ...Headers, a header check, and an address check with no run fail; with
// one, each passes. A run outside hostiletext covers nothing, and a method
// is covered only with its receiver's type. A header function taking no
// string, and a function with no netip.Addr, are not checks.
func TestScanFindsAnUnrunHeaderOrAddressCheck(t *testing.T) {
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
import "net/netip"
type G struct{}
var sentHeaders = map[string]bool{"Accept": true}
func badHeader(h string) bool { return false }
func checkHeader(n uint32) error { return nil }
func (G) Reach(a netip.Addr, port uint16) error { return nil }
func inAny(a ...netip.Addr) bool { return false }
type H struct{}
func (H) Reach(a netip.Addr, port uint16) error { return nil }
func plain(s string) bool { return true }
`)
	write("old/old.go", "package old\nvar oldHeaders = []string{}\n")
	checks, _, err := scanCorpus(root, []string{"old"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"foo sentHeaders", "foo badHeader", "foo G.Reach", "foo inAny", "foo H.Reach"}
	if got := uncoveredCorpus(checks, nil); !slices.Equal(got, want) {
		t.Fatalf("uncovered %q, want %q", got, want)
	}
	write("foo/foo_test.go", `package foo
import ("testing"; "x/hostiletext")
func TestCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, badHeader, "Accept")
	hostiletext.RunHeaders(t, func(h string) bool { return sentHeaders[h] }, "Accept")
	hostiletext.RunAddrs(t, target, func(s string) bool { return G{}.Reach(parse(s), 1) == nil })
	other.RunAddrs(t, target, func(s string) bool { return inAny(parse(s)) }) // not the corpus
	hostiletext.RunAddrs(t, target, func(s string) bool { return lax.Reach(parse(s), 1) == nil }) // names Reach, not H
}
`)
	checks, runs, err := scanCorpus(root, []string{"old"})
	if err != nil {
		t.Fatal(err)
	}
	if got := uncoveredCorpus(checks, runs); !slices.Equal(got, []string{"foo inAny", "foo H.Reach"}) {
		t.Fatalf("after the test, uncovered %q", got)
	}
}
