package guesterr

// REQ: RES-4, CAP-8

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// canary is a synthetic host path; it is no real path on any box.
const canary = "/var/lib/agentos-canary-7f3a/state/journal.db"

var refRE = regexp.MustCompile(`^tool_x failed \(ref [0-9a-f]{8}\); the broker's log has the detail$`)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev); log.SetFlags(flags) })
	return &buf
}

type wrapped struct{ Text }

func (w wrapped) Error() string { return canary + ": " + w.Text.Error() }

// A tool's own text passes; anything else, a Safe error wrapped in
// another included, is a ref, its detail on one broker-log line only.
func TestFilterPassesOnlySafeTextAndLogsTheRest(t *testing.T) {
	buf := captureLog(t)
	if got := Filter("m1", "tool_x", New("arguments must be an object")).Error(); got != "arguments must be an object" {
		t.Fatalf("own text: %q", got)
	}
	if got := Filter("m1", "tool_x", Newf("at most %d, not %s", Num(3), Guest("r1"))).Error(); got != "at most 3, not r1" {
		t.Fatalf("formatted: %q", got)
	}
	for _, err := range []error{
		errors.New("open " + canary + ": permission denied"),
		fmt.Errorf("store: %w", &fs.PathError{Op: "write", Path: canary, Err: fs.ErrPermission}),
		fmt.Errorf("%s: %w", canary, New("arguments must be an object")),
		errors.Join(New("fixed"), errors.New(canary)),
	} {
		buf.Reset()
		got := Filter("m1", "tool_x", err).Error()
		if !refRE.MatchString(got) {
			t.Fatalf("%v: guest saw %q", err, got)
		}
		ref := got[len("tool_x failed (ref ") : len("tool_x failed (ref ")+8]
		line := buf.String()
		if strings.Count(line, "\n") != 1 || !strings.Contains(line, "ref "+ref) || !strings.Contains(line, canary) || !strings.Contains(line, "m1: tool_x") {
			t.Fatalf("log line %q for ref %s", line, ref)
		}
	}
}

// A type embedding a Safe error passes only the embedded text, never its
// own (found while building SR2-3g: embedding promotes the method).
func TestAnEmbeddingTypeShowsOnlyTheEmbeddedText(t *testing.T) {
	if got := Filter("m1", "tool_x", wrapped{New("fixed")}).Error(); got != "fixed" {
		t.Fatalf("guest saw %q", got)
	}
}

// allowlist names, per tool family, the one type whose text passes the
// guest plane's filter as it is.
var allowlist = map[string]string{
	"guesterr": "Text",    // the question, recall, managed-tree and effect tools
	"workers":  "said",    // the worker tools (SR2-3f)
	"grants":   "refusal", // effect denials, via the journal (SR2-3j)
}

// TestOnlyAllowlistedTypesAreSafe fails CI on any other type in the broker
// that declares GuestText, which would let its text reach the guest.
func TestOnlyAllowlistedTypesAreSafe(t *testing.T) {
	found := map[string]string{}
	eachFile(t, func(fset *token.FileSet, path string, file *ast.File) {
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "GuestText" {
				continue
			}
			typ := fd.Recv.List[0].Type
			if s, ok := typ.(*ast.StarExpr); ok {
				typ = s.X
			}
			name := fmt.Sprint(typ)
			pkg := file.Name.Name
			if allowlist[pkg] != name {
				t.Errorf("%s: %s.%s is not on guesterr's allowlist", fset.Position(fd.Pos()), pkg, name)
			}
			found[pkg] = name
		}
	})
	if len(found) != len(allowlist) {
		t.Fatalf("allowlist %v, declared %v", allowlist, found)
	}
}

// TestToolErrorsAreBuiltOnlyFromSafeText fails CI on guest text built
// from anything but literals and safe values: an explicit Literal or Text
// conversion, or an error put into Num or Guest.
func TestToolErrorsAreBuiltOnlyFromSafeText(t *testing.T) {
	eachFile(t, func(fset *token.FileSet, path string, file *ast.File) {
		if file.Name.Name == "guesterr" {
			return
		}
		for _, v := range unsafeText(file) {
			t.Errorf("%s: guesterr %s: %s", fset.Position(v.pos), v.what, v.why)
		}
	})
}

const importPath = "github.com/ghbmrk/agentos/broker/guesterr"

type violation struct {
	pos       token.Pos
	what, why string
}

// unsafeText is each place file builds guest text unsafely, under
// whatever name it imports this package by. A dot-import hides the
// package's calls from the guard, so it is a violation itself.
func unsafeText(file *ast.File) []violation {
	var out []violation
	name := ""
	for _, im := range file.Imports {
		if strings.Trim(im.Path.Value, "`\"") != importPath {
			continue
		}
		switch {
		case im.Name == nil:
			name = "guesterr"
		case im.Name.Name == ".":
			out = append(out, violation{im.Pos(), "dot-import", "hides its calls from this guard"})
		case im.Name.Name != "_":
			name = im.Name.Name
		}
	}
	if name == "" {
		return out
	}
	ours := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.CallExpr:
			if sel, ok := n.Fun.(*ast.SelectorExpr); ok && ours(sel.X) {
				switch sel.Sel.Name {
				case "Literal", "Text":
					out = append(out, violation{n.Pos(), sel.Sel.Name, "conversion"})
				case "Guest", "Num":
					if len(n.Args) > 0 {
						if bad := errorIn(n.Args[0]); bad != "" {
							out = append(out, violation{n.Pos(), sel.Sel.Name, "takes " + bad})
						}
					}
				}
			}
		case *ast.CompositeLit:
			if sel, ok := n.Type.(*ast.SelectorExpr); ok && ours(sel.X) && sel.Sel.Name == "Text" {
				out = append(out, violation{n.Pos(), "Text{}", "literal"})
			}
		}
		return true
	})
	return out
}

// The guard sees an error passed as guest text, under the package's own
// name, an alias, or a dot-import.
func TestTheGuardCatchesAnErrorPassedAsText(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{`package x
import "github.com/ghbmrk/agentos/broker/guesterr"
func f(err error) { _ = guesterr.Newf("%s", guesterr.Guest(err.Error())); _ = guesterr.Literal(s); _ = guesterr.Text{} }`, "Guest,Literal,Text{}"},
		{`package x
import ge "github.com/ghbmrk/agentos/broker/guesterr"
func f(err error) { _ = ge.New(ge.Literal(err.Error())); _ = ge.Newf("%s", ge.Guest(err.Error())); _ = ge.Text{} }`, "Literal,Guest,Text{}"},
		{`package x
import . "github.com/ghbmrk/agentos/broker/guesterr"
func f(err error) { _ = New(Literal(err.Error())) }`, "dot-import"},
		{`package x
import guesterr "fmt"
func f(err error) { _ = guesterr.Errorf("%w", err) }`, ""},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "x.go", c.src, 0)
		if err != nil {
			t.Fatal(err)
		}
		var hits []string
		for _, v := range unsafeText(file) {
			hits = append(hits, v.what)
		}
		if got := strings.Join(hits, ","); got != c.want {
			t.Errorf("guard saw %q, want %q in\n%s", got, c.want, c.src)
		}
	}
}

// errorIn names what in e may be an error or its text.
func errorIn(e ast.Expr) string {
	bad := ""
	ast.Inspect(e, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.Ident:
			if n.Name == "err" || strings.HasSuffix(n.Name, "Err") || strings.HasPrefix(n.Name, "err") {
				bad = "an error " + n.Name
			}
		case *ast.SelectorExpr:
			if n.Sel.Name == "Error" || n.Sel.Name == "Sprint" || n.Sel.Name == "Sprintf" {
				bad = "a call to " + n.Sel.Name
			}
		}
		return true
	})
	return bad
}

// eachFile parses every non-test Go file of the broker module.
func eachFile(t *testing.T, f func(*token.FileSet, string, *ast.File)) {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("broker module root: %v", err)
	}
	fset := token.NewFileSet()
	n := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".")) {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return err
		}
		n++
		f(fset, p, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("parsed only %d files under %s", n, root)
	}
}
