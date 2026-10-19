package change

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"sort"
	"strings"
	"testing"
)

// REQ CONV-6-2, CONV-6-3 (brief IDs, briefs/CONV-6.md; no colon, as test_metrics.py
// does for CONV-0, since tools/trace.py takes only SPEC.md IDs after "REQ:")

// Security recurring kind (#210, #212; check owed by #697's "fixed sentence
// per class" finding): raw error text formatted into a fixed-class Logf lets
// a host path, or anything else an error wraps, reach the log. Every Logf
// call in this package's non-test code passes only fixed classes: no
// argument holds an error value, or a call on one (Error, fmt.Sprint and the
// like), except as an argument of a classifier. A classifier is a package
// function returning string whose every return is a string literal
// (errClass, exemptClass, cutClass); one that returns anything else is not a
// classifier, so its call fails too. Procedural, held by review: error text
// copied into a string variable first and that variable logged.
func TestLogfArgumentsCarryNoErrorText(t *testing.T) {
	fset := logfFset
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg, ok := pkgs["change"]
	if !ok {
		t.Fatal("package change not parsed")
	}
	var files []*ast.File
	for _, f := range pkg.Files {
		files = append(files, f)
	}
	calls, bad := logfErrorArgs(t, fset, files)
	if calls == 0 {
		t.Fatal("no Logf calls found; the check would pass vacuously")
	}
	for _, b := range bad {
		t.Errorf("%s: a Logf argument carries error text; log a fixed class (errClass) instead", b)
	}
}

// The check fails on synthetic instances of the kind and passes the fixed
// classes the package uses.
func TestLogfCheckCatchesErrorText(t *testing.T) {
	const head = `package change
import (
	"errors"
	"fmt"
	"io/fs"
)
type cfg struct{ Logf func(string, ...any) }
var c cfg
var errX = errors.New("x")
var _ = fmt.Sprint
func errClass(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "not found"
	}
	return "error"
}
func leaky(err error) string { return "class: " + err.Error() }
`
	for _, tc := range []struct {
		name, body string
		bad        int
	}{
		{"fixed class", `func f(err error) { c.Logf("x (%s)", errClass(err)) }`, 0},
		{"constant only", `func f() { c.Logf("x") }`, 0},
		{"error value", `func f(err error) { c.Logf("x (%v)", err) }`, 1},
		{"Error call", `func f(err error) { c.Logf("x (%s)", err.Error()) }`, 1},
		{"Sprint of an error", `func f(err error) { c.Logf("x (%s)", fmt.Sprint(err)) }`, 1},
		{"wrapped error", `func f(err error) { c.Logf("x (%v)", fmt.Errorf("w: %w", err)) }`, 1},
		{"package error var", `func f() { c.Logf("x (%v)", errX) }`, 1},
		{"concrete error type", `func f(pe *fs.PathError) { c.Logf("x (%v)", pe) }`, 1},
		{"field of an error", `func f(pe *fs.PathError) { c.Logf("x (%s)", pe.Path) }`, 1},
		{"classifier that leaks", `func f(err error) { c.Logf("x (%s)", leaky(err)) }`, 1},
		{"error in the format", `func f(err error) { c.Logf(err.Error()) }`, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(logfFset, "synthetic.go", head+tc.body+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			calls, bad := logfErrorArgs(t, logfFset, []*ast.File{f})
			if calls == 0 {
				t.Fatal("no Logf calls found")
			}
			if len(bad) != tc.bad {
				t.Errorf("flagged %d arguments, want %d: %v", len(bad), tc.bad, bad)
			}
		})
	}
}

// logfFset and logfImporter are shared so the standard library is
// type-checked from source once per run.
var (
	logfFset     = token.NewFileSet()
	logfImporter = importer.ForCompiler(logfFset, "source", nil)
)

// logfErrorArgs type-checks files as one package and returns how many Logf
// calls it saw and the position of each argument that carries error text.
func logfErrorArgs(t *testing.T, fset *token.FileSet, files []*ast.File) (int, []string) {
	t.Helper()
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
		Defs:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: logfImporter}
	if _, err := conf.Check("change", fset, files, info); err != nil {
		t.Fatalf("type-check: %v", err)
	}
	errIface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	carriesError := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		return ok && tv.Type != nil && !tv.IsType() && types.Implements(tv.Type, errIface)
	}
	classifiers := classifierFuncs(files, info)
	calls := 0
	var bad []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogf(call.Fun) {
				return true
			}
			calls++
			for _, arg := range call.Args {
				leak := false
				ast.Inspect(arg, func(n ast.Node) bool {
					if leak {
						return false
					}
					if c, ok := n.(*ast.CallExpr); ok {
						if id, ok := c.Fun.(*ast.Ident); ok && classifiers[info.Uses[id]] {
							return false
						}
					}
					if e, ok := n.(ast.Expr); ok && carriesError(e) {
						leak = true
						return false
					}
					return true
				})
				if leak {
					bad = append(bad, fset.Position(arg.Pos()).String())
				}
			}
			return true
		})
	}
	sort.Strings(bad)
	return calls, bad
}

func isLogf(fun ast.Expr) bool {
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name == "Logf"
	case *ast.Ident:
		return f.Name == "Logf" || f.Name == "logf"
	}
	return false
}

// classifierFuncs returns the package functions with one string result
// whose every return statement returns a string literal.
func classifierFuncs(files []*ast.File, info *types.Info) map[types.Object]bool {
	out := map[types.Object]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			obj := info.Defs[fd.Name]
			sig, ok := obj.Type().(*types.Signature)
			if !ok || sig.Results().Len() != 1 || !types.Identical(sig.Results().At(0).Type(), types.Typ[types.String]) {
				continue
			}
			literal := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				r, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				if len(r.Results) != 1 {
					literal = false
					return false
				}
				if bl, ok := r.Results[0].(*ast.BasicLit); !ok || bl.Kind != token.STRING {
					literal = false
				}
				return false
			})
			if literal {
				out[obj] = true
			}
		}
	}
	return out
}
