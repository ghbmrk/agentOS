package change

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"sort"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// REQ CONV-6-2, CONV-6-3 (brief IDs, briefs/CONV-6.md; no colon, as test_metrics.py
// does for CONV-0, since tools/trace.py takes only SPEC.md IDs after "REQ:")

// Security recurring kind (#210, #212; check owed by #697's "fixed sentence
// per class" finding): raw error text formatted into a fixed-class Logf lets
// a host path, or anything else an error wraps, reach the log. Every call of
// a func(string, ...any), the type of Config.Logf, under any name, in this
// package's non-test code passes only fixed classes: no argument is a value
// that can hold an error (a T or *T that implements error, a struct, slice
// or map holding one, an any), and no argument contains an error value, a
// call on one (Error) or a call given such a value (fmt.Sprint(box), a
// wrapper's a...), except as an argument of a classifier, under a bool
// (err != nil, errors.Is), or in a constant, len or cap. A forwarding
// wrapper's a... is an []any, so it fails too; log.Printf-shaped functions
// in the package are caught on purpose. A classifier is a package function
// with one unnamed string result whose every return is a string literal,
// and with no defer, go or closure (errClass, exemptClass, cutClass); any
// other call fails. Procedural, held by review: error text copied into a
// string first (a variable, or the string parameter of a helper that logs
// it), a method called on a value that holds an error, an interface other
// than any that an error can satisfy alongside other methods, and Logf
// outside broker/change.
func TestLogfArgumentsCarryNoErrorText(t *testing.T) {
	l := logfLoad(t)
	if unread, err := lintload.Unread(l); err != nil || len(unread) != 0 {
		t.Fatalf("files the check does not read: %q (%v)", unread, err)
	}
	fset, files := l.Fset, l.Packages[0].Files
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
		{"Logf under another name", `func f(err error) { log := c.Logf; log("x (%v)", err) }`, 1},
		{"forwarding wrapper", "func warn(f string, a ...any) { c.Logf(f, a...) }\nfunc f(err error) { warn(\"x (%v)\", err) }", 2},
		{"struct holding an error", "type box struct{ e error }\nfunc f(b box) { c.Logf(\"x (%v)\", b) }", 1},
		{"error by value", `func f(pe fs.PathError) { c.Logf("x (%v)", pe) }`, 1},
		{"slice of errors", `func f(es []error) { c.Logf("x (%v)", es) }`, 1},
		{"error in an any", `func f(err error) { var v any = err; c.Logf("x (%v)", v) }`, 1},
		{"deferred classifier", "func dc(err error) (s string) { defer func() { s = err.Error() }(); return \"fixed\" }\nfunc f(err error) { c.Logf(\"x (%s)\", dc(err)) }", 1},
		{"named-result classifier", "func nc(err error) (s string) { return \"fixed\" }\nfunc f(err error) { c.Logf(\"x (%s)\", nc(err)) }", 1},
		{"field of an error by value", `func f(pe fs.PathError) { c.Logf("x (%s)", pe.Path) }`, 1},
		{"Sprint of a struct holding an error", "type box struct{ e error }\nfunc f(b box) { c.Logf(\"x (%s)\", fmt.Sprint(b)) }", 1},
		{"Sprint of a slice of errors", `func f(es []error) { c.Logf("x (%s)", fmt.Sprint(es)) }`, 1},
		{"Sprint of an any holding an error", `func f(err error) { var v any = err; c.Logf("x (%s)", fmt.Sprint(v)) }`, 1},
		{"returning wrapper", "func w(f string, a ...any) string { return fmt.Sprintf(f, a...) }\nfunc f(err error) { c.Logf(\"x (%s)\", w(\"y (%v)\", err)) }", 1},
		{"byte of error text", `func f(err error) { c.Logf("x (%d)", err.Error()[0]) }`, 1},
		{"len of errors", `func f(es []error) { c.Logf("x (%d)", len(es)) }`, 0},
		{"nil test", `func f(err error) { c.Logf("x (%t)", err != nil) }`, 0},
		{"errors.Is", `func f(err error) { c.Logf("x (%t)", errors.Is(err, fs.ErrNotExist)) }`, 0},
		{"other format func", `func f(err error) { _ = fmt.Sprintf("x (%v)", err) }`, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parser.ParseFile(logfLoad(t).Fset, "synthetic.go", head+tc.body+"\n", 0)
			if err != nil {
				t.Fatal(err)
			}
			calls, bad := logfErrorArgs(t, logfLoad(t).Fset, []*ast.File{f})
			if tc.bad < 0 {
				if calls != 0 {
					t.Errorf("counted %d Logf calls, want 0", calls)
				}
				return
			}
			if calls == 0 {
				t.Fatal("no Logf calls found")
			}
			if len(bad) != tc.bad {
				t.Errorf("flagged %d arguments, want %d: %v", len(bad), tc.bad, bad)
			}
		})
	}
}

var (
	logfOnce   sync.Once
	logfLoaded *lintload.Loaded
	logfErr    error
)

// logfLoad loads package change through the shared lint loader, with
// export data for what the synthetic sources import, once per run.
func logfLoad(t *testing.T) *lintload.Loaded {
	t.Helper()
	logfOnce.Do(func() {
		logfLoaded, logfErr = lintload.Load(".", lintload.Build{Also: []string{"errors", "fmt", "io/fs"}}, ".")
		if logfErr == nil && len(logfLoaded.Packages) != 1 {
			logfErr = fmt.Errorf("loaded %d packages, want change alone", len(logfLoaded.Packages))
		}
	})
	if logfErr != nil {
		t.Fatal(logfErr)
	}
	return logfLoaded
}

// logfErrorArgs type-checks files as one package and returns how many Logf
// calls it saw and the position of each argument that carries error text.
func logfErrorArgs(t *testing.T, fset *token.FileSet, files []*ast.File) (int, []string) {
	t.Helper()
	info := &types.Info{
		Types: map[ast.Expr]types.TypeAndValue{},
		Uses:  map[*ast.Ident]types.Object{},
		Defs:  map[*ast.Ident]types.Object{},
	}
	conf := types.Config{Importer: logfLoad(t).Importer}
	if _, err := conf.Check("change", fset, files, info); err != nil {
		t.Fatalf("type-check: %v", err)
	}
	errIface := types.Universe.Lookup("error").Type().Underlying().(*types.Interface)
	carriesError := func(e ast.Expr) bool {
		tv, ok := info.Types[e]
		return ok && tv.Type != nil && !tv.IsType() && isError(tv.Type, errIface)
	}
	classifiers := classifierFuncs(files, info)
	calls := 0
	var bad []string
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fun, ok := info.Types[call.Fun]; !ok || fun.IsType() || !types.Identical(fun.Type.Underlying(), logfSig) {
				return true
			}
			calls++
			for _, arg := range call.Args {
				// The formatted value itself: anything that can hold an
				// error, such as a struct with an error field, a []error or
				// an any.
				leak := false
				if tv, ok := info.Types[arg]; ok && tv.Type != nil && !tv.IsType() && tv.Value == nil {
					leak = mayCarryError(tv.Type, errIface, map[types.Type]bool{})
				}
				// Inside it: an error value anywhere, or a call (other than a
				// classifier) given an argument that can hold one, such as
				// fmt.Sprint(box) or a wrapper's a...; except under a bool
				// (err != nil, errors.Is) or a constant, len or cap, which
				// carry no text.
				ast.Inspect(arg, func(n ast.Node) bool {
					if leak {
						return false
					}
					e, ok := n.(ast.Expr)
					if !ok {
						return true
					}
					if tv, ok := info.Types[e]; ok && tv.Type != nil {
						if tv.Value != nil {
							return false
						}
						if b, ok := tv.Type.Underlying().(*types.Basic); ok && b.Info()&types.IsBoolean != 0 {
							return false
						}
					}
					if c, ok := n.(*ast.CallExpr); ok {
						if id, ok := ast.Unparen(c.Fun).(*ast.Ident); ok {
							if classifiers[info.Uses[id]] {
								return false
							}
							if b, ok := info.Uses[id].(*types.Builtin); ok && (b.Name() == "len" || b.Name() == "cap") {
								return false
							}
						}
						if fun, ok := info.Types[c.Fun]; !ok || !fun.IsType() {
							for _, a := range c.Args {
								if tv, ok := info.Types[a]; ok && tv.Type != nil && !tv.IsType() && tv.Value == nil &&
									mayCarryError(tv.Type, errIface, map[types.Type]bool{}) {
									leak = true
									return false
								}
							}
						}
					}
					if carriesError(e) {
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

// logfSig is Config.Logf's type, func(string, ...any).
var logfSig = types.NewSignatureType(nil, nil, nil,
	types.NewTuple(
		types.NewParam(token.NoPos, nil, "", types.Typ[types.String]),
		types.NewParam(token.NoPos, nil, "", types.NewSlice(types.Universe.Lookup("any").Type()))),
	nil, true)

// mayCarryError reports whether a value of type t can hold an error: t
// implements error, an error can be stored in t (any, or an interface error
// satisfies), or t is a struct, pointer, array, slice, map or channel that
// holds such a type.
func mayCarryError(t types.Type, errIface *types.Interface, seen map[types.Type]bool) bool {
	if seen[t] {
		return false
	}
	seen[t] = true
	if isError(t, errIface) {
		return true
	}
	switch u := t.Underlying().(type) {
	case *types.Interface:
		return types.Implements(errIface, u)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if mayCarryError(u.Field(i).Type(), errIface, seen) {
				return true
			}
		}
	case *types.Pointer:
		return mayCarryError(u.Elem(), errIface, seen)
	case *types.Array:
		return mayCarryError(u.Elem(), errIface, seen)
	case *types.Slice:
		return mayCarryError(u.Elem(), errIface, seen)
	case *types.Map:
		return mayCarryError(u.Key(), errIface, seen) || mayCarryError(u.Elem(), errIface, seen)
	case *types.Chan:
		return mayCarryError(u.Elem(), errIface, seen)
	}
	return false
}

// isError reports whether t or *t implements error, so a by-value
// fs.PathError, whose Error method has a pointer receiver, counts.
func isError(t types.Type, errIface *types.Interface) bool {
	if types.Implements(t, errIface) {
		return true
	}
	if _, ok := t.Underlying().(*types.Interface); ok {
		return false
	}
	return types.Implements(types.NewPointer(t), errIface)
}

// classifierFuncs returns the package functions with one unnamed string
// result whose every return statement returns a string literal, and with no
// defer, go or closure that could change what they return.
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
			if !ok || sig.Results().Len() != 1 || sig.Results().At(0).Name() != "" || !types.Identical(sig.Results().At(0).Type(), types.Typ[types.String]) {
				continue
			}
			literal := true
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n.(type) {
				case *ast.FuncLit, *ast.DeferStmt, *ast.GoStmt:
					literal = false
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
