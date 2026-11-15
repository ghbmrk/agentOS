package clerk_test

// REQ: CLK-1, STO-2

// The sealer wipe lint (CLK-open-wipe-lint). A plaintext a sealer's Open
// hands back is a credential or a private record, and a sealer may fail
// after it decrypted, returning the plaintext beside its error. Three PRs
// in a row found a caller that returned on that error before its wipe
// (#5666, #5772, and the keys, secrets and plan stores fixed with this
// lint), so the shape is now refused here instead of in review.
//
// The rule, over every non-test file of every package under broker/clerk,
// type-checked: a call of a method named Open whose signature is
// func([]byte, []byte) ([]byte, error) (clerk.Sealer's Open, whatever type
// or interface spells it) appears only as `v, err := x.Open(a, b)` (or =)
// with v a named variable, and the very next statement is
// `defer clear(v)` with the builtin clear, so the wipe covers every return
// path, the error path included. The one exception is a sealer wrapper, a
// method named Open with that same signature, handing its plaintext
// straight to its caller, which this rule then holds: `return x.Open(a,
// b)`, or `v, err := x.Open(a, b)` where every return of the wrapper's own
// body (not a function literal in it) returns v first. Any other Open in a
// wrapper falls under the general rule. Any other use fails: the plaintext
// discarded to _, opened in an if or switch header, returned from a
// function that is not itself such an Open, passed straight to another
// call, or the method taken as a value.
//
// Bound: what the code does with v between the Open and its return (a copy
// kept, a string(v), an append that moves the bytes elsewhere) is held by
// review (a later v = ... does not escape: defer evaluates v at the defer); so are files a build tag leaves out of the default
// build, callers outside broker/clerk, and an Open that is a struct field
// or variable of func type rather than a method (none exists today).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

var wipeLoad = sync.OnceValues(func() (*lintload.Loaded, error) {
	return lintload.Load(".", lintload.Build{}, "./...")
})

// TestEveryOpenedPlaintextIsWipedOnEveryPath runs the rule over the tree.
func TestEveryOpenedPlaintextIsWipedOnEveryPath(t *testing.T) {
	l, err := wipeLoad()
	if err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	opens := 0
	for _, p := range l.Packages {
		for _, f := range p.Files {
			name := l.Fset.File(f.Pos()).Name()
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			rel, err := filepath.Rel(wd, name)
			if err != nil {
				rel = name
			}
			n, ps := wipeProblems(l.Fset, f, p.Info)
			opens += n
			for _, s := range ps {
				problems = append(problems, filepath.ToSlash(rel)+":"+s)
			}
		}
	}
	// A loader that read nothing would pass every tree: the clerk's own
	// stores alone call the sealer's Open more than this.
	if opens < 5 {
		t.Fatalf("the lint saw %d sealer Open calls; want the clerk's stores among them", opens)
	}
	sort.Strings(problems)
	for _, s := range problems {
		t.Error(s)
	}
}

// wipeProblems returns how many sealer Open uses the file holds and, for
// each one the rule refuses, its line and why.
func wipeProblems(fset *token.FileSet, f *ast.File, info *types.Info) (int, []string) {
	ok := map[*ast.Ident]bool{}     // Open selectors in an allowed shape
	called := map[*ast.Ident]bool{} // Open selectors that are a call's callee
	var problems []string
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }

	for _, decl := range f.Decls {
		fd, isFn := decl.(*ast.FuncDecl)
		wrapper := isFn && fd.Recv != nil && fd.Name.Name == "Open" && isSealerOpen(info.Defs[fd.Name])
		if wrapper {
			for _, id := range handedBack(fd.Body, info) {
				ok[id] = true
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if c, isCall := n.(*ast.CallExpr); isCall {
				if sel, isSel := ast.Unparen(c.Fun).(*ast.SelectorExpr); isSel && isSealerOpen(info.Uses[sel.Sel]) {
					called[sel.Sel] = true
				}
			}
			var list []ast.Stmt
			switch b := n.(type) {
			case *ast.BlockStmt:
				list = b.List
			case *ast.CaseClause:
				list = b.Body
			case *ast.CommClause:
				list = b.Body
			}
			for i, s := range list {
				id := openAssign(s, info)
				if id == nil {
					continue
				}
				if i+1 < len(list) && defersClear(list[i+1], s.(*ast.AssignStmt).Lhs[0], info) {
					ok[id] = true
				}
			}
			return true
		})
	}
	uses := 0
	ast.Inspect(f, func(n ast.Node) bool {
		id, isID := n.(*ast.Ident)
		if !isID || !isSealerOpen(info.Uses[id]) {
			return true
		}
		uses++
		switch {
		case ok[id]:
		case !called[id]:
			problems = append(problems, line(id)+": a sealer's Open taken as a value; call it and defer clear on its plaintext")
		default:
			problems = append(problems, line(id)+": a sealer's Open plaintext is not wiped on every path; write `v, err := x.Open(...)` then `defer clear(v)` as the next statement")
		}
		return true
	})
	return uses, problems
}

// handedBack returns the Open selectors a sealer wrapper's body hands
// straight to its caller: the operand of `return x.Open(a, b)`, or the Open
// of `v, err := x.Open(a, b)` when every return of the body returns v as
// its first result. Both look only at the wrapper's own statements, never
// into a function literal, whose Opens fall under the general rule.
func handedBack(body *ast.BlockStmt, info *types.Info) []*ast.Ident {
	var direct, assigned []*ast.Ident
	var vars []types.Object
	var returns []*ast.ReturnStmt
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			returns = append(returns, n)
			if len(n.Results) == 1 {
				if c, isCall := ast.Unparen(n.Results[0]).(*ast.CallExpr); isCall {
					if sel, isSel := ast.Unparen(c.Fun).(*ast.SelectorExpr); isSel && isSealerOpen(info.Uses[sel.Sel]) {
						direct = append(direct, sel.Sel)
					}
				}
			}
		case ast.Stmt:
			if id := openAssign(n, info); id != nil {
				assigned = append(assigned, id)
				vars = append(vars, info.ObjectOf(n.(*ast.AssignStmt).Lhs[0].(*ast.Ident)))
			}
		}
		return true
	})
	for i, id := range assigned {
		every := true
		for _, r := range returns {
			if len(r.Results) == 1 {
				continue // return x.Open(a, b), checked above
			}
			v, isID := (ast.Expr)(nil), false
			if len(r.Results) == 2 {
				v = ast.Unparen(r.Results[0])
				_, isID = v.(*ast.Ident)
			}
			if !isID || info.ObjectOf(v.(*ast.Ident)) != vars[i] {
				every = false
			}
		}
		if every && len(returns) > 0 {
			direct = append(direct, id)
		}
	}
	return direct
}

// openAssign returns the Open selector of s when s is `v, err := x.Open(a,
// b)` (or =) with v a named variable.
func openAssign(s ast.Stmt, info *types.Info) *ast.Ident {
	a, isAssign := s.(*ast.AssignStmt)
	if !isAssign || len(a.Lhs) != 2 || len(a.Rhs) != 1 {
		return nil
	}
	if v, isID := a.Lhs[0].(*ast.Ident); !isID || v.Name == "_" {
		return nil
	}
	c, isCall := ast.Unparen(a.Rhs[0]).(*ast.CallExpr)
	if !isCall {
		return nil
	}
	sel, isSel := ast.Unparen(c.Fun).(*ast.SelectorExpr)
	if !isSel || !isSealerOpen(info.Uses[sel.Sel]) {
		return nil
	}
	return sel.Sel
}

// defersClear reports whether s is `defer clear(v)`, with the builtin
// clear and v the same variable as lhs.
func defersClear(s ast.Stmt, lhs ast.Expr, info *types.Info) bool {
	d, isDefer := s.(*ast.DeferStmt)
	if !isDefer || len(d.Call.Args) != 1 {
		return false
	}
	fn, isID := ast.Unparen(d.Call.Fun).(*ast.Ident)
	if !isID {
		return false
	}
	if _, builtin := info.Uses[fn].(*types.Builtin); !builtin || fn.Name != "clear" {
		return false
	}
	arg, isID := ast.Unparen(d.Call.Args[0]).(*ast.Ident)
	v := lhs.(*ast.Ident)
	want := info.ObjectOf(v)
	return isID && want != nil && info.ObjectOf(arg) == want
}

// isSealerOpen reports whether obj is a method named Open with the
// signature func([]byte, []byte) ([]byte, error).
func isSealerOpen(obj types.Object) bool {
	fn, isFn := obj.(*types.Func)
	if !isFn || fn.Name() != "Open" {
		return false
	}
	sig := fn.Type().(*types.Signature)
	if sig.Recv() == nil || sig.Variadic() || sig.Params().Len() != 2 || sig.Results().Len() != 2 {
		return false
	}
	// Underlying types, so an Open over a named slice (type Blob []byte) is one too.
	bytes := types.NewSlice(types.Typ[types.Byte])
	isBytes := func(t types.Type) bool { return types.Identical(t.Underlying(), bytes) }
	return isBytes(sig.Params().At(0).Type()) &&
		isBytes(sig.Params().At(1).Type()) &&
		isBytes(sig.Results().At(0).Type()) &&
		types.Identical(sig.Results().At(1).Type(), types.Universe.Lookup("error").Type())
}

// TestTheWipeLintRefusesEachShape checks the rule on synthetic sources: each
// case is one function body, and want is the number of problems it has.
func TestTheWipeLintRefusesEachShape(t *testing.T) {
	l, err := wipeLoad()
	if err != nil {
		t.Fatal(err)
	}
	const head = `package p

import "errors"

type Sealer interface {
	Seal(plain, aad []byte) ([]byte, error)
	Open(blob, aad []byte) ([]byte, error)
}

type aead struct{}

func (aead) Open(blob, aad []byte) ([]byte, error) { return blob, nil }

type vm struct{}

func (vm) Open(name string, n int) ([]byte, error) { return nil, nil }

var _ = errors.New
var sink []byte

`
	cases := []struct {
		name, body string
		want       int
	}{
		{"defer right after the open", `func f(s Sealer, b []byte) error {
	plain, err := s.Open(b, nil)
	// a comment between is no statement
	defer clear(plain)
	if err != nil {
		return err
	}
	sink = plain[:0]
	return nil
}`, 0},
		{"plain assignment, concrete sealer", `func f(s aead, b []byte) (err error) {
	var plain []byte
	plain, err = s.Open(b, nil)
	defer clear(plain)
	return err
}`, 0},
		{"a sealer wrapper hands its plaintext to its caller", `type kept struct{ Sealer }

func (k kept) Open(blob, aad []byte) ([]byte, error) {
	plain, err := k.Sealer.Open(blob, aad)
	return plain, err
}`, 0},
		{"a wrapper returning the Open straight on", `type kept struct{ Sealer }

func (k kept) Open(blob, aad []byte) ([]byte, error) {
	return k.Sealer.Open(blob, aad)
}`, 0},
		{"a wrapper dropping the plaintext on its error path", `type w struct{ Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.Sealer.Open(b, a)
	if err != nil {
		return nil, err
	}
	return p, nil
}`, 1},
		{"a wrapper keeping a copy and returning nil", `type w struct{ Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, _ := x.Sealer.Open(b, a)
	sink = p
	return nil, nil
}`, 1},
		{"a closure in a wrapper", `type w struct{ Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	go func() {
		p, _ := x.Sealer.Open(b, a)
		sink = p
	}()
	return nil, nil
}`, 1},
		{"a wrapper returning the Open from a closure", `type w struct{ Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	f := func() ([]byte, error) { return x.Sealer.Open(b, a) }
	return f()
}`, 1},
		{"a wrapper opening twice, the first left unwiped", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	inner, err := x.S.Open(b, a)
	if err != nil {
		return nil, err
	}
	return x.S.Open(inner, a)
}`, 1},
		{"a wrapper discarding an Open", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	_, _ = x.S.Open(b, a)
	return nil, nil
}`, 1},
		{"an Open over a named byte slice", `type Blob []byte

type named interface {
	Open(blob, aad Blob) (Blob, error)
}

func f(s named, b Blob) error {
	plain, err := s.Open(b, nil)
	if err != nil {
		return err
	}
	defer clear(plain)
	return nil
}`, 1},
		{"an Open of another shape is no sealer's", `func f(v vm) error {
	m, err := v.Open("x", 1)
	_ = m
	return err
}`, 0},
		{"defer after the error check (#5772)", `func f(s Sealer, b []byte) error {
	plain, err := s.Open(b, nil)
	if err != nil {
		return err
	}
	defer clear(plain)
	return nil
}`, 1},
		{"wiped by hand after use", `func f(s Sealer, b []byte) error {
	plain, err := s.Open(b, nil)
	if err != nil {
		return errors.New("no")
	}
	clear(plain)
	return nil
}`, 1},
		{"defer clear of another buffer", `func f(s Sealer, b []byte) error {
	plain, err := s.Open(b, nil)
	defer clear(b)
	_ = plain
	return err
}`, 1},
		{"a clear that is not the builtin", `func clear(b []byte) {}

func f(s Sealer, b []byte) error {
	plain, err := s.Open(b, nil)
	defer clear(plain)
	_ = plain
	return err
}`, 1},
		{"plaintext discarded", `func f(s Sealer, b []byte) error {
	_, err := s.Open(b, nil)
	return err
}`, 1},
		{"opened in an if header", `func f(s Sealer, b []byte) error {
	if plain, err := s.Open(b, nil); err != nil {
		return err
	} else {
		clear(plain)
	}
	return nil
}`, 1},
		{"returned from a helper that is no Open", `func f(s Sealer, b []byte) ([]byte, error) {
	return s.Open(b, nil)
}`, 1},
		{"passed straight on", `func g(b []byte, err error) {}

func f(s Sealer, b []byte) {
	g(s.Open(b, nil))
}`, 1},
		{"taken as a value", `func f(s Sealer, b []byte) error {
	o := s.Open
	plain, err := o(b, nil)
	defer clear(plain)
	return err
}`, 1},
		{"in a closure and a switch case", `func f(s Sealer, b []byte, k int) {
	go func() {
		plain, err := s.Open(b, nil)
		_, _ = plain, err
	}()
	switch k {
	case 1:
		plain, err := s.Open(b, nil)
		defer clear(plain)
		_ = err
	}
}`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := parser.ParseFile(l.Fset, "case.go", head+c.body, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			_, info, err := l.Check("example.test/p", []*ast.File{f})
			if err != nil {
				t.Fatal(err)
			}
			if _, got := wipeProblems(l.Fset, f, info); len(got) != c.want {
				t.Fatalf("got %d problems %q; want %d", len(got), got, c.want)
			}
		})
	}
}
