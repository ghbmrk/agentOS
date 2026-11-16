package wipelint_test

// REQ: CLK-1, STO-2

// The sealer wipe lint (CLK-open-wipe-lint). A plaintext a sealer's Open
// hands back is a credential or a private record, and a sealer may fail
// after it decrypted, returning the plaintext beside its error. Three PRs
// in a row found a caller that returned on that error before its wipe
// (#5666, #5772, and the keys, secrets and plan stores fixed with this
// lint), so the shape is now refused here instead of in review.
// The keys and secrets stores open through sealopen.With, whose tests
// observe the wipe (a lint cannot fail a mutant); this lint holds the
// shape of every Open, With's own included.
//
// The rule, over every non-test file of every package under broker/clerk,
// type-checked: a call of a method named Open whose signature is
// func([]byte, []byte) ([]byte, error) (clerk.Sealer's Open, whatever type
// or interface spells it) or func([]byte, []byte, []byte, []byte) ([]byte,
// error) (cipher.AEAD's, CLK-aead-open-wipe #5788) appears only as `v, err := x.Open(a, b)` (or =)
// with v a named variable, and the very next statement is
// `defer clear(v)` with the builtin clear, so the wipe covers every return
// path, the error path included. A function listed in wipeWrappers hands
// its plaintext to its caller: its own Opens are exempt, and every call of
// it is held as an Open is (#5799), so a caller that drops the wipe fails
// as a direct Open's would. A function listed in wipeExempt has its Opens
// exempt and its callers unheld, the reason given (no secret, or a wipe
// the rule cannot see): that entry, and each listed function's body, are
// held by review. A new wrapper fails until a reviewed PR lists it, and a
// listed function that is gone fails too (stale). Any other use fails:
// the plaintext discarded to _, opened in an if or switch header,
// returned from a function that is not listed, passed straight to
// another call, or the Open or wrapper taken as a value.
//
// Bound: what the code does with v between the Open and its return (a copy
// kept, a string(v), an append that moves the bytes elsewhere) is held by
// review (a later v = ... does not escape: defer evaluates v at the
// defer); so are files a build tag leaves out of the default build, callers outside broker/clerk, and an Open that is a struct field
// or variable of func type rather than a method (none exists today).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/lintload"
)

// wipeWrappers names, by types.Func.FullName, each function that hands
// an opened plaintext to its caller, with the reason. Its own Opens are
// exempt, and each call of it is held as an Open is (#5799), so the wipe
// moves to its callers rather than out of the rule.
var wipeWrappers = map[string]string{
	// The test sealer records each plaintext so a test can check its
	// caller wiped it (Wiped); it returns the plaintext beside OpenErr.
	"(*github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest.Kept).Open": "test sealer: hands back and records the plaintext",
	// The clerk's sealer: its plaintext goes to the callers of its Open.
	"(github.com/ghbmrk/agentos/broker/clerk.aesSealer).Open": "the sealer itself: its Open's callers are held here",
	// The store's unwrap: Unlock's two calls defer the wipe.
	"github.com/ghbmrk/agentos/broker/clerk/seal.open": "Unlock's calls are held here",
}

// wipeExempt names, by types.Func.FullName, each function whose Opens are
// exempt and whose callers are not held, with the reason: its plaintext
// is no secret, or a wipe the rule cannot see covers it. Nothing but
// review holds an entry, so each reason names what keeps it true.
var wipeExempt = map[string]string{
	// A driver's key: opened through a closure, once at start and once
	// per Lend, each plaintext wiped on success (clear at start, defer
	// clear in the Lend); stdlib GCM returns a nil plaintext with every
	// error, so the error paths hold nothing. Reshaping it so the rule
	// holds it moves devslot/proc under the mutation gate, which waits on
	// #5800 (#5799's hand-off).
	"github.com/ghbmrk/agentos/broker/clerk/devslot/proc.lendFrom": "callers unchecked: keep the clear at the start check and the defer clear in the Lend",
	// A session frame is an accessory's HTTP response (characteristic
	// values, no key): Read copies it into the session's bufio.Reader and
	// the HTTP parser keeps more copies, so a wipe here would erase one
	// copy of several (#5788).
	"(*github.com/ghbmrk/agentos/broker/clerk/homekit.frameReader).next": "frame handed to Read; an HTTP response copied on by bufio",
	// Pair-setup M6 and pair-verify M2 carry the accessory's identifier,
	// long-term public key and signature, all public; the pin keeps
	// slices of the plaintext, so a wipe would erase the pin.
	"github.com/ghbmrk/agentos/broker/clerk/homekit.openMsg": "pairing plaintext is public: identifier, public key, signature",
}

// clerkDir is broker/clerk, the tree the rule reads. The lint sits in its
// own package so that package clerk's tests, and so the mutation gate's
// targets for it, stay those of the clerk itself.
const clerkDir = ".."

var wipeLoad = sync.OnceValues(func() (*lintload.Loaded, error) {
	return lintload.Load(clerkDir, lintload.Build{}, "./...")
})

// TestEveryOpenedPlaintextIsWipedOnEveryPath runs the rule over the tree.
func TestEveryOpenedPlaintextIsWipedOnEveryPath(t *testing.T) {
	l, err := wipeLoad()
	if err != nil {
		t.Fatal(err)
	}
	wd, err := filepath.Abs(clerkDir)
	if err != nil {
		t.Fatal(err)
	}
	var problems []string
	opens := 0
	seen := map[string]bool{}
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
			n, ps := wipeProblems(l.Fset, f, p.Info, wipeWrappers, wipeExempt, seen)
			opens += n
			for _, s := range ps {
				problems = append(problems, filepath.ToSlash(rel)+":"+s)
			}
		}
	}
	// A loader that read nothing would pass every tree: the clerk's own
	// stores alone call the sealer's Open more than this, and the five
	// direct AEAD Opens of #5788 and the seal.open calls add to them.
	if opens < 10 {
		t.Fatalf("the lint saw %d Open and wrapper calls; want the clerk's stores among them", opens)
	}
	for name, list := range map[string]map[string]string{"wipeWrappers": wipeWrappers, "wipeExempt": wipeExempt} {
		for w := range list {
			if !seen[w] {
				problems = append(problems, name+": "+w+" is no function in broker/clerk any more; remove the stale entry")
			}
		}
	}
	sort.Strings(problems)
	for _, s := range problems {
		t.Error(s)
	}
}

// wipeProblems returns how many held uses (an Open, or a function listed
// in wrappers) the file holds and, for each one the rule refuses, its line
// and why. A function listed in wrappers or exempt is marked in seen, and
// its own held uses are exempt.
func wipeProblems(fset *token.FileSet, f *ast.File, info *types.Info, wrappers, exempt map[string]string, seen map[string]bool) (int, []string) {
	ok := map[*ast.Ident]bool{}     // held callees in an allowed shape
	called := map[*ast.Ident]bool{} // held identifiers that are a call's callee
	var problems []string
	line := func(n ast.Node) string { return strconv.Itoa(fset.PositionFor(n.Pos(), false).Line) }
	held := func(obj types.Object) bool {
		if isSealerOpen(obj) {
			return true
		}
		fn, isFunc := obj.(*types.Func)
		if !isFunc {
			return false
		}
		_, listed := wrappers[fn.FullName()]
		return listed
	}

	for _, decl := range f.Decls {
		fd, isFn := decl.(*ast.FuncDecl)
		listed := false
		if isFn {
			if fn, isFunc := info.Defs[fd.Name].(*types.Func); isFunc {
				_, w := wrappers[fn.FullName()]
				_, e := exempt[fn.FullName()]
				if listed = w || e; listed {
					seen[fn.FullName()] = true
				}
			}
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			if c, isCall := n.(*ast.CallExpr); isCall {
				if id := callee(c); id != nil && held(info.Uses[id]) {
					called[id] = true
					if listed {
						ok[id] = true
					}
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
				id := openAssign(s, info, held)
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
		if !isID || !held(info.Uses[id]) {
			return true
		}
		uses++
		switch {
		case ok[id]:
		case !called[id]:
			problems = append(problems, line(id)+": "+id.Name+" taken as a value; call it and defer clear on its plaintext")
		default:
			problems = append(problems, line(id)+": "+id.Name+"'s plaintext is not wiped on every path; write `v, err := "+id.Name+"(...)` then `defer clear(v)` as the next statement")
		}
		return true
	})
	return uses, problems
}

// openAssign returns the held callee of s when s is `v, err := x.Open(a,
// b)` or `v, err := wrapper(...)` (or =) with v a named variable.
func openAssign(s ast.Stmt, info *types.Info, held func(types.Object) bool) *ast.Ident {
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
	id := callee(c)
	if id == nil || !held(info.Uses[id]) {
		return nil
	}
	return id
}

// callee returns the identifier a call names: f in f(...), Sel in
// x.Sel(...), or nil for any other callee expression.
func callee(c *ast.CallExpr) *ast.Ident {
	switch fn := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		return fn
	case *ast.SelectorExpr:
		return fn.Sel
	}
	return nil
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
// signature func([]byte, []byte) ([]byte, error), a sealer's, or
// func([]byte, []byte, []byte, []byte) ([]byte, error), an AEAD's.
func isSealerOpen(obj types.Object) bool {
	fn, isFn := obj.(*types.Func)
	if !isFn || fn.Name() != "Open" {
		return false
	}
	sig := fn.Type().(*types.Signature)
	if n := sig.Params().Len(); sig.Recv() == nil || sig.Variadic() || (n != 2 && n != 4) || sig.Results().Len() != 2 {
		return false
	}
	// Underlying types, so an Open over a named slice (type Blob []byte) is one too.
	bytes := types.NewSlice(types.Typ[types.Byte])
	isBytes := func(t types.Type) bool { return types.Identical(t.Underlying(), bytes) }
	for i := range sig.Params().Len() {
		if !isBytes(sig.Params().At(i).Type()) {
			return false
		}
	}
	return isBytes(sig.Results().At(0).Type()) &&
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

type AEAD interface {
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

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
		{"a listed wrapper hands its plaintext to its caller", `type listed struct{ Sealer }

func (k *listed) Open(blob, aad []byte) ([]byte, error) {
	plain, err := k.Sealer.Open(blob, aad)
	return plain, err
}`, 0},
		{"the same wrapper unlisted", `type kept struct{ Sealer }

func (k kept) Open(blob, aad []byte) ([]byte, error) {
	plain, err := k.Sealer.Open(blob, aad)
	return plain, err
}`, 1},
		{"an unlisted wrapper returning the Open straight on", `type kept struct{ Sealer }

func (k kept) Open(blob, aad []byte) ([]byte, error) {
	return k.Sealer.Open(blob, aad)
}`, 1},
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
}`, 2},
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
		{"a wrapper opening twice into one variable", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.S.Open(b, a)
	p, err = x.S.Open(p, a)
	return p, err
}`, 2},
		{"a wrapper opening in a loop", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	var p []byte
	var err error
	for i := 0; i < 2; i++ {
		p, err = x.S.Open(b, a)
	}
	return p, err
}`, 1},
		{"a wrapper clearing its variable before return", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.S.Open(b, a)
	p = nil
	return p, err
}`, 1},
		{"a wrapper reslicing its plaintext", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.S.Open(b, a)
	return p[:0], err
}`, 1},
		{"a wrapper's closure reassigning its variable", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.S.Open(b, a)
	func() { p = nil }()
	return p, err
}`, 1},
		{"a wrapper taking its variable's address", `type w struct{ S Sealer }

func reset(p *[]byte) { *p = nil }

func (x w) Open(b, a []byte) ([]byte, error) {
	p, err := x.S.Open(b, a)
	reset(&p)
	return p, err
}`, 1},
		{"a wrapper opening after another statement", `type w struct{ S Sealer }

func (x w) Open(b, a []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("empty")
	}
	p, err := x.S.Open(b, a)
	return p, err
}`, 1},
		{"an AEAD Open with its defer next", `func f(g AEAD, b []byte) error {
	plain, err := g.Open(nil, b[:12], b[12:], nil)
	defer clear(plain)
	return err
}`, 0},
		{"an AEAD Open wiped after the error check (codeseed)", `func f(g AEAD, b []byte) error {
	plain, err := g.Open(nil, b[:12], b[12:], nil)
	if err != nil {
		return err
	}
	defer clear(plain)
	return nil
}`, 1},
		{"an AEAD Open returned from a closure (devslot)", `func f(g AEAD, b []byte) func() ([]byte, error) {
	return func() ([]byte, error) { return g.Open(nil, b[:12], b[12:], nil) }
}`, 1},
		{"an AEAD Open into an outer variable (camera)", `func f(g AEAD, b []byte, lend func(func(AEAD) error) error) error {
	var plain []byte
	err := lend(func(g AEAD) error {
		var err error
		plain, err = g.Open(nil, b[:12], b[12:], nil)
		return err
	})
	defer clear(plain)
	return err
}`, 1},
		{"an AEAD Open in a listed function that is no method", `func openListed(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}`, 0},
		{"a listed helper's caller that defers the wipe", `func openListed(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}

func caller(g AEAD, b []byte) error {
	p, err := openListed(g, b)
	defer clear(p)
	return err
}`, 0},
		{"a listed helper's caller that wipes by hand (seal.Unlock before #5799)", `func openListed(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}

func caller(g AEAD, b []byte) error {
	p, err := openListed(g, b)
	if err != nil {
		return err
	}
	clear(p)
	return nil
}`, 1},
		{"a listed helper's caller that drops the wipe", `func openListed(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}

func caller(g AEAD, b []byte) error {
	p, err := openListed(g, b)
	sink = p
	return err
}`, 1},
		{"a listed helper taken as a value", `func openListed(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}

func caller(g AEAD, b []byte) error {
	o := openListed
	p, err := o(g, b)
	defer clear(p)
	return err
}`, 1},
		{"a listed wrapper method's caller that drops the wipe", `type listed struct{ Sealer }

func (k *listed) Open(blob, aad []byte) ([]byte, error) {
	plain, err := k.Sealer.Open(blob, aad)
	return plain, err
}

func caller(k *listed, b []byte) error {
	p, err := k.Open(b, nil)
	sink = p
	return err
}`, 1},
		{"an exempt function's Opens and callers are not held", `func openPublic(g AEAD, b []byte) ([]byte, error) {
	return g.Open(nil, b[:12], b[12:], nil)
}

func caller(g AEAD, b []byte) error {
	p, err := openPublic(g, b)
	sink = p
	return err
}`, 0},
		{"an AEAD Open in an unlisted function returned on", `func openOther(g AEAD, b []byte) ([]byte, error) {
	p, err := g.Open(nil, b[:12], b[12:], nil)
	if err != nil {
		return nil, err
	}
	return p, nil
}`, 1},
		{"an Open of three byte slices is neither shape", `type three struct{}

func (three) Open(a, b, c []byte) ([]byte, error) { return nil, nil }

func f(x three) error {
	p, err := x.Open(nil, nil, nil)
	_ = p
	return err
}`, 0},
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
			wrappers := map[string]string{"(*example.test/p.listed).Open": "case", "example.test/p.openListed": "case"}
			exempt := map[string]string{"example.test/p.openPublic": "case"}
			if _, got := wipeProblems(l.Fset, f, info, wrappers, exempt, map[string]bool{}); len(got) != c.want {
				t.Fatalf("got %d problems %q; want %d", len(got), got, c.want)
			}
		})
	}
}
