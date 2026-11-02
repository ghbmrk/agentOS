package csrf

// REQ: CH-9

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// #4685, re-plan of #4731, #4778: no key, tag or token leaves this
// package as a value. The package is type-checked and the surface another
// package can reach is computed from go/types, never from spellings: every
// exported object, and every exported method and exported field of every
// named type that surface reaches, whichever package declares it. That
// list must equal want, so adding an exported name, changing a signature,
// or giving any reachable type (exported or not) a new exported method or
// field fails here. No exported variable is allowed (one is assignable, so
// page code could change it, #4780), and no exported result or field may
// have an interface type, since an interface value can carry a type of
// this package whose methods the page then reaches by assertion (#4778).
// The imports must equal wantImps. Revert mutants: an exported Token()
// method, a key field, an exported var, an error result holding a type
// with a Mac method, importing fmt, each fail.
func TestAPI(t *testing.T) {
	pkg, files, info := checked(t)
	got, problems := surface(pkg)
	for _, p := range problems {
		t.Error(p)
	}
	const p = "github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf"
	want := []string{
		"const " + p + ".Cookie untyped string",
		"const " + p + ".Header untyped string",
		"const " + p + ".PairLife time.Duration",
		"const " + p + ".ReuseFor time.Duration",
		"func " + p + ".New(now func() time.Time) (*" + p + ".Tokens, bool)",
		"func (*" + p + ".Tokens).Check(r *net/http.Request) bool",
		"func (*" + p + ".Tokens).Screen(w net/http.ResponseWriter, r *net/http.Request, markup []byte) bool",
		"type " + p + ".Tokens struct{now func() time.Time; mac func(label string, body []byte) []byte}",
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("reachable API:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	// Every field of Tokens is a func, so fmt prints no key from it: fmt
	// never calls a func value.
	st := pkg.Scope().Lookup("Tokens").Type().Underlying().(*types.Struct)
	for i := range st.NumFields() {
		if _, ok := st.Field(i).Type().Underlying().(*types.Signature); !ok {
			t.Errorf("Tokens.%s is a %s, not a func", st.Field(i).Name(), st.Field(i).Type())
		}
	}

	var imps []string
	for _, i := range pkg.Imports() {
		imps = append(imps, i.Path())
	}
	slices.Sort(imps)
	wantImps := []string{"crypto/hmac", "crypto/rand", "crypto/sha256", "encoding/base64", "encoding/binary", "net/http", "time"}
	if !slices.Equal(imps, wantImps) {
		t.Errorf("imports %v, want %v", imps, wantImps)
	}

	for _, p := range compareProblems(files, info) {
		t.Error(p)
	}
}

// surface is every exported object of pkg, and every exported method and
// field of each named type of pkg reachable from them through signatures,
// fields, pointers, slices, arrays, maps, channels and method sets, as
// types.ObjectString prints them (full package paths), sorted; and the
// problems. Each reachable type is walked with its direction: out when
// this package hands the value to its caller (an exported func, a result,
// a field or element of an out value, a parameter of a func the caller
// hands in), in otherwise. A value that flows out must not be an exported
// variable, an interface (it may carry a type of this package whose
// methods the caller reaches by assertion), or a named type of another
// package other than one of basic kind, since such a type can hold an
// interface in turn.
func surface(pkg *types.Package) (got, problems []string) {
	type key struct {
		t   types.Type
		out bool
	}
	seen := map[key]bool{}
	add := func(s string) {
		if !slices.Contains(got, s) {
			got = append(got, s)
		}
	}
	var walk func(t types.Type, out bool, where string)
	walk = func(t types.Type, out bool, where string) {
		if seen[key{t, out}] {
			return
		}
		seen[key{t, out}] = true
		switch t := t.(type) {
		case *types.Named:
			if t.Obj().Pkg() != pkg {
				_, basic := t.Underlying().(*types.Basic)
				if t.Obj().Pkg() != nil && out && !basic {
					problems = append(problems, fmt.Sprintf("%s: a %s flows out", where, t))
				}
				if t.Obj().Pkg() == nil {
					walk(t.Underlying(), out, where) // error
				}
				return
			}
			for _, recv := range []types.Type{t, types.NewPointer(t)} {
				ms := types.NewMethodSet(recv)
				for i := range ms.Len() {
					if m := ms.At(i).Obj(); m.Exported() {
						add(types.ObjectString(m, nil))
						walk(m.Type(), true, where+"."+m.Name())
					}
				}
			}
			walk(t.Underlying(), out, where)
		case *types.Alias:
			walk(types.Unalias(t), out, where)
		case *types.Pointer:
			walk(t.Elem(), out, where)
		case *types.Slice:
			walk(t.Elem(), out, where)
		case *types.Array:
			walk(t.Elem(), out, where)
		case *types.Map:
			walk(t.Key(), out, where)
			walk(t.Elem(), out, where)
		case *types.Chan:
			walk(t.Elem(), true, where)
			walk(t.Elem(), false, where)
		case *types.Signature:
			for v := range t.Params().Variables() {
				walk(v.Type(), !out, where)
			}
			for v := range t.Results().Variables() {
				walk(v.Type(), out, where)
			}
		case *types.Struct:
			for i := range t.NumFields() {
				if f := t.Field(i); f.Exported() {
					add(types.ObjectString(f, nil))
					walk(f.Type(), out, where+"."+f.Name())
				}
			}
		case *types.Interface:
			if out {
				problems = append(problems, fmt.Sprintf("%s: an interface value (%s) flows out, and may carry a type of this package", where, t))
			}
		}
	}
	for _, n := range pkg.Scope().Names() {
		o := pkg.Scope().Lookup(n)
		if !o.Exported() {
			continue
		}
		add(types.ObjectString(o, nil))
		if _, ok := o.(*types.Var); ok {
			problems = append(problems, fmt.Sprintf("%s is an exported variable: page code could assign it", n))
		}
		walk(o.Type(), true, n)
	}
	slices.Sort(got)
	return got, problems
}

// compareProblems lists each comparison in files that could compare a MAC
// other than in constant time: a ==, !=, <, <=, > or >= between two
// non-constant operands of string, byte or array type, a switch whose tag
// and a case are both non-constant strings, or any call other than
// crypto/hmac.Equal that compares bytes. Every MAC is compared by
// hmac.Equal, exactly twice (Check's token and age's tag). Objects are
// resolved through types.Info, so a renamed import or a local named hmac
// does not count. Revert mutant: either hmac.Equal replaced by a string
// compare fails.
func compareProblems(files []*ast.File, info *types.Info) []string {
	var problems []string
	equal := 0
	constant := func(e ast.Expr) bool { return info.Types[e].Value != nil }
	risky := func(e ast.Expr) bool {
		t := info.TypeOf(e)
		if t == nil {
			return false
		}
		switch u := t.Underlying().(type) {
		case *types.Basic:
			return u.Info()&types.IsString != 0 || u.Kind() == types.Byte || u.Kind() == types.Uint8
		case *types.Array:
			return true
		}
		return false
	}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.BinaryExpr:
				switch n.Op {
				case token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
					if !constant(n.X) && !constant(n.Y) && (risky(n.X) || risky(n.Y)) {
						problems = append(problems, fmt.Sprintf("%s: a variable-time comparison %s", f.Name.Name, types.ExprString(n)))
					}
				}
			case *ast.SwitchStmt:
				if n.Tag != nil && !constant(n.Tag) && risky(n.Tag) {
					for _, c := range n.Body.List {
						for _, e := range c.(*ast.CaseClause).List {
							if !constant(e) {
								problems = append(problems, fmt.Sprintf("%s: a variable-time switch case %s", f.Name.Name, types.ExprString(e)))
							}
						}
					}
				}
			case *ast.CallExpr:
				var id *ast.Ident
				switch fn := n.Fun.(type) {
				case *ast.Ident:
					id = fn
				case *ast.SelectorExpr:
					id = fn.Sel
				}
				if id == nil {
					break
				}
				if o, ok := info.Uses[id].(*types.Func); ok && o.Pkg() != nil {
					if o.Pkg().Path() == "crypto/hmac" && o.Name() == "Equal" {
						equal++
					}
				}
			}
			return true
		})
	}
	if equal != 2 {
		problems = append(problems, fmt.Sprintf("hmac.Equal is called %d times, want 2 (Check's token, age's tag)", equal))
	}
	return problems
}

// checked is this package's non-test Go files, type-checked. A type-check
// error, any file other than a .go file in the directory (assembly, C,
// syso), a directive, or a function declared without a body fails the
// test.
func checked(t *testing.T) (*types.Package, []*ast.File, *types.Info) {
	t.Helper()
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || filepath.Ext(n) != ".go" {
			t.Errorf("%s: package csrf holds only Go files", n)
			continue
		}
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		for _, g := range f.Comments {
			for _, c := range g.List {
				if strings.HasPrefix(c.Text, "//go:") || strings.HasPrefix(c.Text, "//line") {
					t.Errorf("%s: directive %q", n, c.Text)
				}
			}
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Body == nil {
				t.Errorf("%s: %s is declared without a body", n, fd.Name.Name)
			}
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.Default()}
	pkg, err := conf.Check("github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf", fset, files, info)
	if err != nil {
		t.Fatal(err)
	}
	return pkg, files, info
}

var epoch = time.UnixMilli(1_800_000_000_000)

func newTokens(t *testing.T, now *time.Time) *Tokens {
	t.Helper()
	k, ok := New(func() time.Time { return *now })
	if !ok {
		t.Fatal("New refused a clock")
	}
	return k
}

// screen draws a screen of k for a request with site and cookie ("" sends
// none) and returns the cookie set ("" when none) and the token shown.
func screen(t *testing.T, k *Tokens, site, cookie string, markup string) (set, tok, body string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "https://enforcer.home.arpa/", nil)
	if site != "" {
		r.Header.Set("Sec-Fetch-Site", site)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: Cookie, Value: cookie})
	}
	w := httptest.NewRecorder()
	if !k.Screen(w, r, []byte(markup)) {
		t.Fatal("Screen refused")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == Cookie {
			set = c.Value
		}
	}
	body = w.Body.String()
	rest, ok := strings.CutPrefix(body, prefix)
	if !ok {
		t.Fatalf("screen does not open with the fixed prefix:\n%s", body)
	}
	tok, after, ok := strings.Cut(rest, "\">\n")
	if !ok || after != markup {
		t.Fatalf("screen is not prefix, token, markup:\n%s", body)
	}
	return set, tok, body
}

func check(k *Tokens, cookie, tok string) bool {
	r := httptest.NewRequest(http.MethodPost, "https://enforcer.home.arpa/approve", nil)
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: Cookie, Value: cookie})
	}
	if tok != "" {
		r.Header.Set(Header, tok)
	}
	return k.Check(r)
}

// #4756: the token sits in one place, the screen's opening, which csrf
// writes before the page's markup; markup cannot move it or add another,
// since the page never holds the value. The screen's pair passes Check.
func TestScreenFixesTokenPlace(t *testing.T) {
	now := epoch
	k := newTokens(t, &now)
	markup := `<title>x</title><img src="https://elsewhere.example/?t=">`
	set, tok, body := screen(t, k, "cross-site", "", markup)
	if set == "" || tok == "" || strings.Count(body, tok) != 1 {
		t.Fatalf("set %q token %q in\n%s", set, tok, body)
	}
	if !check(k, set, tok) {
		t.Error("the screen's own pair is refused")
	}
	if !strings.HasPrefix(prefix, "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n") {
		t.Errorf("the prefix does not open the document: %q", prefix)
	}
}

// #4428: a same-site navigation that sends a cookie this page drew keeps
// it; a cookie the page cannot vouch for, or one past ReuseFor or in the
// future, mints. Revert mutants: keep ignoring the tag, the length, the
// time, or Sec-Fetch-Site, each fail here.
func TestKeepRefusesCookiesItCannotVouchFor(t *testing.T) {
	now := epoch
	k := newTokens(t, &now)
	first, tok, _ := screen(t, k, "cross-site", "", "")
	for _, site := range []string{"same-origin", "same-site", "none"} {
		if set, kept, _ := screen(t, k, site, first, ""); set != "" || kept != tok {
			t.Errorf("%s: set %q, token kept %v", site, set, kept == tok)
		}
	}
	raw, err := base64.RawURLEncoding.DecodeString(first)
	if err != nil || len(raw) != cookieLen {
		t.Fatalf("cookie %q is not %d bytes", first, cookieLen)
	}
	enc := base64.RawURLEncoding.EncodeToString
	flip := func(i int) string {
		c := slices.Clone(raw)
		c[i] ^= 1
		return enc(c)
	}
	mints := func(name, site, cookie string) {
		t.Helper()
		set, got, _ := screen(t, k, site, cookie, "")
		if set == "" || set == cookie || got == tok {
			t.Errorf("%s: kept a cookie (set %q)", name, set)
			return
		}
		if !check(k, set, got) {
			t.Errorf("%s: the new pair is refused", name)
		}
	}
	mints("cross-site", "cross-site", first)
	mints("no Sec-Fetch-Site", "", first)
	mints("nonce changed", "same-origin", flip(0))
	mints("time changed", "same-origin", flip(nonceLen+7))
	mints("tag changed", "same-origin", flip(cookieLen-1))
	mints("old 32-byte cookie", "same-origin", enc(raw[:32]))
	other := newTokens(t, &now)
	o, _, _ := screen(t, other, "cross-site", "", "")
	mints("another key's cookie", "same-origin", o)

	now = epoch.Add(ReuseFor)
	if set, kept, _ := screen(t, k, "same-origin", first, ""); set != "" || kept != tok {
		t.Errorf("at ReuseFor: set %q", set)
	}
	now = epoch.Add(ReuseFor + time.Millisecond)
	mints("expired", "same-origin", first)
	now = epoch.Add(-time.Millisecond)
	mints("drawn in the future", "same-origin", first)
}

// #4427: a pair passes for PairLife and not after, nor from the future;
// a token for another cookie, the cookie as token, or a token with no
// cookie never passes. Revert mutants: Check ignoring the age, the future,
// or comparing with >= PairLife, each fail here.
func TestCheck(t *testing.T) {
	if ReuseFor <= 0 || PairLife-ReuseFor < ReuseFor {
		t.Fatalf("ReuseFor %v leaves a kept screen less than %v", ReuseFor, PairLife-ReuseFor)
	}
	now := epoch
	k := newTokens(t, &now)
	c, tok, _ := screen(t, k, "cross-site", "", "")
	c2, tok2, _ := screen(t, k, "cross-site", "", "")
	refused := map[string][2]string{
		"no cookie":               {"", tok},
		"no token":                {c, ""},
		"token of another cookie": {c, tok2},
		"cookie as token":         {c, c},
		"bad cookie":              {"AAAA", tok},
		"not base64":              {c, "!!!!"},
	}
	for name, p := range refused {
		if check(k, p[0], p[1]) {
			t.Errorf("%s: passes", name)
		}
	}
	if !check(k, c2, tok2) {
		t.Error("the second pair is refused")
	}
	now = epoch.Add(PairLife)
	if !check(k, c, tok) {
		t.Error("refused at PairLife")
	}
	now = epoch.Add(PairLife + time.Millisecond)
	if check(k, c, tok) {
		t.Error("passes past PairLife")
	}
	now = epoch.Add(-time.Millisecond)
	if check(k, c, tok) {
		t.Error("a cookie drawn in the future passes")
	}
}

// #4479: the tag and the token are MACs under one key with different
// labels, so neither stands in for the other over the same bytes. Revert
// mutant: cookieLabel equal to tokenLabel fails.
func TestTagAndTokenLabelsDiffer(t *testing.T) {
	now := epoch
	k := newTokens(t, &now)
	for _, n := range []int{0, bodyLen, cookieLen} {
		x := bytes.Repeat([]byte{7}, n)
		if bytes.Equal(k.mac(cookieLabel, x), k.mac(tokenLabel, x)) {
			t.Errorf("tag and token agree over %d bytes", n)
		}
	}
}

// #4757, #4758: fmt of a Tokens, a pointer to one, or a holder at any
// depth prints no token or tag, in any verb: it prints code addresses
// for the func fields (not key material) and nothing else of the key.
// The control shows the detector finds bytes behind an unexported field.
func TestFmtPrintsNoSecret(t *testing.T) {
	now := epoch
	k := newTokens(t, &now)
	c, tok, _ := screen(t, k, "cross-site", "", "")
	raw, _ := base64.RawURLEncoding.DecodeString(c)
	secrets := [][]byte{raw[bodyLen:], k.mac(tokenLabel, raw[:bodyLen])}
	leaks := func(s string) bool {
		for _, b := range secrets {
			for _, e := range []string{string(b), hex.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b),
				base64.StdEncoding.EncodeToString(b), fmt.Sprint(b), fmt.Sprintf("%#v", b)} {
				if strings.Contains(s, e) {
					return true
				}
			}
		}
		return strings.Contains(s, tok)
	}
	type holder struct {
		v Tokens
		p *Tokens
		a any
	}
	for _, v := range []any{*k, k, holder{*k, k, *k}, &holder{*k, k, k}, []Tokens{*k}, map[string]Tokens{"k": *k}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
			if s := fmt.Sprintf(verb, v); leaks(s) {
				t.Errorf("%s of %T prints a secret: %s", verb, v, s)
			}
		}
	}
	if control := fmt.Sprintf("%x", struct{ b []byte }{secrets[0]}); !leaks(control) {
		t.Fatal("the detector misses bytes behind an unexported field")
	}
}

// #4781: New refuses a nil clock, and a Tokens New did not make passes
// nothing and writes nothing.
func TestZeroTokensRefuse(t *testing.T) {
	if k, ok := New(nil); ok || k != nil {
		t.Error("New took a nil clock")
	}
	for _, k := range []*Tokens{nil, {}} {
		r := httptest.NewRequest(http.MethodPost, "https://enforcer.home.arpa/approve", nil)
		if k.Check(r) {
			t.Errorf("%#v passes a request", k)
		}
		w := httptest.NewRecorder()
		if k.Screen(w, r, []byte("x")) || w.Body.Len() != 0 || len(w.Header()) != 0 {
			t.Errorf("%#v drew a screen", k)
		}
	}
}
