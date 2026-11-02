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
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The package's shape is pinned for correctness, not for secrecy from
// other code in the enforcer process, which is trusted (ASSUMPTIONS
// ENF-page-csrf-2): its exported API is exactly want, so no getter for a
// key, tag or token appears by accident and the page cannot misplace one;
// every field of Tokens is a func, so fmt of a Tokens or any holder prints
// no key into a log (TestFmtPrintsNoSecret); and its MACs are compared in
// constant time (compares). Revert mutants: an exported Token method, a
// key []byte field, a string == in Check, a bytes.Equal in age, each fail.
func TestAPI(t *testing.T) {
	pkg, files, info := checked(t)
	const p = "github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf"
	var got []string
	for _, n := range pkg.Scope().Names() {
		if o := pkg.Scope().Lookup(n); o.Exported() {
			got = append(got, types.ObjectString(o, nil))
		}
	}
	ms := types.NewMethodSet(types.NewPointer(pkg.Scope().Lookup("Tokens").Type()))
	for i := range ms.Len() {
		if m := ms.At(i).Obj(); m.Exported() {
			got = append(got, types.ObjectString(m, nil))
		}
	}
	slices.Sort(got)
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
		t.Errorf("API:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	st := pkg.Scope().Lookup("Tokens").Type().Underlying().(*types.Struct)
	for i := range st.NumFields() {
		if _, ok := st.Field(i).Type().Underlying().(*types.Signature); !ok {
			t.Errorf("Tokens.%s is a %s, not a func: fmt would print it", st.Field(i).Name(), st.Field(i).Type())
		}
	}
	for _, p := range compares(files, info) {
		t.Error(p)
	}
}

// compares is the constant-time rule (#4427 item 3), resolved through
// go/types: Check and age each call crypto/hmac.Equal, and nothing in the
// package compares strings or arrays with == or != or calls another
// package's Equal, Compare or DeepEqual. It catches an honest regression;
// the body is read whole in review.
func compares(files []*ast.File, info *types.Info) []string {
	var problems []string
	equalIn := map[string]bool{}
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.BinaryExpr:
					if n.Op != token.EQL && n.Op != token.NEQ {
						break
					}
					switch u := info.TypeOf(n.X).Underlying().(type) {
					case *types.Basic:
						if u.Info()&types.IsString != 0 {
							problems = append(problems, fmt.Sprintf("%s: %s compares strings", fd.Name.Name, types.ExprString(n)))
						}
					case *types.Array:
						problems = append(problems, fmt.Sprintf("%s: %s compares arrays", fd.Name.Name, types.ExprString(n)))
					}
				case *ast.CallExpr:
					var id *ast.Ident
					switch fn := n.Fun.(type) {
					case *ast.Ident:
						id = fn
					case *ast.SelectorExpr:
						id = fn.Sel
					}
					o, ok := info.Uses[id].(*types.Func)
					if !ok || o.Pkg() == nil {
						break
					}
					switch {
					case o.Pkg().Path() == "crypto/hmac" && o.Name() == "Equal":
						equalIn[fd.Name.Name] = true
					case o.Pkg() != info.Defs[fd.Name].Pkg() && slices.Contains([]string{"Equal", "Compare", "DeepEqual"}, o.Name()):
						problems = append(problems, fmt.Sprintf("%s: calls %s.%s", fd.Name.Name, o.Pkg().Path(), o.Name()))
					}
				}
				return true
			})
		}
	}
	if !equalIn["Check"] || !equalIn["age"] {
		problems = append(problems, fmt.Sprintf("hmac.Equal is called in %v, want Check and age", equalIn))
	}
	return problems
}

// checked is this package's non-test Go files, type-checked.
func checked(t *testing.T) (*types.Package, []*ast.File, *types.Info) {
	t.Helper()
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, n := range names {
		if strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check("github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf", fset, files, info)
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
