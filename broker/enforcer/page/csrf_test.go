package page

// REQ: CH-9

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

type nopActuator struct{}

func (nopActuator) Act(context.Context, string, action.Act, string) error { return nil }

// fullRig is a page with every route wired: a passkey enrolled through the
// enrolment screens, then the page rebuilt with the asserted actions.
func fullRig(t *testing.T) *enrolRig {
	t.Helper()
	g := newEnrolRig(t)
	if code, out := g.enrolAs(newAuthenticator(t), caseCode); code != http.StatusOK {
		t.Fatalf("enrol: %d %v", code, out)
	}
	cfg := g.s.cfg
	cfg.Owner, cfg.Act, cfg.Log, cfg.Lock = g.book.Owner(), nopActuator{}, func(string) {}, nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.s = s
	if !g.s.live() {
		t.Fatal("the rebuilt page is not live")
	}
	return g
}

// forged sends a state-changing request to h as the rig's phone would,
// with cookie and token as given ("" leaves either out), and reports
// whether it was refused by the anti-forgery check.
func (g *rig) forged(h http.Handler, method, path, cookie, token string, hdr ...string) bool {
	g.t.Helper()
	req := httptest.NewRequest(method, "https://"+rp+path, strings.NewReader("{}"))
	req.RemoteAddr = netip.AddrPortFrom(g.remote, 50000).String()
	req.Header.Set("Origin", "https://"+rp)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != "" {
		req.Header.Set("Cookie", tokenCookie+"="+cookie)
	}
	if token != "" {
		req.Header.Set(tokenHeader, token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "" {
			req.Header.Del(hdr[i])
		} else {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	b := w.Body.String()
	return w.Code == http.StatusForbidden && (strings.Contains(b, errToken.Error()) || strings.Contains(b, errCrossOrigin.Error()))
}

// attacks are the requests a page the owner merely visits, or another
// host on the network, can make the phone's browser send: each must be
// refused on every route.
func attacks(g *rig, other *Server) map[string]func(h http.Handler, method, path string) bool {
	g.t.Helper()
	// A pair minted by another page (another key) and a token for another
	// cookie of this page.
	o := &rig{t: g.t, s: other, remote: g.remote}
	o.screen()
	before := g.cookie
	g.screen()
	stale := g.token
	g.screen()
	if g.cookie == before {
		g.t.Fatal("a screen reused the last screen's cookie")
	}
	return map[string]func(h http.Handler, method, path string) bool{
		// SameSite=Strict: a request another site starts carries no cookie.
		"cross-site, no cookie": func(h http.Handler, m, p string) bool {
			return g.forged(h, m, p, "", g.token, "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site")
		},
		"no cookie":               func(h http.Handler, m, p string) bool { return g.forged(h, m, p, "", g.token) },
		"no token":                func(h http.Handler, m, p string) bool { return g.forged(h, m, p, g.cookie, "") },
		"token of another cookie": func(h http.Handler, m, p string) bool { return g.forged(h, m, p, g.cookie, stale) },
		"pair of another page":    func(h http.Handler, m, p string) bool { return g.forged(h, m, p, o.cookie, o.token) },
		"cookie as token":         func(h http.Handler, m, p string) bool { return g.forged(h, m, p, g.cookie, g.cookie) },
		"bad cookie":              func(h http.Handler, m, p string) bool { return g.forged(h, m, p, "AAAA", g.token) },
		// A form post or a no-cors fetch from a planted page: no JSON, no Origin.
		"form post": func(h http.Handler, m, p string) bool {
			return g.forged(h, m, p, g.cookie, g.token, "Content-Type", "application/x-www-form-urlencoded")
		},
		"no origin": func(h http.Handler, m, p string) bool { return g.forged(h, m, p, g.cookie, g.token, "Origin", "") },
	}
}

// CH-9 (#4387): every state-changing route on the page is behind the one
// anti-forgery check. The route table is the page's own (Server.posts),
// so a route added later is tested here as soon as it exists, and the
// table must match the list below, so adding one makes its author look at
// this test. Revert mutants: guard skipping any one route, a route served
// outside posts, guard accepting a token for another cookie, or mint
// reusing a cookie, each fail a subtest here; mutated(p) below is the first
// one, run for every route.
func TestEveryPostIsGuarded(t *testing.T) {
	g := fullRig(t)
	other := fullRig(t)
	want := []string{"/act", "/approve", "/challenge", "/do", "/enrol/begin", "/enrol/finish", "/enrol/reset"}
	got := keys(g.s.posts)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("POST routes %v, want %v: add the new route to this list", got, want)
	}
	atk := attacks(g.rig, other.s)
	for _, p := range got {
		t.Run(p, func(t *testing.T) {
			for name, refused := range atk {
				if !refused(g.s, http.MethodPost, p) {
					t.Errorf("%s: not refused", name)
				}
			}
			// The page's own screen's pair passes the check and reaches the
			// route, which answers for itself.
			if g.forged(g.s, http.MethodPost, p, g.cookie, g.token) {
				t.Errorf("the page's own token is refused")
			}
			// A mutant page that skips the check for p alone is caught by
			// the same attacks.
			mutated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == p {
					headers(w.Header())
					g.s.posts[p].h(w, r)
					return
				}
				g.s.ServeHTTP(w, r)
			})
			caught := false
			for _, refused := range atk {
				caught = caught || !refused(mutated, http.MethodPost, p)
			}
			if !caught {
				t.Errorf("a page that skips the check on %s passes every attack", p)
			}
		})
	}
	// A route nobody has written yet, and any other method, start refused:
	// the check runs before any route is looked up.
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		for _, p := range []string{"/new-route", "/approve", "/enrol/next"} {
			for name, refused := range atk {
				if !refused(g.s, m, p) {
					t.Errorf("%s %s, %s: not refused", m, p, name)
				}
			}
		}
	}
	w := g.do(http.MethodPost, "/new-route", map[string]string{})
	if w.Code != http.StatusNotFound {
		t.Errorf("an unknown route past the check: %d, want 404", w.Code)
	}
	if w := g.do(http.MethodPut, "/approve", map[string]string{}); w.Code != http.StatusNotFound {
		t.Errorf("PUT /approve past the check: %d, want 404", w.Code)
	}
	// Before a passkey is enrolled only the enrolment posts are served,
	// still behind the check.
	f := newEnrolRig(t)
	if w := f.do(http.MethodPost, "/approve", assertion{}); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), errEnrolFirst.Error()) {
		t.Errorf("/approve before enrolment: %d %s", w.Code, w.Body)
	}
	if !f.forged(f.s, http.MethodPost, "/enrol/begin", "", "") {
		t.Error("/enrol/begin before enrolment without a token: not refused")
	}
}

// CH-9: every screen the page draws sets a fresh SameSite=Strict, HttpOnly,
// Secure, host-only cookie and carries its token, and the page's script
// posts with both. Revert mutants: the cookie Lax, readable by script, on
// a Domain or a narrower path, or a screen drawn without a token.
func TestScreensCarryToken(t *testing.T) {
	g := fullRig(t)
	pg := newRig(t)
	next := edit(2, func(d *policy.Document) { d.Destinations = append(d.Destinations, "new.example") })
	screens := map[string]struct {
		g    *rig
		path string
	}{
		"home":    {g.rig, "/"},
		"enrol":   {g.rig, "/enrol"},
		"confirm": {pg, linkFor(next, "add new.example")},
	}
	for name, sc := range screens {
		w := sc.g.do(http.MethodGet, sc.path, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		checkCookie(t, name, w)
	}
	// The action screen, on a page that acts.
	cfg := pg.s.cfg
	cfg.Act, cfg.Log, cfg.Lock = nopActuator{}, func(string) {}, nil
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	pg.s = s
	w := pg.do(http.MethodGet, strings.TrimPrefix(action.Link(rp, "lock", action.Unlock, ""), "https://"+rp), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("action screen: %d %s", w.Code, w.Body)
	}
	checkCookie(t, "action", w)

	js, err := os.ReadFile("static/page.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"` + tokenHeader + `": token`, `credentials: "same-origin"`, `meta[name="enforcer-token"]`} {
		if !strings.Contains(string(js), want) {
			t.Errorf("page.js does not post with %s", want)
		}
	}
}

func checkCookie(t *testing.T, name string, w *httptest.ResponseRecorder) {
	t.Helper()
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == tokenCookie {
			c = k
		}
	}
	if c == nil {
		t.Errorf("%s: no anti-forgery cookie", name)
		return
	}
	if !strings.HasPrefix(c.Name, "__Host-") || c.SameSite != http.SameSiteStrictMode || !c.HttpOnly || !c.Secure ||
		c.Path != "/" || c.Domain != "" || c.MaxAge != 0 || !c.Expires.IsZero() {
		t.Errorf("%s: cookie %q", name, w.Header().Get("Set-Cookie"))
	}
	if m := reToken.FindStringSubmatch(w.Body.String()); m == nil || m[1] == c.Value {
		t.Errorf("%s: no token on the screen, or the token is the cookie", name)
	}
}

// navigate opens path on g.s as a top-level navigation the browser calls
// site, sending cookie ("" sends none), and returns the cookie the answer
// set ("" when it set none) and the token on the screen.
func (g *rig) navigate(path, site, cookie string) (set, token string) {
	g.t.Helper()
	hdr := []string{"Sec-Fetch-Site", site}
	if cookie != "" {
		hdr = append(hdr, "Cookie", tokenCookie+"="+cookie)
	}
	w := g.do(http.MethodGet, path, nil, hdr...)
	if w.Code != http.StatusOK {
		g.t.Fatalf("%s: %d %s", path, w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == tokenCookie {
			set = c.Value
		}
	}
	m := reToken.FindStringSubmatch(w.Body.String())
	if m == nil {
		g.t.Fatalf("%s: no token on the screen", path)
	}
	return set, m[1]
}

// CH-9 (#4428): a same-site navigation that sends a cookie this page drew
// keeps it, so the screens already open keep working; any other mints.
// Revert mutants: every screen minting, keep ignoring Sec-Fetch-Site,
// ignoring the tag, or ignoring the time, each fail a subtest here.
func TestSameSiteScreenKeepsPair(t *testing.T) {
	g := fullRig(t)
	g.screen() // opened from a text: cross-site, so it mints
	first, firstTok := g.cookie, g.token
	if first == "" {
		t.Fatal("the first screen set no cookie")
	}
	for _, site := range []string{"same-origin", "same-site", "none"} {
		for _, path := range []string{"/", "/enrol"} {
			set, tok := g.navigate(path, site, first)
			if set != "" || tok != firstTok {
				t.Errorf("%s %s with the page's cookie: set %q, token kept %v", site, path, set, tok == firstTok)
			}
		}
	}
	// The first screen's pair still passes after the second screen drew.
	if g.forged(g.s, http.MethodPost, "/approve", first, firstTok) {
		t.Error("the first screen's pair is refused after a same-site screen")
	}

	mints := func(name, site, cookie string) {
		t.Helper()
		set, tok := g.navigate("/", site, cookie)
		if set == "" || set == cookie || tok == firstTok {
			t.Errorf("%s: kept a cookie (set %q)", name, set)
			return
		}
		if g.forged(g.s, http.MethodPost, "/approve", set, tok) {
			t.Errorf("%s: the new pair is refused", name)
		}
	}
	mints("same-origin, no cookie", "same-origin", "")
	mints("cross-site with the cookie", "cross-site", first)
	mints("no Sec-Fetch-Site with the cookie", "", first)

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
	other := fullRig(t)
	other.screen()
	mints("another page's cookie", "same-origin", other.cookie)
	mints("nonce changed", "same-origin", flip(0))
	mints("time changed", "same-origin", flip(nonceLen+7))
	mints("tag changed", "same-origin", flip(cookieLen-1))
	mints("old 32-byte cookie", "same-origin", enc(raw[:32]))
	mints("not base64", "same-origin", "!!!!")

	// Expired: kept up to reuseFor after it was drawn, not after.
	g.now = g.now.Add(reuseFor)
	if set, tok := g.navigate("/", "same-origin", first); set != "" || tok != firstTok {
		t.Errorf("at reuseFor: set %q", set)
	}
	g.now = g.now.Add(time.Millisecond)
	mints("expired", "same-origin", first)
	// Drawn in the future (the clock went back): not kept.
	g.now = g.now.Add(-reuseFor - time.Hour)
	mints("drawn in the future", "same-origin", first)
}

// CH-9 (#4427): a pair passes guard for pairLife after its cookie was
// drawn and not after, whether its screen minted it or kept it, and a
// cookie the clock says was drawn in the future is refused. A screen that
// keeps a cookie at reuseFor still has pairLife-reuseFor to be tapped.
// Revert mutants: guard ignoring the age, ignoring the future, or
// comparing with >= pairLife, each fail here.
func TestPairLifetime(t *testing.T) {
	if reuseFor <= 0 || pairLife-reuseFor < reuseFor {
		t.Fatalf("reuseFor %v leaves a kept screen less than %v", reuseFor, pairLife-reuseFor)
	}
	g := fullRig(t)
	g.screen()
	c, tok := g.cookie, g.token
	start := g.now
	passes := func() bool {
		t.Helper()
		return !g.forged(g.s, http.MethodPost, "/approve", c, tok)
	}
	g.now = start.Add(reuseFor)
	if set, kept := g.navigate("/", "same-origin", c); set != "" || kept != tok {
		t.Fatalf("at reuseFor the screen did not keep the pair")
	}
	g.now = start.Add(pairLife)
	if !passes() {
		t.Error("a pair is refused at pairLife")
	}
	g.now = start.Add(pairLife + time.Millisecond)
	if passes() {
		t.Error("a pair passes past pairLife")
	}
	g.now = start.Add(-time.Millisecond)
	if passes() {
		t.Error("a pair whose cookie was drawn in the future passes")
	}
}

// #4479: the cookie's tag and the screen's token are MACs under one key
// with different labels, so neither can be taken for the other even over
// the same bytes. Revert mutant: cookieLabel equal to tokenLabel fails.
func TestTagAndTokenLabelsDiffer(t *testing.T) {
	g := fullRig(t)
	for _, n := range []int{0, nonceLen + 8, cookieLen} {
		x := bytes.Repeat([]byte{7}, n)
		if g.s.tag(x).equal(g.s.mac(x).secretSum()) {
			t.Errorf("tag and mac agree over %d bytes", n)
		}
	}
}

// #4427, #4685: a tag or a token leaves only by its exits. exitProblems
// lists each way the package's Go files and templates let one out by
// another; the package's own give none.
func TestSecretsLeaveOnlyByTheirExits(t *testing.T) {
	fset, files, tmpls := ownSource(t)
	for _, p := range exitProblems(fset, files, tmpls) {
		t.Error(p)
	}
	for _, pat := range []string{"*.s", "*.c", "*.h", "*.syso"} {
		if m, _ := filepath.Glob(pat); len(m) > 0 {
			t.Errorf("non-Go sources %v can read a secret's memory", m)
		}
	}
}

// ownSource is the package's non-test Go files and its templates.
func ownSource(t *testing.T) (*token.FileSet, []*ast.File, map[string]string) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			files = append(files, f)
		}
	}
	names, err := filepath.Glob("templates/*.html")
	if err != nil || len(names) == 0 {
		t.Fatalf("no templates: %v", err)
	}
	tmpls := map[string]string{}
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		tmpls[n] = string(b)
	}
	return fset, files, tmpls
}

// The pinned shape and bodies of secret and its exits.
const (
	secretType  = "struct{ secretSum func() []byte }"
	equalBody   = "return x.secretSum != nil && len(x.secretSum()) == sha256.Size && hmac.Equal(x.secretSum(), b)"
	cookieBody  = `http.SetCookie(w, &http.Cookie{ Name: tokenCookie, Value: base64.RawURLEncoding.EncodeToString(append(body[:len(body):len(body)], x.secretSum()...)), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, })`
	issueBody   = "return base64.RawURLEncoding.EncodeToString(x.secretSum())"
	tokenAction = "{{.Token.IssueToken}}"
)

// exitProblems checks, over the Go files (no test files) and templates:
//
//   - shape: secret is secretType, its methods are exactly equal, IssueToken
//     and setCookie with the pinned bodies, no other declaration names
//     secretSum, and each file declaring it or a method imports only the standard library
//     under its own names (so hmac and sha256 are crypto's, #4685 item 4);
//     no file imports reflect, unsafe, C, httptest, text/template or its
//     parse package. secret's own spec alone is skipped (item 5).
//   - the cookie (route 2): setCookie is called only by mint, and only once;
//     a response's header map is reached only as w.Header().Set(...) or
//     headers(w.Header()), whose parameter is used only for Set; a request's
//     only as r.Header.Get; and no type has a Header, Write or WriteHeader
//     method, so none can stand in for a response and keep what is set on it;
//     writerProblems also refuses promoted methods and other packages' types.
//   - the token (route 3): Go code never names IssueToken; the one template
//     parse is ParseFS(files, "templates/*.html"); no code reaches a
//     template's Tree; every "Token" in a template is inside {{.Token.IssueToken}};
//     and the one Execute or ExecuteTemplate is render's, into a local
//     buffer used only as w.Write([]byte(b.String())).
//
// Route 1 (fmt through a holder) needs no check here beyond the shape:
// fmt never calls a func, which TestFmtPrintsNoSecretInAnyHolder shows.
func exitProblems(fset *token.FileSet, files []*ast.File, tmpls map[string]string) []string {
	var out []string
	bad := func(n ast.Node, format string, a ...any) {
		out = append(out, fset.Position(n.Pos()).String()+": "+fmt.Sprintf(format, a...))
	}
	text := func(n any) string {
		var sb strings.Builder
		printer.Fprint(&sb, fset, n)
		return strings.Join(strings.Fields(sb.String()), " ")
	}
	var methods []string
	setCookies, parses, execs, typed := 0, 0, 0, 0
	for _, f := range files {
		ownsType := false
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.TYPE {
				for _, sp := range gd.Specs {
					if ts := sp.(*ast.TypeSpec); ts.Name.Name == "secret" {
						ownsType = true
						typed++
						if got := text(ts.Type); got != secretType {
							bad(ts, "secret is %s, want %s", got, secretType)
						}
					}
				}
			}
			if fd, ok := d.(*ast.FuncDecl); ok && secretRecv(fd) {
				ownsType = true
			}
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			switch path {
			case "reflect", "unsafe", "C", "net/http/httptest", "text/template", "text/template/parse", "html/template/parse":
				bad(imp, "imports %s", path)
			}
			if ownsType && (imp.Name != nil || strings.Contains(strings.Split(path, "/")[0], ".")) {
				bad(imp, "a file declaring secret or a secret method imports %s other than as the standard library names it", path)
			}
		}
		for _, d := range f.Decls {
			fn, own := "declaration", false
			var params []string
			if fd, ok := d.(*ast.FuncDecl); ok {
				fn = fd.Name.Name
				for _, fl := range fd.Type.Params.List {
					for _, n := range fl.Names {
						params = append(params, n.Name)
					}
				}
				if fd.Recv != nil {
					if secretRecv(fd) {
						own = true
						methods = append(methods, fn)
						want := map[string]string{"equal": equalBody, "setCookie": cookieBody, "IssueToken": issueBody}[fn]
						if got := text(fd.Body.List); got != want {
							bad(fd, "secret.%s's body is %q, want %q", fn, got, want)
						}
					}
					switch fn {
					case "Header", "Write", "WriteHeader":
						bad(fd, "a type has a %s method, so it can stand in for a response", fn)
					}
				}
			}
			var stack []ast.Node
			parent := func(i int) ast.Node {
				if len(stack) < i {
					return nil
				}
				return stack[len(stack)-i]
			}
			ast.Inspect(d, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return true
				}
				if ts, ok := n.(*ast.TypeSpec); ok && ts.Name.Name == "secret" {
					return false
				}
				if id, ok := n.(*ast.Ident); ok {
					if id.Name == "secretSum" && !own {
						bad(n, "%s reads a secret's bytes", fn)
					}
					if fn == "headers" && len(params) == 1 && id.Name == params[0] {
						if _, decl := parent(1).(*ast.Field); !decl {
							sel, _ := parent(1).(*ast.SelectorExpr)
							call, _ := parent(2).(*ast.CallExpr)
							if sel == nil || sel.X != id || sel.Sel.Name != "Set" || call == nil || call.Fun != sel {
								bad(n, "headers uses its header map other than to Set")
							}
						}
					}
				}
				if sel, ok := n.(*ast.SelectorExpr); ok {
					call, _ := parent(1).(*ast.CallExpr)
					called := call != nil && call.Fun == sel
					switch sel.Sel.Name {
					case "IssueToken":
						bad(n, "%s names IssueToken; only a template may call it", fn)
					case "setCookie":
						setCookies++
						if !called || fn != "mint" {
							bad(n, "%s uses setCookie; only mint calls it", fn)
						}
					case "Header":
						if x, ok := sel.X.(*ast.Ident); ok && x.Name == "http" {
							if _, field := parent(1).(*ast.Field); !field || fn != "headers" {
								bad(n, "%s names http.Header; only headers' parameter has that type", fn)
							}
							break
						}
						up, _ := parent(1).(*ast.SelectorExpr)
						if called && len(call.Args) == 0 {
							set, _ := parent(2).(*ast.SelectorExpr)
							setCall, _ := parent(3).(*ast.CallExpr)
							hdrs, _ := parent(2).(*ast.CallExpr)
							viaSet := set != nil && set.Sel.Name == "Set" && setCall != nil && setCall.Fun == set
							viaHeaders := hdrs != nil && len(hdrs.Args) == 1 && hdrs.Args[0] == call && text(hdrs.Fun) == "headers"
							if !viaSet && !viaHeaders {
								bad(n, "%s reads a response's headers", fn)
							}
						} else if up == nil || up.X != sel || up.Sel.Name != "Get" {
							bad(n, "%s uses a header map other than r.Header.Get", fn)
						}
					case "Tree", "Parse", "ParseFiles", "ParseGlob", "AddParseTree":
						bad(n, "%s uses template %s; templates come only from the embedded files", fn, sel.Sel.Name)
					case "ParseFS":
						parses++
						if !called || len(call.Args) != 2 || text(call.Args[0])+", "+text(call.Args[1]) != `files, "templates/*.html"` {
							bad(n, "%s parses templates other than ParseFS(files, \"templates/*.html\")", fn)
						}
					case "Execute", "ExecuteTemplate":
						execs++
						if !called || fn != "render" || !onlyToResponse(d.(*ast.FuncDecl), call, text) {
							bad(n, "%s executes a template other than render's into its response", fn)
						}
					}
				}
				stack = append(stack, n)
				return true
			})
		}
	}
	slices.Sort(methods)
	if got, want := strings.Join(methods, ","), "IssueToken,equal,setCookie"; got != want {
		out = append(out, fmt.Sprintf("secret's methods are %s, want %s", got, want))
	}
	for what, n := range map[string]int{"type secret": typed, "setCookie call": setCookies, "ParseFS call": parses, "template execution": execs} {
		if n != 1 {
			out = append(out, fmt.Sprintf("%d of %s, want 1", n, what))
		}
	}
	for name, b := range tmpls {
		if strings.Count(b, "Token") != 2*strings.Count(b, tokenAction) {
			out = append(out, fmt.Sprintf("%s names Token other than as %s", name, tokenAction))
		}
	}
	out = append(out, writerProblems(fset, files)...)
	slices.Sort(out)
	return out
}

// secretRecv is whether fd is a method of secret.
func secretRecv(fd *ast.FuncDecl) bool {
	if fd.Recv == nil {
		return false
	}
	rt := fd.Recv.List[0].Type
	if st, ok := rt.(*ast.StarExpr); ok {
		rt = st.X
	}
	id, ok := rt.(*ast.Ident)
	return ok && id.Name == "secret"
}

// srcImporter type-checks the package's imports from source, once.
var srcImporter = sync.OnceValue(func() types.Importer { return importer.ForCompiler(token.NewFileSet(), "source", nil) })

// writerProblems checks, with the files type-checked, that every response
// writer the package touches is one net/http handed a handler (#4685 route
// 2 and 3): no expression of a concrete type implementing
// http.ResponseWriter (a declared or promoted method set, of this package's
// type or another's), and every expression of type http.ResponseWriter is a
// function's own parameter. So mint, render and every handler write onto,
// and set the cookie on, only the writer they were called with, which
// traces back to ServeHTTP's. Type errors are problems too.
func writerProblems(fset *token.FileSet, files []*ast.File) []string {
	var out []string
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: srcImporter(), Error: func(err error) { out = append(out, "type check: "+err.Error()) }}
	pkg, _ := conf.Check("github.com/ghbmrk/agentos/broker/enforcer/page", fset, files, info)
	var rw types.Type
	for _, imp := range pkg.Imports() {
		if imp.Path() == "net/http" {
			rw = imp.Scope().Lookup("ResponseWriter").Type()
		}
	}
	if rw == nil {
		return append(out, "the package does not import net/http")
	}
	iface := rw.Underlying().(*types.Interface)
	params := map[types.Object]bool{}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			if ft, ok := n.(*ast.FuncType); ok && ft.Params != nil {
				for _, fl := range ft.Params.List {
					for _, id := range fl.Names {
						params[info.Defs[id]] = true
					}
				}
			}
			return true
		})
	}
	for e, tv := range info.Types {
		if tv.IsType() || tv.Type == nil {
			continue
		}
		at := fset.Position(e.Pos()).String()
		if _, isIface := tv.Type.Underlying().(*types.Interface); !isIface && types.Implements(tv.Type, iface) {
			out = append(out, fmt.Sprintf("%s: %s is a %s, which can stand in for a response", at, types.ExprString(e), tv.Type))
		}
		if types.Identical(tv.Type, rw) {
			id, ok := e.(*ast.Ident)
			if !ok || !params[info.Uses[id]] {
				out = append(out, fmt.Sprintf("%s: %s is a response writer other than a function's own parameter", at, types.ExprString(e)))
			}
		}
	}
	return out
}

// onlyToResponse is whether exec, in fd, writes into a local buffer b that
// fd uses otherwise only as w.Write([]byte(b.String())), w being fd's
// first parameter.
func onlyToResponse(fd *ast.FuncDecl, exec *ast.CallExpr, text func(any) string) bool {
	if len(exec.Args) == 0 || len(fd.Type.Params.List) == 0 || len(fd.Type.Params.List[0].Names) == 0 {
		return false
	}
	amp, ok := exec.Args[0].(*ast.UnaryExpr)
	if !ok || amp.Op != token.AND {
		return false
	}
	b, ok := amp.X.(*ast.Ident)
	if !ok {
		return false
	}
	w := fd.Type.Params.List[0].Names[0].Name
	want := w + ".Write([]byte(" + b.Name + ".String()))"
	declared, written, ok := 0, 0, true
	var stack []ast.Node
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if id, isID := n.(*ast.Ident); isID && id.Name == b.Name {
			at := func(i int) ast.Node {
				if len(stack) < i {
					return nil
				}
				return stack[len(stack)-i]
			}
			switch {
			case id == b:
			case at(1) != nil && func() bool {
				vs, v := at(1).(*ast.ValueSpec)
				return v && len(vs.Values) == 0 && text(vs.Type) == "strings.Builder"
			}():
				declared++
			case at(4) != nil && text(at(4)) == want:
				written++
			default:
				ok = false
			}
		}
		stack = append(stack, n)
		return true
	})
	return ok && declared == 1 && written == 1
}

// #4685 route 1: fmt prints no byte of a secret held in any way, under any
// verb: as a value, through an unexported value or pointer field, through
// a pointer to a pointer, in a slice or map, or wrapped in an error under
// %w. A revert of secret's field to []byte fails here.
func TestFmtPrintsNoSecretInAnyHolder(t *testing.T) {
	canary := []byte("\x01\x02canary")
	x := newSecret(canary)
	type hidden struct{ v secret }
	type hiddenPtr struct{ p *secret }
	type shown struct{ V secret }
	holders := []any{x, &x, hidden{x}, &hidden{x}, hiddenPtr{&x}, shown{x}, []secret{x}, map[string]secret{"k": x},
		struct{ h hidden }{hidden{x}}, new(&x), []any{x}}
	verbs := []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%o", "%b", "%c", "%U", "%p", "%T", "%e", "%t"}
	forms := []string{"canary", "63616e617279", "63616E617279", "99 97 110", "[1 2", `\x01`, "\x01\x02", "Y2FuYXJ5", "AQJjYW5hcnk"}
	if out := fmt.Sprintf("%x", struct{ v []byte }{canary}); !strings.Contains(out, forms[1]) {
		t.Fatalf("the check misses bytes behind an unexported field: %s", out)
	}
	for _, h := range holders {
		var outs []string
		for _, v := range verbs {
			outs = append(outs, fmt.Sprintf(v, h))
		}
		outs = append(outs, fmt.Sprint(h), fmt.Sprintln(h), fmt.Errorf("e: %w", leakErr{h}).Error(), fmt.Sprintf("%v", fmt.Errorf("%w", leakErr{h})))
		for _, o := range outs {
			for _, f := range forms {
				if strings.Contains(o, f) {
					t.Errorf("fmt of %T prints %q: %s", h, f, o)
				}
			}
		}
	}
}

// leakErr is an error that holds a secret in an unexported field.
type leakErr struct{ v any }

func (leakErr) Error() string { return "leak" }

// teeFile starts an added file with a response wrapper that declares no
// method: http.ResponseWriter's are promoted from inner, Write from the
// buffer embedded beside it.
const teeFile = `import (
	"bytes"
	"net/http"
	"strings"
)

var _ = bytes.MinRead

type inner struct{ http.ResponseWriter }

type tee struct {
	*strings.Builder
	inner
}

`

// #4685: exitProblems refuses each route it closes. Each case edits one
// of the package's files, adds a file, or adds a template, and must yield
// a problem containing want.
func TestExitCheckCatchesEachRoute(t *testing.T) {
	type swap struct{ file, old, new string }
	for _, c := range []struct {
		name string
		swap swap
		add  string // a Go file's body after its package clause
		tmpl string
		want string
	}{
		// Route 1's shape: the field back to bytes.
		{name: "slice field", swap: swap{"csrf.go", "secretSum func() []byte }", "secretSum []byte }"}, want: "secret is struct{ secretSum []byte }"},
		{name: "fourth method", add: "func (secret) String() string { return \"\" }", want: "secret's methods are"},
		// Route 2: the cookie's value reaching Go code.
		{name: "setCookie outside mint", add: "func leak(s *Server, w http.ResponseWriter) { s.tag(nil).setCookie(w, nil) }", want: "leak uses setCookie"},
		{name: "setCookie method value", add: "func leak(s *Server) any { return s.tag(nil).setCookie }", want: "leak uses setCookie"},
		{name: "Set-Cookie read back", add: `func leak(w http.ResponseWriter) bool { return w.Header().Get("Set-Cookie") != "" }`, want: "leak reads a response's headers"},
		{name: "header map held", add: "func leak(w http.ResponseWriter) any { h := w.Header(); return h }", want: "leak reads a response's headers"},
		{name: "header method value", add: "func leak(w http.ResponseWriter) any { return w.Header }", want: "leak uses a header map"},
		{name: "http.Header elsewhere", add: "func leak(h http.Header) {}", want: "leak names http.Header"},
		{name: "headers reads", swap: swap{"server.go", `h.Set("X-Frame-Options", "DENY")`, `_ = h.Get("Set-Cookie")`}, want: "headers uses its header map"},
		{name: "recorder", add: "type rec struct{ h http.Header }\n\nfunc (r *rec) Header() http.Header { return r.h }", want: "a type has a Header method"},
		{name: "tee writer", add: "type tee struct{ http.ResponseWriter }\n\nfunc (tee) Write(b []byte) (int, error) { return len(b), nil }", want: "a type has a Write method"},
		{name: "httptest", add: `import _ "net/http/httptest"`, want: "imports net/http/httptest"},
		// Route 3: the token reaching Go code.
		{name: "Go call", add: "func leak(x secret) string { return x.IssueToken() }", want: "leak names IssueToken"},
		{name: "interface call", add: "func leak(x any) string { return x.(interface{ IssueToken() string }).IssueToken() }", want: "leak names IssueToken"},
		{name: "Go-string template", add: `func leak(s *Server) { s.tmpl.New("x").Parse("{{.IssueToken}}") }`, want: "leak uses template Parse"},
		{name: "second ParseFS", add: `func leak(s *Server) { s.tmpl.ParseFS(files, "static/*") }`, want: "leak parses templates"},
		{name: "tree surgery", add: "func leak(s *Server) any { return s.tmpl.Tree }", want: "leak uses template Tree"},
		{name: "text/template", add: `import _ "text/template"`, want: "imports text/template"},
		{name: "second execution", add: `func leak(s *Server, b *strings.Builder, d any) { s.tmpl.ExecuteTemplate(b, "home.html", d) }`, want: "leak executes a template"},
		{name: "rendered page read", swap: swap{"home.go", "w.Write([]byte(b.String()))", `w.Write([]byte(b.String())); _ = strings.Contains(b.String(), "x")`}, want: "render executes a template"},
		{name: "template range", tmpl: `{{range $k, $v := .}}{{$v.IssueToken}}{{end}}`, want: "names Token other than"},
		{name: "template printf", tmpl: `{{printf "%s" .Token.IssueToken}}`, want: "names Token other than"},
		{name: "template func", tmpl: `{{when .Token}}`, want: "names Token other than"},
		// Route 2 and 3 through a stand-in response (Security on #4731).
		{name: "promoted tee", add: teeFile + `func leak(s *Server, w http.ResponseWriter, r *http.Request) string {
	var b strings.Builder
	s.render(tee{&b, inner{w}}, r, "enrol.html", map[string]any{})
	return b.String()
}`, want: "which can stand in for a response"},
		{name: "buffer tee", add: teeFile + `type btee struct {
	*bytes.Buffer
	inner
}

func leak(s *Server, w http.ResponseWriter, r *http.Request) string {
	b := new(bytes.Buffer)
	s.mint(btee{b, inner{w}})
	return b.String()
}`, want: "which can stand in for a response"},
		{name: "ServeHTTP tee", add: teeFile + `func leak(s *Server, w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	s.ServeHTTP(tee{&b, inner{w}}, r)
}`, want: "which can stand in for a response"},
		{name: "foreign recorder", add: `import (
	"net/http"
	"net/http/httptest"
)

func leak(s *Server, r *http.Request) string {
	w := httptest.NewRecorder()
	s.render(w, r, "home.html", map[string]any{})
	return w.Body.String()
}`, want: "*net/http/httptest.ResponseRecorder, which can stand in"},
		{name: "writer from a call", add: `import "net/http"

func leak(s *Server, r *http.Request, mk func() http.ResponseWriter) {
	s.render(mk(), r, "home.html", map[string]any{})
}`, want: "mk() is a response writer other than"},
		{name: "writer in a field", add: `import "net/http"

type holder struct{ w http.ResponseWriter }

func leak(h holder, s *Server, r *http.Request) { s.render(h.w, r, "home.html", map[string]any{}) }`, want: "h.w is a response writer other than"},
		// #4685 items 4 and 5.
		{name: "equal moved", swap: swap{"csrf.go", "func (x secret) equal(b []byte) bool {\n\treturn x.secretSum != nil && len(x.secretSum()) == sha256.Size && hmac.Equal(x.secretSum(), b)\n}", ""},
			add:  "import (\n\thmac \"bytes\"\n\t\"crypto/sha256\"\n)\n\nfunc (x secret) equal(b []byte) bool {\n\treturn x.secretSum != nil && len(x.secretSum()) == sha256.Size && hmac.Equal(x.secretSum(), b)\n}",
			want: "a file declaring secret or a secret method imports bytes other than"},
		{name: "hmac alias", swap: swap{"csrf.go", `"crypto/hmac"`, `hmac "bytes"`}, want: "imports bytes other than"},
		{name: "foreign hmac", swap: swap{"csrf.go", `"crypto/hmac"`, `"github.com/ghbmrk/agentos/broker/hmac"`}, want: "imports github.com/ghbmrk/agentos/broker/hmac other than"},
		{name: "grouped spec", swap: swap{"csrf.go", "type secret struct{ secretSum func() []byte }", "type (\n\tsecret struct{ secretSum func() []byte }\n\tleak   [len(secret{}.secretSum())]byte\n)"}, want: "declaration reads a secret's bytes"},
	} {
		t.Run(c.name, func(t *testing.T) {
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
				b, err := os.ReadFile(n)
				if err != nil {
					t.Fatal(err)
				}
				src := string(b)
				if n == c.swap.file {
					if !strings.Contains(src, c.swap.old) {
						t.Fatalf("%s has no %q", n, c.swap.old)
					}
					src = strings.Replace(src, c.swap.old, c.swap.new, 1)
				}
				f, err := parser.ParseFile(fset, n, src, parser.ParseComments)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, f)
			}
			if c.add != "" {
				f, err := parser.ParseFile(fset, "zz_added.go", "package page\n\n"+c.add+"\n", 0)
				if err != nil {
					t.Fatal(err)
				}
				files = append(files, f)
			}
			_, _, tmpls := ownSource(t)
			if c.tmpl != "" {
				tmpls["templates/zz_added.html"] = c.tmpl
			}
			got := exitProblems(fset, files, tmpls)
			if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
				t.Errorf("no problem contains %q; got %q", c.want, got)
			}
		})
	}
}

// A zero secret equals nothing, not even an empty header token.
func TestZeroSecretEqualsNothing(t *testing.T) {
	for _, b := range [][]byte{nil, {}, make([]byte, 32)} {
		if (secret{}).equal(b) {
			t.Errorf("zero secret equals %d bytes", len(b))
		}
	}
}
