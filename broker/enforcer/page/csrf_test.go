package page

// REQ: CH-9

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/action"
	"github.com/ghbmrk/agentos/broker/enforcer/page/internal/csrf"
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
		"home.html":    {g.rig, "/"},
		"enrol.html":   {g.rig, "/enrol"},
		"confirm.html": {pg, linkFor(next, "add new.example")},
	}
	// The list is the code's own (#4784): every screen render draws, and
	// every top-level template, is one here or the action screen below.
	drawn := renderedScreens(t)
	if want := append(keys(screens), "action.html"); !sameSet(drawn, want) || !sameSet(topLevel(t), want) {
		t.Fatalf("render draws %v and the top-level templates are %v; this test opens %v: add the new screen here", drawn, topLevel(t), want)
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
	checkCookie(t, "action.html", w)

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

	// The cookie's own refusals (length, tag, time) are package csrf's
	// TestKeepRefusesCookiesItCannotVouchFor; here another page's cookie
	// and one that is not base64.
	other := fullRig(t)
	other.screen()
	mints("another page's cookie", "same-origin", other.cookie)
	mints("not base64", "same-origin", "!!!!")

	// Expired: kept up to csrf.ReuseFor after it was drawn, not after.
	g.now = g.now.Add(csrf.ReuseFor)
	if set, tok := g.navigate("/", "same-origin", first); set != "" || tok != firstTok {
		t.Errorf("at csrf.ReuseFor: set %q", set)
	}
	g.now = g.now.Add(time.Millisecond)
	mints("expired", "same-origin", first)
	// Drawn in the future (the clock went back): not kept.
	g.now = g.now.Add(-csrf.ReuseFor - time.Hour)
	mints("drawn in the future", "same-origin", first)
}

// CH-9 (#4427): a pair passes guard for csrf.PairLife after its cookie was
// drawn and not after, whether its screen minted it or kept it, and a
// cookie the clock says was drawn in the future is refused. A screen that
// keeps a cookie at ReuseFor still has PairLife-ReuseFor to be tapped.
// Revert mutants: guard ignoring the age, ignoring the future, or
// comparing with >= PairLife, each fail here.
func TestPairLifetime(t *testing.T) {
	if csrf.ReuseFor <= 0 || csrf.PairLife-csrf.ReuseFor < csrf.ReuseFor {
		t.Fatalf("csrf.ReuseFor %v leaves a kept screen less than %v", csrf.ReuseFor, csrf.PairLife-csrf.ReuseFor)
	}
	g := fullRig(t)
	g.screen()
	c, tok := g.cookie, g.token
	start := g.now
	passes := func() bool {
		t.Helper()
		return !g.forged(g.s, http.MethodPost, "/approve", c, tok)
	}
	g.now = start.Add(csrf.ReuseFor)
	if set, kept := g.navigate("/", "same-origin", c); set != "" || kept != tok {
		t.Fatalf("at csrf.ReuseFor the screen did not keep the pair")
	}
	g.now = start.Add(csrf.PairLife)
	if !passes() {
		t.Error("a pair is refused at csrf.PairLife")
	}
	g.now = start.Add(csrf.PairLife + time.Millisecond)
	if passes() {
		t.Error("a pair passes past csrf.PairLife")
	}
	g.now = start.Add(-time.Millisecond)
	if passes() {
		t.Error("a pair whose cookie was drawn in the future passes")
	}
}

// #4778 R1: csrf.Screen writes every screen's opening (doctype, html,
// head, charset and the token's meta), so no template writes any of it:
// a second opening could carry another enforcer-token meta, or one the
// script reads first. Revert mutant: home.html reopening the document.
func TestTemplatesLeaveTheOpeningToCSRF(t *testing.T) {
	names, err := fs.Glob(files, "templates/*.html")
	if err != nil || len(names) == 0 {
		t.Fatalf("templates: %v %v", names, err)
	}
	for _, n := range names {
		b, err := fs.ReadFile(files, n)
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(b))
		for _, bad := range []string{"<!doctype", "<html", "<head", "charset", "enforcer-token"} {
			if strings.Contains(low, bad) {
				t.Errorf("%s writes %q, which csrf.Screen's opening owns", n, bad)
			}
		}
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// topLevel is every embedded template that is a screen: every file under
// templates/ that is not only a {{define}} of a partial.
func topLevel(t *testing.T) []string {
	t.Helper()
	names, err := fs.Glob(files, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var top []string
	for _, n := range names {
		b, err := fs.ReadFile(files, n)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(strings.TrimSpace(string(b)), "{{define") {
			top = append(top, path.Base(n))
		}
	}
	return top
}

// renderedScreens type-checks the package's non-test Go files and returns
// the template name of every call of (*Server).render, resolved through
// go/types. It fails the test if a name is not a constant string, if
// html/template's or text/template's Execute or ExecuteTemplate is used (called, or taken as
// a method value) anywhere but inside render, or if render is used other
// than by a call (#4784): so every screen is drawn by render, which hands
// it to csrf.Screen. It also fails the test if the page uses net/http's
// file API (Dir, FileServer, ServeFile, ...), which opens files by name.
func renderedScreens(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("parse: %v (%d packages)", err, len(pkgs))
	}
	var fl []*ast.File
	for _, p := range pkgs {
		for _, f := range p.Files {
			fl = append(fl, f)
		}
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Uses: map[*ast.Ident]types.Object{}, Defs: map[*ast.Ident]types.Object{}}
	// Imports come from the build's own export data (go list -export), so
	// nothing is type-checked from source (#4770).
	out, err := exec.Command("go", "list", "-export", "-deps", "-f", "{{.ImportPath}} {{.Export}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	export := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if p, f, ok := strings.Cut(l, " "); ok && f != "" {
			export[p] = f
		}
	}
	lookup := func(p string) (io.ReadCloser, error) {
		f, ok := export[p]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", p)
		}
		return os.Open(f)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "gc", lookup)}
	if _, err := conf.Check("github.com/ghbmrk/agentos/broker/enforcer/page", fset, fl, info); err != nil {
		t.Fatal(err)
	}
	var render types.Object
	for id, o := range info.Defs {
		if fn, ok := o.(*types.Func); ok && id.Name == "render" {
			if r := fn.Signature().Recv(); r != nil && types.TypeString(r.Type(), nil) == "*github.com/ghbmrk/agentos/broker/enforcer/page.Server" {
				render = fn
			}
		}
	}
	if render == nil {
		t.Fatal("no (*Server).render")
	}
	exec := func(o types.Object) bool {
		fn, ok := o.(*types.Func)
		return ok && fn.Pkg() != nil && (fn.Pkg().Path() == "html/template" || fn.Pkg().Path() == "text/template") && (fn.Name() == "Execute" || fn.Name() == "ExecuteTemplate")
	}
	// The page opens no file by name: with net/http's file API it could
	// seek /proc/self/mem, and the import allowlist (ARC2's
	// enforcerWebImports) already keeps os and syscall out.
	fileAPI := func(o types.Object) bool {
		return o.Pkg() != nil && o.Pkg().Path() == "net/http" && slices.Contains([]string{
			"Dir", "FS", "FileServer", "FileServerFS", "ServeFile", "ServeFileFS", "NewFileTransport", "NewFileTransportFS"}, o.Name())
	}
	var names []string
	for _, f := range fl {
		var inRender []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if fd, ok := n.(*ast.FuncDecl); ok && info.Defs[fd.Name] == render {
				inRender = append(inRender, fd)
			}
			return true
		})
		inside := func(p token.Pos) bool {
			for _, n := range inRender {
				if n.Pos() <= p && p < n.End() {
					return true
				}
			}
			return false
		}
		calls := map[*ast.Ident]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := c.Fun.(*ast.SelectorExpr); ok && info.Uses[sel.Sel] == render {
				calls[sel.Sel] = true
				if len(c.Args) != 4 {
					t.Errorf("%s: render with %d arguments", fset.Position(c.Pos()), len(c.Args))
					return true
				}
				v := info.Types[c.Args[2]].Value
				if v == nil || v.Kind() != constant.String {
					t.Errorf("%s: render's template name is not a constant", fset.Position(c.Pos()))
					return true
				}
				names = append(names, constant.StringVal(v))
			}
			return true
		})
		for id, o := range info.Uses {
			if fset.File(id.Pos()) != fset.File(f.Pos()) {
				continue
			}
			if o == render && !calls[id] {
				t.Errorf("%s: render is used other than by a call", fset.Position(id.Pos()))
			}
			if exec(o) && !inside(id.Pos()) {
				t.Errorf("%s: a template is executed outside render", fset.Position(id.Pos()))
			}
			if fileAPI(o) {
				t.Errorf("%s: the page uses net/http's %s, which opens files by name (#4778)", fset.Position(id.Pos()), o.Name())
			}
		}
	}
	return names
}
