package page

// REQ: CH-9

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

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
