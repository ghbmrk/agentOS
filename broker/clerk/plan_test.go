package clerk_test

// REQ: CLK-1, CLK-3, CLK-4, CLK-7, PLN-5

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
)

// planFix is a plan login clerk over a fake provider under example.com. The
// provider's tokens are synthetic: real-access-N and real-refresh-N, the Nth
// login it issued, for account acct.
type planFix struct {
	srv   *httptest.Server
	roots *x509.CertPool
	seal  clerk.Sealer
	sec   *clerk.Secrets
	host  string

	mu      sync.Mutex
	n       int    // logins issued
	acct    string // the account the next answer names
	refresh string // the live refresh token
	seen    []*http.Request
	bodies  []string
	// answer, if set, answers /oauth/token instead of the fake's own.
	answer    func(w http.ResponseWriter, r *http.Request, body string) bool
	exchanges atomic.Int32
	gate      chan struct{} // if set, a refresh waits on it
}

func jwt(claims any) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]string{"alg": "RS256"}) + "." + enc(claims) + ".sig"
}

func idToken(acct string) string {
	return jwt(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": acct}, "email": "owner@example.invalid"})
}

func newPlanFix(t *testing.T) *planFix {
	t.Helper()
	f := &planFix{acct: "acct-1"}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.srv.Certificate())
	f.seal = sealer(t)
	f.sec = clerk.NewSecrets(f.seal, nil)
	f.host = "example.com:" + f.srv.URL[strings.LastIndex(f.srv.URL, ":")+1:]
	return f
}

func (f *planFix) tokens() map[string]any {
	f.n++
	acc, ref := "real-access-"+string(rune('0'+f.n)), "real-refresh-"+string(rune('0'+f.n))
	f.refresh = ref
	return map[string]any{"access_token": acc, "refresh_token": ref, "id_token": idToken(f.acct), "expires_in": 3600, "token_type": "Bearer"}
}

func (f *planFix) serve(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, r.Clone(context.Background()))
	f.bodies = append(f.bodies, string(b))
	f.mu.Unlock()
	switch r.URL.Path {
	case "/api/accounts/deviceauth/usercode":
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device_auth_id":"dev-1","user_code":"ABCD-1234"}`))
	case "/oauth/token":
		f.exchanges.Add(1)
		if f.gate != nil {
			<-f.gate
		}
		if f.answer != nil && f.answer(w, r, string(b)) {
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			var m map[string]string
			json.Unmarshal(b, &m)
			if m["refresh_token"] != f.refresh {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.tokens())
	case "/backend-api/codex/responses", "/backend-api/codex/models":
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Codex-Primary-Used-Percent", "12")
		w.Header().Set("Set-Cookie", "session=s")
		w.Write([]byte("data: ok\n\n"))
	default:
		w.WriteHeader(404)
	}
}

// last is the last request the provider saw, and its body.
func (f *planFix) last() (*http.Request, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.seen) == 0 {
		return nil, ""
	}
	return f.seen[len(f.seen)-1], f.bodies[len(f.bodies)-1]
}

func (f *planFix) hits() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

func (f *planFix) decl(t *testing.T) clerk.PlanDeclaration {
	d := clerk.CodexPlan((&exitFix{srv: f.srv}).guard(netip.MustParseAddr("8.8.8.8")))
	for i := range d.Endpoints {
		d.Endpoints[i].Host = f.host
	}
	return d
}

func (f *planFix) login(t *testing.T) *clerk.PlanLogin {
	t.Helper()
	p, err := clerk.NewPlanLogin(f.decl(t), f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func req(method, path, body string, h map[string]string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:18432"+path, strings.NewReader(body))
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return r
}

func read(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// codeForm is the CLI's code exchange, with its local callback.
func codeForm() string {
	return url.Values{"client_id": {"app_x"}, "code": {"ac_1"}, "code_verifier": {"v1"}, "grant_type": {"authorization_code"},
		"redirect_uri": {"http://127.0.0.1:18432/deviceauth/callback"}}.Encode()
}

// signIn runs the owner's sign-in in guest and returns what the guest got.
func signIn(t *testing.T, p *clerk.PlanLogin, guest string) map[string]any {
	t.Helper()
	if err := p.BeginSignIn(guest); err != nil {
		t.Fatal(err)
	}
	resp, d := p.Do(context.Background(), guest, req("POST", "/oauth/token", codeForm(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}))
	if d != "" {
		t.Fatalf("code exchange: %s", d)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(read(t, resp)), &got); err != nil {
		t.Fatal(err)
	}
	if !p.SignedIn(guest) {
		t.Fatal("the sign-in guest's commit is not recorded")
	}
	return got
}

func model(p *clerk.PlanLogin, guest, bearer string) (*http.Response, string) {
	h := map[string]string{"Content-Type": "application/json", "Cookie": "c=1", "X-Forwarded-For": "1.2.3.4"}
	if bearer != "" {
		h["Authorization"] = "Bearer " + bearer
	}
	return p.Do(context.Background(), guest, req("POST", "/backend-api/codex/responses", `{"model":"m"}`, h))
}

func refreshBody(ph string) string {
	return `{"client_id":"app_x","grant_type":"refresh_token","refresh_token":"` + ph + `"}`
}

func refreshReq(p *clerk.PlanLogin, guest, ph string) (*http.Response, string) {
	return p.Do(context.Background(), guest, req("POST", "/oauth/token", refreshBody(ph), map[string]string{"Content-Type": "application/json"}))
}

func noReal(t *testing.T, what, s string) {
	t.Helper()
	if strings.Contains(s, "real-") {
		t.Fatalf("%s carries a real token: %s", what, s)
	}
}

// A guest's token set and every answer it gets hold placeholders only; its
// id_token carries the account and no other claim of the provider's.
func TestPlanGuestHoldsOnlyPlaceholders(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if _, err := p.Guest("g1"); !errors.Is(err, clerk.ErrNoPlanLogin) {
		t.Fatalf("Guest before a sign-in = %v", err)
	}
	got := signIn(t, p, "signin")
	b, _ := json.Marshal(got)
	noReal(t, "the sign-in answer", string(b))
	if got["expires_in"] == nil || got["token_type"] != "Bearer" {
		t.Fatalf("declared plain fields were not passed: %v", got)
	}
	tok, err := p.Guest("g1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ = json.Marshal(tok)
	noReal(t, "the guest's token set", string(b))
	if tok.Account != "acct-1" || len(tok.Tokens) != 3 {
		t.Fatalf("token set = %+v", tok)
	}
	parts := strings.Split(tok.Tokens["id_token"], ".")
	claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if !strings.Contains(string(claims), `"chatgpt_account_id":"acct-1"`) || strings.Contains(string(claims), "email") {
		t.Fatalf("placeholder id_token claims = %s", claims)
	}
	again, _ := p.Guest("g1")
	other, _ := p.Guest("g2")
	if again.Tokens["access_token"] != tok.Tokens["access_token"] || other.Tokens["access_token"] == tok.Tokens["access_token"] {
		t.Fatal("placeholders are not stable per guest and distinct across guests")
	}
	if _, err := p.Guest("signin"); err == nil {
		t.Fatal("a sign-in guest got a run guest's token set")
	}
}

// The real token goes only into a declared request of the guest that holds
// the placeholder, with only the declared headers; anything else is refused
// before a byte leaves.
func TestPlanInjectsOnlyAtDeclaredEndpoints(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g1, _ := p.Guest("g1")
	g2, _ := p.Guest("g2")
	resp, d := model(p, "g1", g1.Tokens["access_token"])
	if d != "" {
		t.Fatalf("model call: %s", d)
	}
	read(t, resp)
	up, body := f.last()
	if up.Header.Get("Authorization") != "Bearer real-access-1" || body != `{"model":"m"}` || up.Host != f.host {
		t.Fatalf("upstream got %q %q %q", up.Header.Get("Authorization"), body, up.Host)
	}
	if up.Header.Get("Cookie") != "" || up.Header.Get("X-Forwarded-For") != "" {
		t.Fatal("an undeclared header passed")
	}
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Codex-Primary-Used-Percent") != "12" {
		t.Fatalf("answer headers = %v", resp.Header)
	}
	q := httptest.NewRequest("GET", "http://x/backend-api/codex/models?client_version=0.162.1", nil)
	q.Header.Set("Authorization", "Bearer "+g1.Tokens["access_token"])
	if resp, d := p.Do(context.Background(), "g1", q); d != "" {
		t.Fatalf("read: %s", d)
	} else {
		read(t, resp)
	}
	before := f.hits()
	for name, c := range map[string]func() (*http.Response, string){
		"undeclared path": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/backend-api/files", "{}", map[string]string{"Authorization": "Bearer " + g1.Tokens["access_token"]}))
		},
		"another guest's placeholder": func() (*http.Response, string) { return model(p, "g1", g2.Tokens["access_token"]) },
		"the refresh placeholder":     func() (*http.Response, string) { return model(p, "g1", g1.Tokens["refresh_token"]) },
		"no bearer":                   func() (*http.Response, string) { return model(p, "g1", "") },
		"the real token itself":       func() (*http.Response, string) { return model(p, "g1", "real-access-1") },
		"a sign-in step from a run guest": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`, map[string]string{"Content-Type": "application/json"}))
		},
		"an undeclared query": func() (*http.Response, string) {
			r := httptest.NewRequest("GET", "http://x/backend-api/codex/models?client_version=1&x=2", nil)
			r.Header.Set("Authorization", "Bearer "+g1.Tokens["access_token"])
			return p.Do(context.Background(), "g1", r)
		},
		"a read with a body": func() (*http.Response, string) {
			r := httptest.NewRequest("GET", "http://x/backend-api/codex/models", strings.NewReader("x"))
			r.Header.Set("Authorization", "Bearer "+g1.Tokens["access_token"])
			return p.Do(context.Background(), "g1", r)
		},
		"an encoded body": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/backend-api/codex/responses", "x", map[string]string{"Authorization": "Bearer " + g1.Tokens["access_token"], "Content-Encoding": "gzip"}))
		},
	} {
		if resp, d := c(); resp != nil || d == "" {
			t.Errorf("%s was served", name)
		}
	}
	if f.hits() != before {
		t.Fatalf("a refused request reached the provider (%d requests)", f.hits()-before)
	}
	p.Forget("g1")
	if resp, _ := model(p, "g1", g1.Tokens["access_token"]); resp != nil {
		t.Fatal("a forgotten guest's placeholder still resolves")
	}
}

// A provider that echoes the injected token gets it redacted, in a header
// and in the body, however the body is chunked.
func TestPlanRedactsTheInjectedToken(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	// A second server echoes the token split over two flushed writes.
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("X-Request-Id", "id-"+tok)
		w.WriteHeader(200)
		w.Write([]byte("a " + tok[:5]))
		w.(http.Flusher).Flush()
		time.Sleep(20 * time.Millisecond)
		w.Write([]byte(tok[5:] + " b " + tok))
	})
	resp, d := model(p, "g", g.Tokens["access_token"])
	if d != "" {
		t.Fatal(d)
	}
	body := read(t, resp)
	if body != "a [redacted] b [redacted]" || resp.Header.Get("X-Request-Id") != "id-[redacted]" {
		t.Fatalf("answer = %q, header %q", body, resp.Header.Get("X-Request-Id"))
	}
	// An encoded answer, which redaction cannot read, is refused.
	f.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte("x"))
	})
	if resp, d := model(p, "g", g.Tokens["access_token"]); resp != nil || d != clerk.DPlanEncoded {
		t.Fatalf("an encoded answer = %q", d)
	}
}

// A refresh goes out with the real refresh token; the new login is sealed
// before the answer is released, and the guest gets its own placeholders.
func TestPlanRefreshSwapsBackToPlaceholders(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
	if d != "" {
		t.Fatalf("refresh: %s", d)
	}
	up, body := f.last()
	if !strings.Contains(body, `"refresh_token":"real-refresh-1"`) || up.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("refresh sent %q", body)
	}
	out := read(t, resp)
	noReal(t, "the refresh answer", out)
	var got map[string]any
	json.Unmarshal([]byte(out), &got)
	if got["access_token"] != g.Tokens["access_token"] || got["refresh_token"] != g.Tokens["refresh_token"] {
		t.Fatalf("the guest's placeholders changed: %v", got)
	}
	resp, d = model(p, "g", g.Tokens["access_token"])
	if d != "" {
		t.Fatal(d)
	}
	read(t, resp)
	if up, _ := f.last(); up.Header.Get("Authorization") != "Bearer real-access-2" {
		t.Fatalf("the refreshed login was not stored: %q", up.Header.Get("Authorization"))
	}
	// A refresh body out of shape, or with another guest's placeholder, is
	// refused before it leaves.
	h, _ := p.Guest("h")
	before := f.hits()
	for _, b := range []string{
		refreshBody(h.Tokens["refresh_token"]),
		`{"grant_type":"authorization_code","refresh_token":"` + g.Tokens["refresh_token"] + `"}`,
		`{"grant_type":"refresh_token","refresh_token":"` + g.Tokens["refresh_token"] + `","extra":"x"}`,
		`{"grant_type":"refresh_token","refresh_token":"` + g.Tokens["refresh_token"] + `"} {}`,
	} {
		if resp, _ := p.Do(context.Background(), "g", req("POST", "/oauth/token", b, nil)); resp != nil {
			t.Errorf("refresh %s was served", b)
		}
	}
	if f.hits() != before {
		t.Fatal("a refused refresh reached the provider")
	}
}

// Refreshes that arrive together make one exchange of the single-use token,
// and each guest gets the answer in its own placeholders.
func TestPlanRefreshRunsOneFlight(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	f.exchanges.Store(0)
	f.gate = make(chan struct{})
	guests := []string{"a", "b", "c"}
	tok := map[string]clerk.PlanTokens{}
	for _, g := range guests {
		tok[g], _ = p.Guest(g)
	}
	var wg sync.WaitGroup
	got := make([]string, len(guests))
	for i, g := range guests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, d := refreshReq(p, g, tok[g].Tokens["refresh_token"])
			if d != "" {
				got[i] = d
				return
			}
			got[i] = read(t, resp)
		}()
	}
	for f.exchanges.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // the others join the flight
	close(f.gate)
	wg.Wait()
	if n := f.exchanges.Load(); n != 1 {
		t.Fatalf("%d exchanges, want 1", n)
	}
	for i, g := range guests {
		if !strings.Contains(got[i], tok[g].Tokens["access_token"]) {
			t.Fatalf("guest %s got %q", g, got[i])
		}
		noReal(t, "a joined refresh", got[i])
	}
}

// answerWith makes the provider answer the next token request with body.
func (f *planFix) answerWith(status int, body string) {
	f.answer = func(w http.ResponseWriter, r *http.Request, _ string) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
		f.answer = nil
		return true
	}
}

// An answer out of its declared shape is dropped and stops the route, with
// nothing further sent, until a release with a new declaration version; a
// restart keeps the stop and Resume does not lift it.
func TestPlanUnmatchedAnswerStopsUntilRequalified(t *testing.T) {
	for name, body := range map[string]string{
		"undeclared field":  `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + idToken("acct-1") + `","session":"real-s"}`,
		"no account":        `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + jwt(map[string]string{"sub": "x"}) + `"}`,
		"another account":   `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + idToken("acct-2") + `"}`,
		"text out of shape": `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + idToken("acct-1") + `","token_type":"real-access-9"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newPlanFix(t)
			p := f.login(t)
			signIn(t, p, "signin")
			g, _ := p.Guest("g")
			f.answerWith(200, body)
			if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != clerk.DPlanUnswappable {
				t.Fatalf("refresh = %v %q", resp, d)
			}
			if p.Stopped() != clerk.StopUnswappable {
				t.Fatalf("Stopped = %q", p.Stopped())
			}
			before := f.hits()
			if resp, d := model(p, "g", g.Tokens["access_token"]); resp != nil || !strings.HasPrefix(d, clerk.DPlanStopped) {
				t.Fatalf("model call on a stopped route = %q", d)
			}
			if err := p.BeginSignIn("s2"); err == nil {
				t.Fatal("a sign-in started on an unswappable route")
			}
			if f.hits() != before {
				t.Fatal("a stopped route sent a request")
			}
			if err := p.Resume(); !errors.Is(err, clerk.ErrRequalify) {
				t.Fatalf("Resume = %v", err)
			}
			if err := p.Remove(); err != nil || p.Stopped() != clerk.StopUnswappable {
				t.Fatalf("Remove lifted the stop: %v %q", err, p.Stopped())
			}
			// A restart with the same declaration keeps it.
			at, _ := f.sec.MarshalBinary()
			sec := clerk.NewSecrets(f.seal, nil)
			if err := sec.UnmarshalBinary(at); err != nil {
				t.Fatal(err)
			}
			again, err := clerk.NewPlanLogin(f.decl(t), sec, f.roots)
			if err != nil || again.Stopped() != clerk.StopUnswappable {
				t.Fatalf("after a restart Stopped = %q (%v)", again.Stopped(), err)
			}
			d := f.decl(t)
			d.Version = "codex-0.163.0-1"
			next, err := clerk.NewPlanLogin(d, sec, f.roots)
			if err != nil || next.Stopped() != "" {
				t.Fatalf("a new declaration version did not requalify: %q (%v)", next.Stopped(), err)
			}
		})
	}
}

// A declared refused-login answer stops the route until the owner resumes
// it or signs in again; an undeclared 400 or a 500 is dropped and stops
// nothing.
func TestPlanRefusedLoginStopsUntilResumeOrSignIn(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	for _, a := range []struct {
		status int
		body   string
	}{{400, `{"error":"invalid_grant"}`}, {500, `{"error":"server"}`}, {401, `{"error":{"code":"other"}}`}} {
		f.answerWith(a.status, a.body)
		if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || !strings.HasPrefix(d, clerk.DPlanExchange) {
			t.Fatalf("error answer %d = %q", a.status, d)
		}
		if p.Stopped() != "" {
			t.Fatalf("%d %s stopped the route", a.status, a.body)
		}
	}
	f.answerWith(401, `{"error":{"code":"refresh_token_expired","message":"real-refresh-1"}}`)
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d == "" {
		t.Fatal("a refused login was forwarded")
	}
	if p.Stopped() != clerk.StopRefused {
		t.Fatalf("Stopped = %q", p.Stopped())
	}
	if resp, _ := model(p, "g", g.Tokens["access_token"]); resp != nil {
		t.Fatal("a refused route made a model call")
	}
	if _, err := p.Guest("h"); !errors.Is(err, clerk.ErrPlanStopped) {
		t.Fatalf("Guest on a refused route = %v", err)
	}
	if err := p.Resume(); err != nil || p.Stopped() != "" {
		t.Fatalf("Resume = %v, Stopped %q", err, p.Stopped())
	}
	f.answerWith(400, `{"error":"refresh_token_reused"}`)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	if p.Stopped() != clerk.StopRefused {
		t.Fatalf("Stopped = %q", p.Stopped())
	}
	signIn(t, p, "signin-2")
	if p.Stopped() != "" {
		t.Fatalf("a new sign-in left the route %q", p.Stopped())
	}
}

// Only the sign-in guest reaches the device steps, which carry no
// credential; its code exchange goes out with the provider's callback, sets
// the login, and marks that guest alone as signed in. A sign-in to another
// account replaces the login, and old placeholders stop resolving.
func TestPlanSignInSetsTheLogin(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	resp, d := p.Do(context.Background(), "s", req("POST", "/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`,
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer x"}))
	if d != "" {
		t.Fatalf("device step: %s", d)
	}
	if out := read(t, resp); !strings.Contains(out, "ABCD-1234") {
		t.Fatalf("device answer = %q", out)
	}
	if up, _ := f.last(); up.Header.Get("Authorization") != "" {
		t.Fatal("a device step carried a credential")
	}
	before := f.hits()
	for _, b := range []string{
		strings.Replace(codeForm(), "127.0.0.1%3A18432", "evil.example", 1),
		codeForm() + "&scope=x",
		strings.Replace(codeForm(), "authorization_code", "password", 1),
	} {
		if resp, _ := p.Do(context.Background(), "s", req("POST", "/oauth/token", b, map[string]string{"Content-Type": "application/x-www-form-urlencoded"})); resp != nil {
			t.Errorf("code exchange %s was served", b)
		}
	}
	if f.hits() != before || p.Signed() {
		t.Fatal("a refused code exchange reached the provider")
	}
	got := signIn(t, p, "s")
	if _, body := f.last(); !strings.Contains(body, "redirect_uri=https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback") {
		t.Fatalf("code exchange sent %q", body)
	}
	if got["access_token"] == "real-access-1" || !p.Signed() || p.SignedIn("other") {
		t.Fatal("the sign-in did not set the login for that guest alone")
	}
	if err := p.BeginSignIn("s"); err == nil {
		t.Fatal("a guest holding placeholders became a sign-in guest")
	}
	old, _ := p.Guest("g")
	f.mu.Lock()
	f.acct = "acct-2"
	f.mu.Unlock()
	signIn(t, p, "s2")
	if resp, _ := model(p, "g", old.Tokens["access_token"]); resp != nil {
		t.Fatal("a placeholder minted for the old account resolved to the new one")
	}
	if now, _ := p.Guest("g"); now.Account != "acct-2" || now.Tokens["access_token"] == old.Tokens["access_token"] {
		t.Fatalf("Guest after an account change = %+v", now)
	}
	if err := p.Remove(); err != nil || p.Signed() {
		t.Fatal("Remove left the login")
	}
}

// The clerk holds its own login and no other account's secret.
func TestPlanClerkHoldsOneSlot(t *testing.T) {
	f := newPlanFix(t)
	if err := f.sec.Put("gmail", clerk.KindGrant, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := clerk.NewPlanLogin(f.decl(t), f.sec, f.roots); err == nil {
		t.Fatal("a store holding another slot was taken")
	}
	sec := clerk.NewSecrets(sealer(t), nil)
	if err := sec.Put("codex", clerk.KindStatic, []byte("k")); err != nil {
		t.Fatal(err)
	}
	if _, err := clerk.NewPlanLogin(f.decl(t), sec, f.roots); err == nil {
		t.Fatal("a static slot opened as a plan login")
	}
	d := f.decl(t)
	d.Guard = nil
	if _, err := clerk.NewPlanLogin(d, clerk.NewSecrets(sealer(t), nil), f.roots); err == nil {
		t.Fatal("a declaration without the home-network policy was taken")
	}
	d = f.decl(t)
	d.RequestHeaders = append(d.RequestHeaders, "Cookie")
	if _, err := clerk.NewPlanLogin(d, clerk.NewSecrets(sealer(t), nil), f.roots); err == nil {
		t.Fatal("a declaration passing Cookie was taken")
	}
}

// A stop the slot cannot record still stops the route.
func TestPlanStopHeldWhenTheSlotCannotRecordIt(t *testing.T) {
	f := newPlanFix(t)
	var fail atomic.Bool
	f.sec = clerk.NewSecrets(sealer(t), func([]byte) error {
		if fail.Load() {
			return errors.New("disk full")
		}
		return nil
	})
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	fail.Store(true)
	f.answerWith(200, `{"access_token":"real-access-9","id_token":"`+idToken("acct-1")+`","extra":"x"}`)
	if resp, _ := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil {
		t.Fatal("an unswappable answer was forwarded")
	}
	if p.Stopped() != clerk.StopUnswappable {
		t.Fatalf("Stopped = %q", p.Stopped())
	}
	if resp, _ := model(p, "g", g.Tokens["access_token"]); resp != nil {
		t.Fatal("a held stop let a model call through")
	}
	if err := p.Resume(); !errors.Is(err, clerk.ErrRequalify) {
		t.Fatalf("Resume = %v", err)
	}
	// A good answer that cannot be sealed is dropped too: the single-use
	// token it replaces is not handed on.
	f2 := newPlanFix(t)
	f2.sec = clerk.NewSecrets(sealer(t), func([]byte) error {
		if fail.Load() {
			return errors.New("disk full")
		}
		return nil
	})
	fail.Store(false)
	p2 := f2.login(t)
	signIn(t, p2, "signin")
	g2, _ := p2.Guest("g")
	fail.Store(true)
	if resp, d := refreshReq(p2, "g", g2.Tokens["refresh_token"]); resp != nil || d != clerk.DPlanSave {
		t.Fatalf("refresh with a failing store = %q", d)
	}
}
