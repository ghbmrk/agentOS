package plan_test

// REQ: CLK-1, CLK-3, CLK-4, CLK-7, PLN-5

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/plan"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// planFix is a plan login clerk over a fake provider under example.com. The
// provider's tokens are synthetic: real-access-N and real-refresh-N, the Nth
// login it issued, for account acct.
type planFix struct {
	srv   *httptest.Server
	roots *x509.CertPool
	seal  clerk.Sealer
	sec   *plan.Store
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
	// usercode, if set, answers the user code step instead of the fake's own.
	usercode func(w http.ResponseWriter) bool
	// device, if set, answers the device token poll instead of the fake's own.
	device func(w http.ResponseWriter, r *http.Request, body string) bool
	// stream, if set, answers a model call instead of the fake's own.
	stream func(w http.ResponseWriter, r *http.Request)
	// list, if set, answers the models read instead of the fake's own.
	list func(w http.ResponseWriter, r *http.Request)
}

func sealer(t *testing.T) clerk.Sealer {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// resolver answers every name with one address.
type resolver netip.Addr

func (r resolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.Addr(r)}, nil
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
	f.sec = plan.NewStore(f.seal, nil)
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
		if f.usercode != nil && f.usercode(w) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device_auth_id":"real-device-1","user_code":"ABCD-1234"}`))
	case "/api/accounts/deviceauth/token":
		if f.device != nil && f.device(w, r, string(b)) {
			return
		}
		if !strings.Contains(string(b), `"device_auth_id":"real-device-1"`) {
			w.WriteHeader(404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"authorization_code":"real-code-1","code_challenge":"challenge-1","code_verifier":"real-verifier-1"}`))
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
		if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			if f, _ := url.ParseQuery(string(b)); f.Get("code") != "real-code-1" || f.Get("code_verifier") != "real-verifier-1" {
				w.WriteHeader(400)
				w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
		}
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
		if f.stream != nil && r.URL.Path == "/backend-api/codex/responses" {
			f.stream(w, r)
			return
		}
		if f.list != nil && r.URL.Path == "/backend-api/codex/models" {
			f.list(w, r)
			return
		}
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

func (f *planFix) decl(t *testing.T) plan.Declaration {
	d := plan.Codex(netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
	}}))
	for i := range d.Endpoints {
		d.Endpoints[i].Host = f.host
	}
	return d
}

func (f *planFix) login(t *testing.T) *plan.Login {
	t.Helper()
	p, err := plan.New(f.decl(t), f.sec, f.roots)
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

// codeForm is the CLI's code exchange of code and verifier, with its local
// callback.
func codeForm(code, verifier string) string {
	return url.Values{"client_id": {plan.CodexClientID}, "code": {code}, "code_verifier": {verifier}, "grant_type": {"authorization_code"},
		"redirect_uri": {"http://127.0.0.1:18432/deviceauth/callback"}}.Encode()
}

// deviceSteps runs a sign-in guest's device steps as the CLI does and
// returns the code exchange it would then send, holding what the guest got.
func deviceSteps(t *testing.T, p *plan.Login, guest string) string {
	t.Helper()
	json1 := map[string]string{"Content-Type": "application/json"}
	resp, d := p.Do(context.Background(), guest, req("POST", "/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`, json1), nil)
	if d != "" {
		t.Fatalf("usercode: %s", d)
	}
	var uc map[string]string
	if err := json.Unmarshal([]byte(read(t, resp)), &uc); err != nil {
		t.Fatal(err)
	}
	poll, _ := json.Marshal(map[string]string{"device_auth_id": uc["device_auth_id"], "user_code": uc["user_code"]})
	resp, d = p.Do(context.Background(), guest, req("POST", "/api/accounts/deviceauth/token", string(poll), json1), nil)
	if d != "" {
		t.Fatalf("devicetoken: %s", d)
	}
	var ct map[string]string
	if err := json.Unmarshal([]byte(read(t, resp)), &ct); err != nil {
		t.Fatal(err)
	}
	return codeForm(ct["authorization_code"], ct["code_verifier"])
}

// signIn runs the owner's sign-in in guest and returns what the guest got.
func signIn(t *testing.T, p *plan.Login, guest string) map[string]any {
	t.Helper()
	if err := p.BeginSignIn(guest); err != nil {
		t.Fatal(err)
	}
	resp, d := p.Do(context.Background(), guest, req("POST", "/oauth/token", deviceSteps(t, p, guest), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil)
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

func model(p *plan.Login, guest, bearer string) (*http.Response, string) {
	h := map[string]string{"Content-Type": "application/json", "Cookie": "c=1", "X-Forwarded-For": "1.2.3.4"}
	if bearer != "" {
		h["Authorization"] = "Bearer " + bearer
	}
	return p.Do(context.Background(), guest, req("POST", "/backend-api/codex/responses", `{"model":"m","stream":true}`, h), free)
}

// free admits every model call and records nothing.
func free([]byte) (func(plan.Used), string) { return func(plan.Used) {}, "" }

func refreshBody(ph string) string {
	return `{"client_id":"` + plan.CodexClientID + `","grant_type":"refresh_token","refresh_token":"` + ph + `"}`
}

func refreshReq(p *plan.Login, guest, ph string) (*http.Response, string) {
	return p.Do(context.Background(), guest, req("POST", "/oauth/token", refreshBody(ph), map[string]string{"Content-Type": "application/json"}), nil)
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
	if _, err := p.Guest("g1"); !errors.Is(err, plan.ErrNoLogin) {
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
	if up.Header.Get("Authorization") != "Bearer real-access-1" || body != `{"model":"m","store":false,"stream":true}` || up.Host != f.host {
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
	if resp, d := p.Do(context.Background(), "g1", q, nil); d != "" {
		t.Fatalf("read: %s", d)
	} else {
		read(t, resp)
	}
	before := f.hits()
	for name, c := range map[string]func() (*http.Response, string){
		"undeclared path": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/backend-api/files", "{}", map[string]string{"Authorization": "Bearer " + g1.Tokens["access_token"]}), nil)
		},
		"another guest's placeholder": func() (*http.Response, string) { return model(p, "g1", g2.Tokens["access_token"]) },
		"the refresh placeholder":     func() (*http.Response, string) { return model(p, "g1", g1.Tokens["refresh_token"]) },
		"no bearer":                   func() (*http.Response, string) { return model(p, "g1", "") },
		"the real token itself":       func() (*http.Response, string) { return model(p, "g1", "real-access-1") },
		"a sign-in step from a run guest": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`, map[string]string{"Content-Type": "application/json"}), nil)
		},
		"an undeclared query": func() (*http.Response, string) {
			r := httptest.NewRequest("GET", "http://x/backend-api/codex/models?client_version=1&x=2", nil)
			r.Header.Set("Authorization", "Bearer "+g1.Tokens["access_token"])
			return p.Do(context.Background(), "g1", r, nil)
		},
		"a read with a body": func() (*http.Response, string) {
			r := httptest.NewRequest("GET", "http://x/backend-api/codex/models", strings.NewReader("x"))
			r.Header.Set("Authorization", "Bearer "+g1.Tokens["access_token"])
			return p.Do(context.Background(), "g1", r, nil)
		},
		"an encoded body": func() (*http.Response, string) {
			return p.Do(context.Background(), "g1", req("POST", "/backend-api/codex/responses", "x", map[string]string{"Authorization": "Bearer " + g1.Tokens["access_token"], "Content-Encoding": "gzip"}), free)
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
	if resp, d := model(p, "g", g.Tokens["access_token"]); resp != nil || d != plan.DEncoded {
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
		if resp, _ := p.Do(context.Background(), "g", req("POST", "/oauth/token", b, nil), nil); resp != nil {
			t.Errorf("refresh %s was served", b)
		}
	}
	if f.hits() != before {
		t.Fatal("a refused refresh reached the provider")
	}
}

// REQ: CLK-7
//
// A refresh body carries the CLI's own client_id and no scope (#3110): one
// with another client_id or scope, or without the client_id, is refused
// with nothing sent, so a guest cannot shape the provider's answer into an
// unswappable stop. The declared values pass.
func TestPlanRefreshPinsClientIDAndScope(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["refresh_token"]
	before := f.hits()
	for _, b := range []string{
		`{"client_id":"app_other","grant_type":"refresh_token","refresh_token":"` + ph + `"}`,
		`{"client_id":"` + plan.CodexClientID + `x","grant_type":"refresh_token","refresh_token":"` + ph + `"}`,
		`{"client_id":"` + strings.ToLower(plan.CodexClientID) + `","grant_type":"refresh_token","refresh_token":"` + ph + `"}`,
		`{"client_id":"` + plan.CodexClientID + `","grant_type":"refresh_token","refresh_token":"` + ph + `","scope":"openid"}`,
		`{"client_id":"` + plan.CodexClientID + `","grant_type":"refresh_token","refresh_token":"` + ph + `","scope":""}`,
		`{"grant_type":"refresh_token","refresh_token":"` + ph + `","scope":"openid profile email"}`,
		// Three keys, as the declared body has: an undeclared key with an
		// empty value stands where client_id belongs.
		`{"grant_type":"refresh_token","refresh_token":"` + ph + `","scope":""}`,
		`{"grant_type":"refresh_token","refresh_token":"` + ph + `"}`,
		`{"client_id":"` + plan.CodexClientID + `","grant_type":"refresh_token"}`,
	} {
		if resp, d := p.Do(context.Background(), "g", req("POST", "/oauth/token", b, map[string]string{"Content-Type": "application/json"}), nil); resp != nil || d != plan.DPlaceholder {
			t.Errorf("refresh %s: served or %q", b, d)
		}
	}
	if f.hits() != before || p.Stopped() != "" {
		t.Fatalf("a refused refresh reached the provider (%d sent) or stopped the route (%q)", f.hits()-before, p.Stopped())
	}
	resp, d := refreshReq(p, "g", ph)
	if d != "" {
		t.Fatalf("the declared refresh: %s", d)
	}
	read(t, resp)
	_, body := f.last()
	var sent map[string]string
	if err := json.Unmarshal([]byte(body), &sent); err != nil || len(sent) != 3 || sent["client_id"] != plan.CodexClientID ||
		sent["grant_type"] != "refresh_token" || sent["refresh_token"] != "real-refresh-1" {
		t.Fatalf("the declared refresh sent %q", body)
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
	tok := map[string]plan.Tokens{}
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
		"number too long":   `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + idToken("acct-1") + `","expires_in":123456789012345678901}`,
		"text out of shape": `{"access_token":"real-access-9","refresh_token":"real-refresh-9","id_token":"` + idToken("acct-1") + `","token_type":"real-access-9"}`,
	} {
		t.Run(name, func(t *testing.T) {
			f := newPlanFix(t)
			p := f.login(t)
			signIn(t, p, "signin")
			g, _ := p.Guest("g")
			f.answerWith(200, body)
			if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != plan.DUnswappable {
				t.Fatalf("refresh = %v %q", resp, d)
			}
			if p.Stopped() != plan.StopUnswappable {
				t.Fatalf("Stopped = %q", p.Stopped())
			}
			before := f.hits()
			if resp, d := model(p, "g", g.Tokens["access_token"]); resp != nil || !strings.HasPrefix(d, plan.DStopped) {
				t.Fatalf("model call on a stopped route = %q", d)
			}
			if err := p.BeginSignIn("s2"); err == nil {
				t.Fatal("a sign-in started on an unswappable route")
			}
			if f.hits() != before {
				t.Fatal("a stopped route sent a request")
			}
			if err := p.Resume(); !errors.Is(err, plan.ErrRequalify) {
				t.Fatalf("Resume = %v", err)
			}
			if err := p.Remove(); err != nil || p.Stopped() != plan.StopUnswappable {
				t.Fatalf("Remove lifted the stop: %v %q", err, p.Stopped())
			}
			// A restart with the same declaration keeps it.
			at, _ := f.sec.MarshalBinary()
			sec := plan.NewStore(f.seal, nil)
			sec.Load(at)
			again, err := plan.New(f.decl(t), sec, f.roots)
			if err != nil || again.Stopped() != plan.StopUnswappable {
				t.Fatalf("after a restart Stopped = %q (%v)", again.Stopped(), err)
			}
			d := f.decl(t)
			d.Version = "codex-0.163.0-1"
			next, err := plan.New(d, sec, f.roots)
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
	}{{400, `{"error":"invalid_grant"}`}, {500, `{"error":"server"}`}, {401, `{"error":{"code":"other"}}`},
		{500, `{"error":"refresh_token_expired"}`}, {403, `{"error":{"code":"refresh_token_reused"}}`}} {
		f.answerWith(a.status, a.body)
		if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || !strings.HasPrefix(d, plan.DExchange) {
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
	if p.Stopped() != plan.StopRefused {
		t.Fatalf("Stopped = %q", p.Stopped())
	}
	if resp, _ := model(p, "g", g.Tokens["access_token"]); resp != nil {
		t.Fatal("a refused route made a model call")
	}
	if _, err := p.Guest("h"); !errors.Is(err, plan.ErrStopped) {
		t.Fatalf("Guest on a refused route = %v", err)
	}
	if err := p.Resume(); err != nil || p.Stopped() != "" {
		t.Fatalf("Resume = %v, Stopped %q", err, p.Stopped())
	}
	f.answerWith(400, `{"error":"refresh_token_reused"}`)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	if p.Stopped() != plan.StopRefused {
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
		map[string]string{"Content-Type": "application/json", "Authorization": "Bearer x"}), nil)
	if d != "" {
		t.Fatalf("device step: %s", d)
	}
	if out := read(t, resp); !strings.Contains(out, "ABCD-1234") {
		t.Fatalf("device answer = %q", out)
	}
	if up, _ := f.last(); up.Header.Get("Authorization") != "" {
		t.Fatal("a device step carried a credential")
	}
	long := `{"client_id":"` + strings.Repeat("a", 513) + `"}`
	if resp, _ := p.Do(context.Background(), "s", req("POST", "/api/accounts/deviceauth/usercode", long, map[string]string{"Content-Type": "application/json"}), nil); resp != nil {
		t.Fatal("a device step with an over-long value was served")
	}
	before := f.hits()
	for _, b := range []string{
		strings.Replace(codeForm("c", "v"), "127.0.0.1%3A18432", "evil.example", 1),
		codeForm("c", "v") + "&scope=x",
		strings.Replace(codeForm("c", "v"), "authorization_code", "password", 1),
	} {
		if resp, _ := p.Do(context.Background(), "s", req("POST", "/oauth/token", b, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil); resp != nil {
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

// The store holds this plan's login alone: one sealed for another plan, or
// under another key, does not open.
func TestPlanClerkHoldsOneSlot(t *testing.T) {
	f := newPlanFix(t)
	d := f.decl(t)
	d.Name = "other"
	other, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	signIn(t, other, "signin")
	at, _ := f.sec.MarshalBinary()
	for name, st := range map[string]*plan.Store{"another plan": plan.NewStore(f.seal, nil), "another key": plan.NewStore(sealer(t), nil)} {
		st.Load(at)
		if _, err := plan.New(f.decl(t), st, f.roots); err == nil {
			t.Errorf("a store sealed for %s was taken", name)
		}
	}
	d = f.decl(t)
	d.Guard = nil
	if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err == nil {
		t.Fatal("a declaration without the home-network policy was taken")
	}
	d = f.decl(t)
	d.RequestHeaders = append(d.RequestHeaders, "Cookie")
	if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err == nil {
		t.Fatal("a declaration passing Cookie was taken")
	}
	for _, mod := range []func(*plan.Declaration){
		func(d *plan.Declaration) { d.ResponseHeaders = append(d.ResponseHeaders, "Set-Cookie") },
		func(d *plan.Declaration) { d.ResponseHeaders = append(d.ResponseHeaders, "X-Codex-Session-Token") },
		func(d *plan.Declaration) { d.ResponseHeaders = append(d.ResponseHeaders, "Session_id") },
	} {
		d = f.decl(t)
		mod(&d)
		if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err == nil {
			t.Errorf("a declaration passing a forbidden answer header was taken: %v", d.ResponseHeaders)
		}
	}
}

// A stop the slot cannot record still stops the route.
func TestPlanStopHeldWhenTheSlotCannotRecordIt(t *testing.T) {
	f := newPlanFix(t)
	var fail atomic.Bool
	f.sec = plan.NewStore(sealer(t), func([]byte) error {
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
	if p.Stopped() != plan.StopUnswappable {
		t.Fatalf("Stopped = %q", p.Stopped())
	}
	if resp, _ := model(p, "g", g.Tokens["access_token"]); resp != nil {
		t.Fatal("a held stop let a model call through")
	}
	if err := p.Resume(); !errors.Is(err, plan.ErrRequalify) {
		t.Fatalf("Resume = %v", err)
	}
	// A good answer that cannot be sealed is dropped too: the single-use
	// token it replaces is not handed on.
	f2 := newPlanFix(t)
	f2.sec = plan.NewStore(sealer(t), func([]byte) error {
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
	if resp, d := refreshReq(p2, "g", g2.Tokens["refresh_token"]); resp != nil || d != plan.DSave {
		t.Fatalf("refresh with a failing store = %q", d)
	}
}

// A refresh answer that arrives after the owner removed the login, or signed
// in again, was made for a login no longer stored: it is dropped, never
// committed, and stops nothing, whatever it says (#3105 Security 1).
func TestPlanStaleRefreshAnswerStopsNothing(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   func() string
		owner  func(t *testing.T, f *planFix, p *plan.Login)
	}{
		"removed, then a good answer": {200, nil, func(t *testing.T, f *planFix, p *plan.Login) {
			if err := p.Remove(); err != nil {
				t.Fatal(err)
			}
		}},
		"signed in to another account, then the old account's answer": {200, nil, func(t *testing.T, f *planFix, p *plan.Login) {
			f.mu.Lock()
			f.acct = "acct-2"
			f.mu.Unlock()
			signIn(t, p, "signin-2")
		}},
		"signed in again, then a refused code": {401, func() string { return `{"error":"refresh_token_reused"}` }, func(t *testing.T, f *planFix, p *plan.Login) {
			signIn(t, p, "signin-2")
		}},
		"removed, then an answer out of shape": {200, func() string { return `{"access_token":"real-access-9","extra":"x"}` }, func(t *testing.T, f *planFix, p *plan.Login) {
			if err := p.Remove(); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newPlanFix(t)
			p := f.login(t)
			signIn(t, p, "signin")
			g, _ := p.Guest("g")
			entered, hold := make(chan struct{}), make(chan struct{})
			f.answer = func(w http.ResponseWriter, r *http.Request, _ string) bool {
				if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
					return false // the owner's code exchange
				}
				close(entered)
				<-hold
				f.mu.Lock()
				body := ""
				if c.body != nil {
					body = c.body()
				} else {
					f.acct = "acct-1"
					b, _ := json.Marshal(f.tokens())
					body = string(b)
				}
				f.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(c.status)
				w.Write([]byte(body))
				return true
			}
			done := make(chan string)
			go func() {
				resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
				if resp != nil {
					d = "forwarded: " + read(t, resp)
				}
				done <- d
			}()
			<-entered
			f.answer = func(http.ResponseWriter, *http.Request, string) bool { return false }
			c.owner(t, f, p)
			close(hold)
			if d := <-done; d != plan.DStale {
				t.Fatalf("a stale refresh answer = %q", d)
			}
			if s := p.Stopped(); s != "" {
				t.Fatalf("a stale answer stopped the route: %q", s)
			}
			if err := p.BeginSignIn("again"); err != nil {
				t.Fatalf("BeginSignIn after a stale answer: %v", err)
			}
			if strings.HasPrefix(name, "removed") && p.Signed() {
				t.Fatal("a stale answer was committed after Remove")
			}
			if strings.HasPrefix(name, "signed in to another") {
				if now, err := p.Guest("h"); err != nil || now.Account != "acct-2" {
					t.Fatalf("the stale answer replaced the new login: %+v %v", now, err)
				}
			}
		})
	}
}

// A refresh answer may omit the refresh token, which Codex declares
// optional: the stored one is kept, and the route goes on.
func TestPlanRefreshAnswerWithoutARefreshTokenKeepsTheStoredOne(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	f.answerWith(200, `{"access_token":"real-access-7","id_token":"`+idToken("acct-1")+`"}`)
	resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
	if d != "" {
		t.Fatalf("refresh = %q", d)
	}
	out := read(t, resp)
	noReal(t, "the refresh answer", out)
	if strings.Contains(out, "refresh_token") || p.Stopped() != "" {
		t.Fatalf("answer %q, Stopped %q", out, p.Stopped())
	}
	resp, _ = model(p, "g", g.Tokens["access_token"])
	read(t, resp)
	if up, _ := f.last(); up.Header.Get("Authorization") != "Bearer real-access-7" {
		t.Fatalf("model call sent %q", up.Header.Get("Authorization"))
	}
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); d != "" {
		t.Fatalf("the kept refresh token was not used: %q", d)
	} else {
		read(t, resp)
	}
	if _, body := f.last(); !strings.Contains(body, `"refresh_token":"real-refresh-1"`) {
		t.Fatalf("second refresh sent %q", body)
	}
}

// A guest that cancels its refresh mid-exchange does not lose the answer:
// the provider has already spent the single-use token, so the flight runs
// on and commits the new one (ASSUMPTIONS a7; #3105 L3 1).
func TestPlanCancelledRefreshStillCommits(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	f.exchanges.Store(0)
	f.gate = make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, 1)
	go func() {
		_, d := p.Do(ctx, "g", req("POST", "/oauth/token", refreshBody(g.Tokens["refresh_token"]), map[string]string{"Content-Type": "application/json"}), nil)
		done <- d
	}()
	for f.exchanges.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	time.Sleep(20 * time.Millisecond)
	close(f.gate)
	<-done
	f.gate = nil
	resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
	if resp == nil {
		t.Fatalf("the rotated token was lost when the guest cancelled: next refresh = %q", d)
	}
	read(t, resp)
	if _, body := f.last(); !strings.Contains(body, `"refresh_token":"real-refresh-2"`) {
		t.Fatalf("the next refresh sent %q", body)
	}
}

// REQ: CLK-7
//
// A code exchange sends the declared client_id, the one its refresh sends
// (#5089 item 7): another is refused with nothing sent, and the declared
// one passes.
func TestPlanCodeExchangePinsClientID(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "s")
	before := f.hits()
	for _, id := range []string{"app_other", plan.CodexClientID + "x", strings.ToLower(plan.CodexClientID)} {
		b := strings.Replace(form, "client_id="+plan.CodexClientID, "client_id="+url.QueryEscape(id), 1)
		if resp, d := p.Do(context.Background(), "s", req("POST", "/oauth/token", b, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil); resp != nil || d != plan.DUndeclared {
			t.Errorf("code exchange with client_id %q: served or %q", id, d)
		}
	}
	if f.hits() != before || p.Signed() {
		t.Fatalf("a refused code exchange reached the provider (%d sent) or signed in", f.hits()-before)
	}
	resp, d := p.Do(context.Background(), "s", req("POST", "/oauth/token", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil)
	if d != "" {
		t.Fatalf("the declared code exchange: %s", d)
	}
	read(t, resp)
	if _, body := f.last(); !strings.Contains(body, "client_id="+plan.CodexClientID+"&") || !p.SignedIn("s") {
		t.Fatalf("the declared code exchange sent %q", body)
	}
}

// REQ: CLK-7
//
// A refresh carries the declared refresh headers and none of the guest's
// (#5089 item 2): a guest's Accept, User-Agent, Originator or account
// header never reaches the provider, so a guest cannot shape a refresh's
// answer through its headers either.
func TestPlanRefreshSendsOnlyDeclaredHeaders(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	h := map[string]string{
		"Content-Type": "application/json", "Accept": "application/x-www-form-urlencoded", "User-Agent": "guest/1",
		"Originator": "guest", "Chatgpt-Account-Id": "acct-other", "Session_id": "s-1", "Openai-Beta": "x", "Version": "9",
	}
	resp, d := p.Do(context.Background(), "g", req("POST", "/oauth/token", refreshBody(g.Tokens["refresh_token"]), h), nil)
	if d != "" {
		t.Fatalf("refresh: %s", d)
	}
	read(t, resp)
	up, _ := f.last()
	if up.URL.Path != "/oauth/token" || up.Header.Get("Originator") != "codex_cli_rs" || up.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("the refresh sent %v", up.Header)
	}
	for k := range up.Header {
		switch k {
		case "Originator", "Content-Type", "Content-Length", "Accept-Encoding":
		default:
			t.Errorf("the refresh sent header %s: %q", k, up.Header.Values(k))
		}
	}
	if len(up.Header.Values("Originator")) != 1 {
		t.Errorf("the refresh sent Originator %q", up.Header.Values("Originator"))
	}
}

// REQ: CLK-7
//
// New refuses a declaration whose refresh would not be the CLI's exact one
// (#5089 items 1 and 9): refresh_token declared as a fixed value, a
// grant_type other than refresh_token or none, a code exchange without the
// client_id, or a refresh header that is a credential, framing or the
// clerk's own, non-canonical, or no plain value. Codex's declaration
// passes.
func TestPlanDeclarationHoldsTheRefresh(t *testing.T) {
	f := newPlanFix(t)
	if _, err := plan.New(f.decl(t), plan.NewStore(sealer(t), nil), f.roots); err != nil {
		t.Fatalf("Codex: %v", err)
	}
	cases := map[string]func(d *plan.Declaration){
		"refresh_token fixed": func(d *plan.Declaration) { d.Refresh["refresh_token"] = "x" },
		"no grant_type":       func(d *plan.Declaration) { delete(d.Refresh, "grant_type") },
		"another grant_type":  func(d *plan.Declaration) { d.Refresh["grant_type"] = "authorization_code" },
		"no client_id":        func(d *plan.Declaration) { delete(d.Refresh, "client_id") },
		"empty client_id":     func(d *plan.Declaration) { d.Refresh["client_id"] = "" },
		"Authorization":       func(d *plan.Declaration) { d.RefreshHeaders["Authorization"] = "Bearer x" },
		"Cookie":              func(d *plan.Declaration) { d.RefreshHeaders["Cookie"] = "c=1" },
		"Content-Type":        func(d *plan.Declaration) { d.RefreshHeaders["Content-Type"] = "text/plain" },
		"Accept-Encoding":     func(d *plan.Declaration) { d.RefreshHeaders["Accept-Encoding"] = "gzip" },
		"X-Forwarded-For":     func(d *plan.Declaration) { d.RefreshHeaders["X-Forwarded-For"] = "1.2.3.4" },
		"non-canonical":       func(d *plan.Declaration) { d.RefreshHeaders["originator"] = "codex_cli_rs" },
		"empty value":         func(d *plan.Declaration) { d.RefreshHeaders["Originator"] = "" },
		"padded value":        func(d *plan.Declaration) { d.RefreshHeaders["Originator"] = " codex_cli_rs" },
		"line break":          func(d *plan.Declaration) { d.RefreshHeaders["Originator"] = "codex\r\nX-A: b" },
		"non-ASCII":           func(d *plan.Declaration) { d.RefreshHeaders["Originator"] = "codexé" },
	}
	for name, mutate := range cases {
		d := f.decl(t)
		mutate(&d)
		if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err == nil {
			t.Errorf("%s: New accepted the declaration", name)
		}
	}
	// Without a code exchange, a refresh needs no client_id.
	d := f.decl(t)
	delete(d.Refresh, "client_id")
	var keep []plan.Endpoint
	for _, e := range d.Endpoints {
		if e.Kind != plan.Code {
			keep = append(keep, e)
		}
	}
	d.Endpoints = keep
	if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err != nil {
		t.Fatalf("no code exchange, no client_id: %v", err)
	}
}

// The answer to a token exchange reaches the guest as JSON, and a
// credential the provider sends that is part of the guest's placeholder is
// not swapped into it: the placeholder would carry the credential (CLK-7).
func TestPlanExchangeAnswerHoldsNoCredential(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("signin"); err != nil {
		t.Fatal(err)
	}
	resp, d := p.Do(context.Background(), "signin", req("POST", "/oauth/token", deviceSteps(t, p, "signin"), map[string]string{"Content-Type": "application/x-www-form-urlencoded"}), nil)
	if d != "" {
		t.Fatalf("code exchange: %s", d)
	}
	resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("the exchange answer's Content-Type is %q", ct)
	}
	g, _ := p.Guest("g")
	f.answerWith(200, `{"access_token":"agentos-ph-access","id_token":"`+idToken("acct-1")+`"}`)
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != plan.DUnswappable {
		t.Fatalf("a credential inside a placeholder: %v %q", resp != nil, d)
	}
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp == nil || d != "" {
		t.Fatalf("the refresh after it: %q", d)
	}
}

// A refused login the slot could not record is held in memory, and a new
// sign-in answers it there too.
func TestPlanSignInAnswersAHeldRefusal(t *testing.T) {
	f := newPlanFix(t)
	var fail atomic.Bool
	f.sec = plan.NewStore(sealer(t), func([]byte) error {
		if fail.Load() {
			return errors.New("disk full")
		}
		return nil
	})
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	fail.Store(true)
	f.answerWith(401, `{"error":{"code":"refresh_token_expired"}}`)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	if p.Stopped() != plan.StopRefused {
		t.Fatalf("Stopped = %q, want a held refusal", p.Stopped())
	}
	fail.Store(false)
	signIn(t, p, "signin-2")
	if p.Stopped() != "" {
		t.Fatalf("a new sign-in left the route %q", p.Stopped())
	}
}

// sealProbe is a sealer whose Seal can be made to fail, whose Open can be
// made to fail while still handing back what it opened, and which keeps
// every plaintext it was handed or handed back. failIn names a Login method
// whose own loads of the slot fail, and onOpen, if set, runs at each Open
// with the method that loaded.
type sealProbe struct {
	clerk.Sealer
	failSeal, failOpen atomic.Bool
	mu                 sync.Mutex
	opened, sealed     [][]byte
	failIn             string
	onOpen             func(by string)
}

func (s *sealProbe) Seal(plain, aad []byte) ([]byte, error) {
	s.mu.Lock()
	s.sealed = append(s.sealed, plain)
	s.mu.Unlock()
	if s.failSeal.Load() {
		return nil, errors.New("seal fails")
	}
	return s.Sealer.Seal(plain, aad)
}

func (s *sealProbe) Open(blob, aad []byte) ([]byte, error) {
	by := loadedBy()
	plain, err := s.Sealer.Open(blob, aad)
	s.mu.Lock()
	s.opened = append(s.opened, plain)
	failIn, onOpen := s.failIn, s.onOpen
	s.mu.Unlock()
	if onOpen != nil {
		onOpen(by)
	}
	if s.failOpen.Load() || failIn != "" && by == failIn {
		return plain, errors.New("open fails")
	}
	return plain, err
}

// loadedBy is the Login method that loaded the slot an Open serves.
func loadedBy() string {
	pc := make([]uintptr, 64)
	frames := runtime.CallersFrames(pc[:runtime.Callers(2, pc)])
	for f, more := frames.Next(); more; f, more = frames.Next() {
		if strings.HasSuffix(f.Function, ".(*Login).load") {
			f, _ = frames.Next()
			return f.Function[strings.LastIndex(f.Function, ".")+1:]
		}
	}
	return ""
}

// wiped reports whether every plaintext in got was zeroed.
func wiped(got [][]byte) bool {
	for _, b := range got {
		if len(b) == 0 || bytes.Count(b, []byte{0}) != len(b) {
			return false
		}
	}
	return len(got) > 0
}

// returns fails t unless fn returns within a few seconds: a lock left held
// would hang it.
func returns(t *testing.T, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// The login's slot: a login that cannot be sealed is not stored, and the
// one stored stays; a slot that does not open is not read, whatever the
// sealer handed back; every plaintext opened is wiped once read (CLK-1).
func TestPlanSlotSealsOpensAndWipes(t *testing.T) {
	f := newPlanFix(t)
	s := &sealProbe{Sealer: f.seal}
	f.sec = plan.NewStore(s, nil)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	before, _ := f.sec.MarshalBinary()

	s.failSeal.Store(true)
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != plan.DSave {
		t.Fatalf("a refresh that cannot be sealed: %v %q", resp != nil, d)
	}
	s.failSeal.Store(false)
	if after, _ := f.sec.MarshalBinary(); !bytes.Equal(after, before) || !p.Signed() {
		t.Fatal("a login that could not be sealed changed the stored one")
	}

	returns(t, "a Resume after a login that could not be sealed", func() { p.Resume() })
	s.mu.Lock()
	if !wiped(s.opened) || !wiped(s.sealed) {
		t.Fatalf("a plaintext was not wiped: opened %q, sealed %q", s.opened, s.sealed)
	}
	s.mu.Unlock()

	s.failOpen.Store(true)
	if _, err := plan.New(f.decl(t), f.sec, f.roots); err == nil {
		t.Fatal("a slot that did not open was read")
	}
}

// A declaration is refused for the rule it breaks, each rule on its own: no
// later rule stands in for an earlier one, and a declaration with no pool is
// no pool to name.
func TestPlanDeclarationNamesTheRuleItBreaks(t *testing.T) {
	f := newPlanFix(t)
	cases := []struct {
		name, want string
		edit       func(d *plan.Declaration)
	}{
		{"a name that is not plain", "a plain name and a version", func(d *plan.Declaration) { d.Name = "co dex" }},
		{"no version", "a plain name and a version", func(d *plan.Declaration) { d.Version = "" }},
		{"an unknown mode", `mode "x"`, func(d *plan.Declaration) { d.Mode = "x" }},
		{"an unknown endpoint kind", `kind "x"`, func(d *plan.Declaration) { d.Endpoints[0].Kind = "x" }},
		{"an unnamed endpoint", "is out of shape", func(d *plan.Declaration) { d.Endpoints[1].Name = "" }},
		{"a lower-case method", "is out of shape", func(d *plan.Declaration) { d.Endpoints[1].Method = "get" }},
		{"a path out of shape", "is out of shape", func(d *plan.Declaration) { d.Endpoints[1].Path = "/a b" }},
		{"a host out of shape", "is out of shape", func(d *plan.Declaration) { d.Endpoints[1].Host = "Example.com" }},
		{"a read by POST", "a read is a GET", func(d *plan.Declaration) { d.Endpoints[1].Method = "POST" }},
		{"a GET that is not a read", "a read is a GET", func(d *plan.Declaration) { d.Endpoints[0].Method = "GET" }},
		{"a repeated request", "repeats a request", func(d *plan.Declaration) {
			e := d.Endpoints[1]
			e.Name = "models-2"
			d.Endpoints = append(d.Endpoints, e)
		}},
		{"a repeated token field", "unnamed or repeated", func(d *plan.Declaration) { d.Token = append(d.Token, d.Token[3]) }},
		{"an unnamed token field", "unnamed or repeated", func(d *plan.Declaration) { d.Token[3].Name = "" }},
		{"a credential with a pattern", "only text takes a pattern", func(d *plan.Declaration) { d.Token[0].Pattern = "x" }},
		{"a number with a pattern", "only text takes a pattern", func(d *plan.Declaration) { d.Token[3].Pattern = "x" }},
		{"text with no pattern", "text needs a valid pattern", func(d *plan.Declaration) { d.Token[4].Pattern = "" }},
		{"text with a broken pattern", "text needs a valid pattern", func(d *plan.Declaration) { d.Token[4].Pattern = "(" }},
		{"an unknown field kind", `kind "x"`, func(d *plan.Declaration) { d.Token[3].Kind = "x" }},
		{"a credential that is no token", "only the access, refresh and id tokens are credentials", func(d *plan.Declaration) {
			d.Token[3].Kind = plan.FieldCredential
		}},
		{"a token that is no credential", "only the access, refresh and id tokens are credentials", func(d *plan.Declaration) {
			d.Token[2].Kind, d.Token[2].Pattern = plan.FieldText, "x"
		}},
		{"no access token", "declares an access token", func(d *plan.Declaration) { d.Token = d.Token[1:] }},
		{"an optional access token", "declares an access token", func(d *plan.Declaration) { d.Token[0].Optional = true }},
		{"no id token", "declares an access token", func(d *plan.Declaration) { d.Token = append(d.Token[:2:2], d.Token[3:]...) }},
		{"no account claim", "declares an access token", func(d *plan.Declaration) { d.AccountClaim = nil }},
		{"no body keys", "declares its keys, input types and content types", func(d *plan.Declaration) { d.Body.Keys = nil }},
		{"no input types", "declares its keys, input types and content types", func(d *plan.Declaration) { d.Body.InputTypes = nil }},
		{"no content types", "declares its keys, input types and content types", func(d *plan.Declaration) { d.Body.ContentTypes = nil }},
		{"no store key", "declares store", func(d *plan.Declaration) {
			d.Body.Keys = []string{"model", "input", "stream", "client_metadata"}
		}},
		{"a stream with no stream key", "declares its stream key", func(d *plan.Declaration) {
			d.Body.Keys = []string{"model", "input", "store", "client_metadata"}
		}},
		{"a pool with no name", "needs its ID and name", func(d *plan.Declaration) { d.Pool.Name = "" }},
	}
	for _, c := range cases {
		d := f.decl(t)
		d.Endpoints = append([]plan.Endpoint(nil), d.Endpoints...)
		d.Token = append([]plan.Field(nil), d.Token...)
		c.edit(&d)
		_, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: New said %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := plan.New(f.decl(t), nil, f.roots); err == nil || !strings.Contains(err.Error(), "needs its sealed store") {
		t.Errorf("no store: New said %v", err)
	}
	d := f.decl(t)
	d.Pool = plan.Pool{}
	if _, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots); err != nil {
		t.Errorf("a declaration with no pool: %v", err)
	}
}

// Loading an empty at-rest form leaves the store empty (CLK-1).
func TestPlanStoreLoadsNothingAsEmpty(t *testing.T) {
	s := plan.NewStore(sealer(t), nil)
	s.Load([]byte("sealed"))
	s.Load(nil)
	if b, _ := s.MarshalBinary(); len(b) != 0 {
		t.Fatalf("an empty load kept %q", b)
	}
}

// Do refuses a request out of its declared form, each by its own answer,
// before anything is sent; a declared one goes as the declaration says: its
// query in the clerk's encoding, the declared headers only, the real token,
// and a body of known length (CLK-3, CLK-7).
func TestPlanDoHoldsTheRequestToItsForm(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ph := g.Tokens["access_token"]
	bearer := map[string]string{"Authorization": "Bearer " + ph}
	big := refreshBody(g.Tokens["refresh_token"]) + strings.Repeat(" ", 64<<10)
	n := f.hits()
	for name, c := range map[string]struct {
		r    *http.Request
		want string
	}{
		"a query that does not parse":    {req("GET", "/backend-api/codex/models?client_version=1&x=%zz", "", bearer), plan.DUndeclared},
		"an upgrade by Connection alone": {req("GET", "/backend-api/codex/models", "", map[string]string{"Authorization": "Bearer " + ph, "Connection": "keep-alive, Upgrade"}), plan.DUndeclared},
		"an undeclared path":             {req("POST", "/backend-api/codex/other", "{}", bearer), plan.DUndeclared},
		"an encoded body": {req("POST", "/backend-api/codex/responses", `{"model":"m","stream":true}`,
			map[string]string{"Authorization": "Bearer " + ph, "Content-Encoding": "gzip"}), plan.DEncoded},
		"a refresh past an exchange's bound": {req("POST", "/oauth/token", big, map[string]string{"Content-Type": "application/json"}), plan.DUndeclared},
		"a placeholder with no Bearer":       {req("GET", "/backend-api/codex/models", "", map[string]string{"Authorization": ph}), plan.DPlaceholder},
	} {
		if resp, d := p.Do(context.Background(), "g", c.r, free); resp != nil || d != c.want {
			t.Errorf("%s: %v %q, want %q", name, resp != nil, d, c.want)
		}
	}
	if f.hits() != n {
		t.Fatal("a refused request reached the provider")
	}
	h := map[string]string{"Authorization": "Bearer " + ph, "Originator": "codex_cli_rs", "Cookie": "c=1"}
	resp, d := p.Do(context.Background(), "g", req("GET", "/backend-api/codex/models?client_version=0.162.1", "", h), nil)
	if d != "" {
		t.Fatalf("models read: %s", d)
	}
	read(t, resp)
	if up, _ := f.last(); up.URL.RawQuery != "client_version=0.162.1" || up.Header.Get("Originator") != "codex_cli_rs" ||
		up.Header.Get("Cookie") != "" || up.Header.Get("Authorization") != "Bearer real-access-1" {
		t.Fatalf("the models read went as %q %v", up.URL.RawQuery, up.Header)
	}
	resp, d = p.Do(context.Background(), "g", req("POST", "/backend-api/codex/responses", `{"model":"m","stream":true}`, h), free)
	if d != "" {
		t.Fatalf("model call: %s", d)
	}
	read(t, resp)
	if up, body := f.last(); up.Header.Get("Authorization") != "Bearer real-access-1" || up.Header.Get("Originator") != "codex_cli_rs" ||
		up.ContentLength != int64(len(body)) {
		t.Fatalf("the model call went with length %d for %q, %v", up.ContentLength, body, up.Header)
	}
}

// A provider that cannot be reached answers no request: each kind gets the
// clerk's no-answer detail and nothing else (CLK-3).
func TestPlanUnreachableProviderAnswersNothing(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "s")
	f.srv.Close()
	for name, c := range map[string]struct {
		guest string
		r     *http.Request
	}{
		"a code exchange": {"s", formReq(form)},
		"a device step":   {"s", jsonReq("/api/accounts/deviceauth/usercode", `{"client_id":"app_x"}`)},
		"a refresh":       {"g", req("POST", "/oauth/token", refreshBody(g.Tokens["refresh_token"]), map[string]string{"Content-Type": "application/json"})},
		"a models read":   {"g", req("GET", "/backend-api/codex/models", "", map[string]string{"Authorization": "Bearer " + g.Tokens["access_token"]})},
	} {
		if resp, d := p.Do(context.Background(), c.guest, c.r, nil); resp != nil || !strings.HasPrefix(d, clerk.DNoAnswer) {
			t.Errorf("%s: %v %q", name, resp != nil, d)
		}
	}
}

// A dial the home-network policy denies is reported as blocked (DEV-2).
func TestPlanDeniedDialIsBlocked(t *testing.T) {
	f := newPlanFix(t)
	signIn(t, f.login(t), "signin")
	d := f.decl(t)
	d.Guard = netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("169.254.169.254"))})
	p, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	g, err := p.Guest("g")
	if err != nil {
		t.Fatal(err)
	}
	h := map[string]string{"Authorization": "Bearer " + g.Tokens["access_token"]}
	if resp, det := p.Do(context.Background(), "g", req("GET", "/backend-api/codex/models", "", h), nil); resp != nil || det != clerk.DBlocked {
		t.Fatalf("a denied dial: %v %q", resp != nil, det)
	}
}

// An answer that is encoded is dropped and closed, so the provider's
// connection does not stay open; one cut short is no answer (CLK-3).
func TestPlanEncodedOrCutAnswerIsDropped(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	closed, end := make(chan struct{}, 1), make(chan struct{})
	t.Cleanup(func() { close(end) })
	encoded := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(200)
		w.Write([]byte("x"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
			closed <- struct{}{}
		case <-end:
		}
	}
	f.stream, f.list = encoded, encoded
	var cut atomic.Bool
	f.answer = func(w http.ResponseWriter, r *http.Request, _ string) bool {
		if !cut.Load() {
			encoded(w, r)
			return true
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "100")
		w.Write([]byte(`{"access_token":`))
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler)
	}
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "s")
	ph := g.Tokens["access_token"]
	for name, do := range map[string]func() (*http.Response, string){
		"code exchange": func() (*http.Response, string) { return p.Do(context.Background(), "s", formReq(form), nil) },
		"model call":    func() (*http.Response, string) { return model(p, "g", ph) },
		"models read": func() (*http.Response, string) {
			return p.Do(context.Background(), "g", req("GET", "/backend-api/codex/models", "", map[string]string{"Authorization": "Bearer " + ph}), nil)
		},
		"refresh": func() (*http.Response, string) { return refreshReq(p, "g", g.Tokens["refresh_token"]) },
	} {
		if resp, d := do(); resp != nil || d != plan.DEncoded {
			t.Fatalf("an encoded %s answer: %v %q", name, resp != nil, d)
		}
		select {
		case <-closed:
		case <-time.After(5 * time.Second):
			t.Fatalf("the encoded %s answer was left open", name)
		}
	}
	cut.Store(true)
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || !strings.HasPrefix(d, clerk.DNoAnswer) {
		t.Fatalf("a refresh answer cut short: %v %q", resp != nil, d)
	}
}

// breakable is a connection whose writes can be made to fail.
type breakable struct {
	net.Conn
	broken atomic.Bool
}

func (c *breakable) Write(b []byte) (int, error) {
	if c.broken.Load() {
		return 0, errors.New("connection broken")
	}
	return c.Conn.Write(b)
}

// A model call whose reused connection fails before a byte is written is
// sent again, whole, on a new connection (CLK-3).
func TestPlanModelCallIsResentWhole(t *testing.T) {
	f := newPlanFix(t)
	var mu sync.Mutex
	var conns []*breakable
	d := f.decl(t)
	d.Guard = netguard.New(netguard.Config{Resolver: resolver(netip.MustParseAddr("8.8.8.8")), Connect: func(ctx context.Context, network, _ string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, f.srv.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		b := &breakable{Conn: c}
		mu.Lock()
		conns = append(conns, b)
		mu.Unlock()
		return b, nil
	}})
	p, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	resp, det := model(p, "g", g.Tokens["access_token"])
	if det != "" {
		t.Fatal(det)
	}
	read(t, resp)
	mu.Lock()
	for _, c := range conns {
		c.broken.Store(true)
	}
	n := len(conns)
	mu.Unlock()
	resp, det = model(p, "g", g.Tokens["access_token"])
	if det != "" {
		t.Fatalf("a model call on a broken connection: %q", det)
	}
	read(t, resp)
	mu.Lock()
	defer mu.Unlock()
	if _, body := f.last(); len(conns) == n || body != `{"model":"m","store":false,"stream":true}` {
		t.Fatalf("sent again on %d new connections as %q", len(conns)-n, body)
	}
}

// A device step goes to the provider as the clerk's own JSON, whatever type
// the guest named, with its text as written; its answer has a known length;
// a body that is not a JSON object, or an answer too large to read, passes
// nothing; and with no secret declared, an answer that is no JSON object is
// still dropped (CLK-1, CLK-3).
func TestPlanDeviceStepIsSentAndAnsweredAsJSON(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	const uc = "/api/accounts/deviceauth/usercode"
	resp, d := p.Do(context.Background(), "s", req("POST", uc, `{"client_id":"app<x>&"}`, map[string]string{"Content-Type": "text/plain"}), nil)
	if d != "" {
		t.Fatalf("usercode: %s", d)
	}
	if body := read(t, resp); resp.ContentLength != int64(len(body)) {
		t.Fatalf("the answer's length is %d for %d bytes", resp.ContentLength, len(body))
	}
	if up, sent := f.last(); up.Header.Get("Content-Type") != "application/json" || sent != `{"client_id":"app<x>&"}` {
		t.Fatalf("the device step went as %q %q", up.Header.Get("Content-Type"), sent)
	}
	if resp, d := p.Do(context.Background(), "s", jsonReq(uc, "client_id=app_x"), nil); resp != nil || d != plan.DUndeclared {
		t.Fatalf("a body that is no JSON object: %v %q", resp != nil, d)
	}
	f.usercode = func(w http.ResponseWriter) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"device_auth_id":"real-device-1","user_code":"ABCD-1234","pad":"` + strings.Repeat("x", 64<<10) + `"}`))
		return true
	}
	if resp, d := p.Do(context.Background(), "s", jsonReq(uc, `{"client_id":"app_x"}`), nil); resp != nil || d != plan.DUndeclared {
		t.Fatalf("an answer too large to read: %v %q", resp != nil, d)
	}
	dc := f.decl(t)
	dc.Endpoints[3].Secret, dc.Endpoints[4].Takes = nil, nil
	q, err := plan.New(dc, plan.NewStore(sealer(t), nil), f.roots)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	f.usercode = func(w http.ResponseWriter) bool {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not json"))
		return true
	}
	if resp, d := q.Do(context.Background(), "s", jsonReq(uc, `{"client_id":"app_x"}`), nil); resp != nil || d != plan.DSecret {
		t.Fatalf("an answer that is no JSON object: %v %q", resp != nil, d)
	}
}

// A code exchange passes only in its exact form: the form type, each key
// once, no other key; it goes to the provider as a form of that exact type
// (CLK-1).
func TestPlanCodeExchangeIsHeldToItsForm(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	if err := p.BeginSignIn("s"); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, "s")
	ct := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	n := f.exchanges.Load()
	for name, r := range map[string]*http.Request{
		"another type":  req("POST", "/oauth/token", form, map[string]string{"Content-Type": "text/plain"}),
		"an extra key":  req("POST", "/oauth/token", form+"&scope=x", ct),
		"a key twice":   req("POST", "/oauth/token", form+"&code=x", ct),
		"an empty form": req("POST", "/oauth/token", "", ct),
	} {
		if resp, d := p.Do(context.Background(), "s", r, nil); resp != nil || d != plan.DUndeclared {
			t.Errorf("%s: %v %q", name, resp != nil, d)
		}
	}
	if f.exchanges.Load() != n {
		t.Fatal("a code exchange out of form was sent")
	}
	resp, d := p.Do(context.Background(), "s", req("POST", "/oauth/token", form, map[string]string{"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}), nil)
	if d != "" {
		t.Fatalf("code exchange: %s", d)
	}
	read(t, resp)
	if up, _ := f.last(); up.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("the code exchange went as %q", up.Header.Get("Content-Type"))
	}
}

// A token answer is held to its declared shape: JSON, with an id_token
// whose account claim reads whole and within its bound, and both tokens a
// login needs; a declared flag passes (CLK-7).
func TestPlanTokenAnswerIsHeldToItsShape(t *testing.T) {
	f := newPlanFix(t)
	d := f.decl(t)
	d.Token = append(d.Token, plan.Field{Name: "fresh", Kind: plan.FieldBool, Optional: true})
	claims, _ := json.Marshal(map[string]any{"https://api.openai.com/auth": map[string]string{"chatgpt_account_id": "acct-1"}})
	for len(claims)%3 != 0 {
		claims = append(claims, ' ')
	}
	cut := "e30." + base64.RawURLEncoding.EncodeToString(claims) + "*.sig"
	tok := func(id string, drop string, add map[string]any) string {
		m := map[string]any{"access_token": "real-access-9", "refresh_token": "real-refresh-9", "id_token": id}
		delete(m, drop)
		for k, v := range add {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, c := range []struct {
		name, ct, body, want string
	}{
		{"an id_token cut short", "application/json", tok(cut, "", nil), plan.DUnswappable},
		{"an account past its bound", "application/json", tok(idToken(strings.Repeat("a", 257)), "", nil), plan.DUnswappable},
		{"an answer that is not JSON", "text/plain", tok(idToken("acct-1"), "", nil), plan.DUnswappable},
		{"no refresh token", "application/json", tok(idToken("acct-1"), "refresh_token", nil), plan.DUnswappable},
		{"a declared flag", "application/json", tok(idToken("acct-1"), "", map[string]any{"fresh": true}), ""},
	} {
		p, err := plan.New(d, plan.NewStore(sealer(t), nil), f.roots)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.BeginSignIn("s"); err != nil {
			t.Fatal(err)
		}
		form := deviceSteps(t, p, "s")
		f.answer = func(w http.ResponseWriter, _ *http.Request, _ string) bool {
			w.Header().Set("Content-Type", c.ct)
			w.Write([]byte(c.body))
			return true
		}
		resp, det := p.Do(context.Background(), "s", formReq(form), nil)
		if det != c.want || (resp != nil) != (c.want == "") {
			t.Errorf("%s: %v %q, want %q", c.name, resp != nil, det, c.want)
		}
		if resp != nil {
			read(t, resp)
		}
	}
	f.answer = nil
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	f.answerWith(200, tok(idToken("acct-1"), "access_token", nil))
	if resp, det := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || det != plan.DUnswappable {
		t.Fatalf("a refresh answer with no access token: %v %q", resp != nil, det)
	}
}

// A guest has a name, and its id_token placeholder carries an expiry the
// CLI reads as live.
func TestPlanGuestNamesAndItsIDTokenExpiry(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	if _, err := p.Guest(""); err == nil {
		t.Fatal("a guest with no name got tokens")
	}
	if err := p.BeginSignIn(""); err == nil || p.Signing("") {
		t.Fatal("a sign-in guest with no name began")
	}
	g, _ := p.Guest("g")
	parts := strings.Split(g.Tokens["id_token"], ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.Exp < time.Now().Add(364*24*time.Hour).Unix() {
		t.Fatalf("the id_token placeholder's claims %s (%v)", raw, err)
	}
}

// A slot that does not open lets nothing through: Stopped reads it as
// unswappable, Guest and Resume return its error, and a commit drops the
// answer (CLK-1).
func TestPlanSlotThatDoesNotOpenHoldsAll(t *testing.T) {
	f := newPlanFix(t)
	s := &sealProbe{Sealer: f.seal}
	f.sec = plan.NewStore(s, nil)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	failIn := func(m string) {
		s.mu.Lock()
		s.failIn = m
		s.mu.Unlock()
	}
	failIn("Guest")
	if _, err := p.Guest("g"); err == nil || errors.Is(err, plan.ErrNoLogin) {
		t.Fatalf("a slot that did not open for Guest: %v", err)
	}
	failIn("swap")
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != plan.DSave {
		t.Fatalf("a commit to a slot that did not open: %v %q", resp != nil, d)
	}
	failIn("")
	s.failOpen.Store(true)
	if st := p.Stopped(); st != plan.StopUnswappable {
		t.Fatalf("a slot that does not open reads as %q", st)
	}
	if err := p.Resume(); err == nil {
		t.Fatal("Resume read a slot that does not open")
	}
}

// outOfShapeSignIn has a new sign-in guest's code exchange answered out of
// shape, which stops the route as unswappable.
func outOfShapeSignIn(t *testing.T, f *planFix, p *plan.Login, guest string) {
	t.Helper()
	if err := p.BeginSignIn(guest); err != nil {
		t.Fatal(err)
	}
	form := deviceSteps(t, p, guest)
	f.answerWith(200, `{"access_token":"x"}`)
	if resp, d := p.Do(context.Background(), guest, formReq(form), nil); resp != nil || d != plan.DUnswappable {
		t.Fatalf("an out-of-shape sign-in: %v %q", resp != nil, d)
	}
}

const refusedBody = `{"error":{"code":"refresh_token_expired"}}`

// An unswappable stop outranks a refusal already recorded, and removing the
// login keeps it: only the stop is stored (CLK-7).
func TestPlanUnswappableOutranksARefusal(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	f.answerWith(401, refusedBody)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	if p.Stopped() != plan.StopRefused {
		t.Fatalf("Stopped = %q, want refused", p.Stopped())
	}
	outOfShapeSignIn(t, f, p, "s2")
	if p.Stopped() != plan.StopUnswappable {
		t.Fatalf("an unswappable stop over a refusal reads %q", p.Stopped())
	}
	if err := p.Remove(); err != nil || p.Signed() || p.Stopped() != plan.StopUnswappable {
		t.Fatalf("Remove under an unswappable stop: %v, signed %v, %q", err, p.Signed(), p.Stopped())
	}
}

// A refresh the provider answers after the route was stopped as
// unswappable changes nothing: a good answer is not committed, and a
// refusal does not rewrite the stop (CLK-7).
func TestPlanRefreshAnsweredAfterAnUnswappableStop(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		want   string
	}{
		{"a good answer", 200, plan.DStopped + " " + plan.StopUnswappable},
		{"a refusal", 401, plan.DExchange + " http 401"},
	} {
		f := newPlanFix(t)
		p := f.login(t)
		signIn(t, p, "signin")
		g, _ := p.Guest("g")
		hold := make(chan struct{})
		f.answer = func(w http.ResponseWriter, r *http.Request, _ string) bool {
			w.Header().Set("Content-Type", "application/json")
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
				w.Write([]byte(`{"access_token":"x"}`)) // the sign-in's exchange: out of shape
				return true
			}
			<-hold
			if c.status == 200 {
				return false
			}
			w.WriteHeader(c.status)
			w.Write([]byte(refusedBody))
			return true
		}
		n := f.exchanges.Load()
		got := make(chan string, 1)
		go func() {
			resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
			if resp != nil {
				resp.Body.Close()
			}
			got <- d
		}()
		for f.exchanges.Load() == n {
			time.Sleep(time.Millisecond)
		}
		if err := p.BeginSignIn("s2"); err != nil {
			t.Fatal(err)
		}
		form := deviceSteps(t, p, "s2")
		if resp, d := p.Do(context.Background(), "s2", formReq(form), nil); resp != nil || d != plan.DUnswappable {
			t.Fatalf("an out-of-shape sign-in: %v %q", resp != nil, d)
		}
		before, _ := f.sec.MarshalBinary()
		close(hold)
		if d := <-got; d != c.want {
			t.Errorf("%s: the refresh got %q, want %q", c.name, d, c.want)
		}
		if after, _ := f.sec.MarshalBinary(); !bytes.Equal(before, after) {
			t.Errorf("%s: an answer to a stopped route rewrote the slot", c.name)
		}
	}
}

// Remove and Resume clear what they own: a Remove that cannot be written
// changes nothing; a refusal the slot could not record is held until
// Resume; one it recorded goes with the login, and so do the sign-in marks,
// the user code and every placeholder (CLK-1, CH-10).
func TestPlanRemoveAndResumeClearWhatTheyOwn(t *testing.T) {
	f := newPlanFix(t)
	var fail atomic.Bool
	f.sec = plan.NewStore(sealer(t), func([]byte) error {
		if fail.Load() {
			return errors.New("disk full")
		}
		return nil
	})
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	fail.Store(true)
	var err error
	returns(t, "a Remove that cannot be written", func() { err = p.Remove() })
	if err == nil || !p.Signed() {
		t.Fatalf("a Remove that cannot be written: %v, signed %v", err, p.Signed())
	}
	fail.Store(false)
	resp, d := model(p, "g", g.Tokens["access_token"])
	if d != "" {
		t.Fatalf("the placeholders went with a Remove that failed: %q", d)
	}
	read(t, resp)

	fail.Store(true)
	f.answerWith(401, refusedBody)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	fail.Store(false)
	if p.Stopped() != plan.StopRefused {
		t.Fatalf("Stopped = %q, want a held refusal", p.Stopped())
	}
	if err := p.Resume(); err != nil || p.Stopped() != "" {
		t.Fatalf("Resume left %q (%v)", p.Stopped(), err)
	}

	f.answerWith(401, refusedBody)
	refreshReq(p, "g", g.Tokens["refresh_token"])
	if p.Stopped() != plan.StopRefused || p.UserCode("signin") == "" || !p.Signing("signin") {
		t.Fatalf("before Remove: %q %q %v", p.Stopped(), p.UserCode("signin"), p.Signing("signin"))
	}
	if err := p.Remove(); err != nil || p.Stopped() != "" || p.Signing("signin") || p.UserCode("signin") != "" {
		t.Fatalf("after Remove: %v %q %q %v", err, p.Stopped(), p.UserCode("signin"), p.Signing("signin"))
	}
	signIn(t, p, "signin-2")
	if resp, d := model(p, "g", g.Tokens["access_token"]); resp != nil || d != plan.DPlaceholder {
		t.Fatalf("a placeholder from before Remove: %v %q", resp != nil, d)
	}
}

// A refresh with another guest's placeholder is refused at once, even while
// a refresh of the login is in flight: it never joins it. A guest that
// joined a flight and gives up gets its own answer at once (CLK-7).
func TestPlanRefreshJoinsAFlightOnlyAsItsOwnGuest(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	a, _ := p.Guest("a")
	b, _ := p.Guest("b")
	f.gate = make(chan struct{})
	n := f.exchanges.Load()
	led := make(chan string, 1)
	go func() {
		resp, d := refreshReq(p, "a", a.Tokens["refresh_token"])
		if resp != nil {
			resp.Body.Close()
		}
		led <- d
	}()
	for f.exchanges.Load() == n {
		time.Sleep(time.Millisecond)
	}
	returns(t, "a refresh with another guest's placeholder", func() {
		if resp, d := refreshReq(p, "b", a.Tokens["refresh_token"]); resp != nil || d != plan.DPlaceholder {
			t.Errorf("another guest's placeholder: %v %q", resp != nil, d)
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	joined := make(chan string, 1)
	go func() {
		resp, d := p.Do(ctx, "b", req("POST", "/oauth/token", refreshBody(b.Tokens["refresh_token"]), map[string]string{"Content-Type": "application/json"}), nil)
		if resp != nil {
			resp.Body.Close()
		}
		joined <- d
	}()
	cancel()
	returns(t, "a joined refresh that gave up", func() {
		if d := <-joined; d != plan.DExchange {
			t.Errorf("a joined refresh that gave up got %q", d)
		}
	})
	close(f.gate)
	if d := <-led; d != "" {
		t.Fatalf("the flight's leader got %q", d)
	}
}

// A refresh whose caller gave up before its flight ended still gets the
// answer it led, every time (ASSUMPTIONS a7).
func TestPlanCancelledLeaderGetsItsAnswer(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := range 24 {
		resp, d := p.Do(ctx, "g", req("POST", "/oauth/token", refreshBody(g.Tokens["refresh_token"]), map[string]string{"Content-Type": "application/json"}), nil)
		if resp == nil {
			t.Fatalf("refresh %d, led by a caller that gave up: %q", i, d)
		}
		read(t, resp)
	}
}

// A refresh is checked again inside its flight: a login removed after the
// first check sends nothing (CLK-7).
func TestPlanRefreshIsRecheckedInItsFlight(t *testing.T) {
	f := newPlanFix(t)
	s := &sealProbe{Sealer: f.seal}
	f.sec = plan.NewStore(s, nil)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	var once sync.Once
	s.mu.Lock()
	s.onOpen = func(by string) {
		if by == "resolve" {
			once.Do(func() { p.Remove() })
		}
	}
	s.mu.Unlock()
	n := f.exchanges.Load()
	if resp, d := refreshReq(p, "g", g.Tokens["refresh_token"]); resp != nil || d != plan.DPlaceholder {
		t.Fatalf("a refresh of a login removed after its check: %v %q", resp != nil, d)
	}
	if f.exchanges.Load() != n {
		t.Fatal("a refresh of a removed login was sent")
	}
}

// waitLocked waits until a goroutine in fn waits on a mutex.
func waitLocked(t *testing.T, fn string) {
	t.Helper()
	buf := make([]byte, 1<<20)
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
			if strings.Contains(g, "[sync.Mutex.Lock") && strings.Contains(g, fn) {
				return
			}
		}
	}
	t.Fatalf("no goroutine in %s waited on a lock", fn)
}

// A refresh answer that waited for the commit lock while the owner removed
// the login is stale once it holds the lock: it stops nothing (CLK-7).
func TestPlanRefreshIsStaleOnceItHoldsTheCommitLock(t *testing.T) {
	f := newPlanFix(t)
	s := &sealProbe{Sealer: f.seal}
	f.sec = plan.NewStore(s, nil)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	hold := make(chan struct{})
	f.answer = func(http.ResponseWriter, *http.Request, string) bool { <-hold; return false }
	n := f.exchanges.Load()
	got := make(chan string, 1)
	go func() {
		resp, d := refreshReq(p, "g", g.Tokens["refresh_token"])
		if resp != nil {
			resp.Body.Close()
		}
		got <- d
	}()
	for f.exchanges.Load() == n {
		time.Sleep(time.Millisecond)
	}
	var once sync.Once
	s.mu.Lock()
	s.onOpen = func(by string) {
		if by == "Remove" {
			once.Do(func() {
				close(hold)
				waitLocked(t, ".(*Login).swap(")
			})
		}
	}
	s.mu.Unlock()
	if err := p.Remove(); err != nil {
		t.Fatal(err)
	}
	if d := <-got; d != plan.DStale || p.Stopped() != "" {
		t.Fatalf("a refresh answer to a login removed meanwhile: %q, stopped %q", d, p.Stopped())
	}
}

// deep is a value nested n objects deep.
func deep(n int) any {
	var v any = "x"
	for range n {
		v = map[string]any{"a": v}
	}
	return v
}

// A model body is held to each rule of its shape on its own, wherever the
// value sits (PLN-5(a), CLK-7).
func TestPlanModelBodyHeldToEachRule(t *testing.T) {
	f := newPlanFix(t)
	p := f.login(t)
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	ns := func(tools ...any) []any {
		return []any{map[string]any{"type": "namespace", "name": "functions", "tools": tools}}
	}
	msg := func(k string, v any) []any { return []any{map[string]any{"type": "message", "role": "user", k: v}} }
	tools := map[string]any{"tools": []any{}}
	for _, c := range []struct {
		name, want string
		edit       func(m map[string]any)
	}{
		{"a tool choice of a declared type", "", func(m map[string]any) { m["tool_choice"] = map[string]any{"type": "function"} }},
		{"a tool choice that is a number", "choice", func(m map[string]any) { m["tool_choice"] = 5 }},
		{"input that is text", "input", func(m map[string]any) { m["input"] = "x" }},
		{"an input item that is text", "input", func(m map[string]any) { m["input"] = []any{"x"} }},
		{"tools inside an input item", "tool", func(m map[string]any) { m["input"] = msg("meta", tools) }},
		{"additional_tools with no tools", "input", func(m map[string]any) { m["input"] = []any{map[string]any{"type": "additional_tools"}} }},
		{"content that is a number", "content", func(m map[string]any) { m["input"] = msg("content", 5) }},
		{"a content part that is text", "content", func(m map[string]any) { m["input"] = msg("content", []any{"x"}) }},
		{"tools inside a content part", "tool", func(m map[string]any) {
			m["input"] = msg("content", []any{map[string]any{"type": "input_text", "meta": tools}})
		}},
		{"tools that are an object", "tool", func(m map[string]any) { m["tools"] = map[string]any{} }},
		{"a tool that is text", "tool", func(m map[string]any) { m["tools"] = []any{"x"} }},
		{"tools inside a list", "tool", func(m map[string]any) { m["include"] = []any{tools} }},
		{"a function schema nested too deep", "depth", func(m map[string]any) {
			m["text"] = map[string]any{"type": "function", "parameters": deep(40)}
		}},
		{"a tool nested too deep", "depth", func(m map[string]any) {
			m["tools"] = ns(map[string]any{"type": "custom", "name": "exec", "format": deep(40)})
		}},
		{"an address in a function's schema", "", func(m map[string]any) {
			m["tools"] = ns(map[string]any{"type": "function", "name": "wait",
				"parameters": map[string]any{"examples": []any{map[string]any{"url": "https://example.com/x"}}}})
		}},
	} {
		m := capture(t)
		c.edit(m)
		want := ""
		if c.want != "" {
			want = plan.DBody + " " + c.want
		}
		resp, d := callWith(p, "g", g.Tokens["access_token"], encode(t, m), free)
		if d != want {
			t.Errorf("%s: %q, want %q", c.name, d, want)
		}
		if resp != nil {
			read(t, resp)
		}
	}
}

// A JSON text in client_metadata is one JSON value: an empty text is
// refused even where the shape inside admits null.
func TestPlanMetadataJSONTextIsOneValue(t *testing.T) {
	f := newPlanFix(t)
	d := f.decl(t)
	d.Body.Meta = map[string]plan.Value{"j": {Kind: plan.KindJSON, Max: 64, Each: &plan.Value{Kind: plan.KindBool, Null: true}}}
	p, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	for v, want := range map[string]string{"true": "", "null": "", "": plan.DBody + " meta"} {
		body := encode(t, map[string]any{"model": "m", "stream": true, "client_metadata": map[string]any{"j": v}})
		resp, det := callWith(p, "g", g.Tokens["access_token"], body, free)
		if det != want {
			t.Errorf("client_metadata %q: %q, want %q", v, det, want)
		}
		if resp != nil {
			read(t, resp)
		}
	}
}

// An input item or a content part that is no object is refused, even under
// a declaration that lists an empty type (PLN-5(a)).
func TestPlanBodyItemsAreObjects(t *testing.T) {
	f := newPlanFix(t)
	d := f.decl(t)
	d.Body.InputTypes = append(d.Body.InputTypes, "")
	d.Body.ContentTypes = append(d.Body.ContentTypes, "")
	p, err := plan.New(d, f.sec, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	signIn(t, p, "signin")
	g, _ := p.Guest("g")
	for name, c := range map[string]struct {
		input any
		want  string
	}{
		"an input item that is text":  {[]any{"x"}, "input"},
		"a content part that is text": {[]any{map[string]any{"type": "message", "role": "user", "content": []any{"x"}}}, "content"},
	} {
		body := encode(t, map[string]any{"model": "m", "stream": true, "input": c.input})
		if resp, det := callWith(p, "g", g.Tokens["access_token"], body, free); resp != nil || det != plan.DBody+" "+c.want {
			t.Errorf("%s: %v %q", name, resp != nil, det)
		}
	}
}
