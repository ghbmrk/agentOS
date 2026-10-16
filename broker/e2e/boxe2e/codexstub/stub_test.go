package codexstub

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: HW-10, CRED-5

// serve runs s on a fresh unix socket and returns its path.
func serve(t *testing.T, s *Stub) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "codexstub")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

type recordRT struct {
	mu   sync.Mutex
	urls []string
}

func (f *recordRT) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.urls = append(f.urls, r.URL.String())
	f.mu.Unlock()
	return &http.Response{StatusCode: 599, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
}

type noAudit struct{}

func (noAudit) Egress(egress.Event) {}

type rig struct {
	stub   *Stub
	logins *egress.PlanLogins
	rt     http.RoundTripper
	other  *recordRT
	usage  egress.PlanUsage
}

func newRig(t *testing.T) *rig {
	t.Helper()
	v, err := vault.Create(filepath.Join(t.TempDir(), "vault"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { v.Close() })
	r := &rig{stub: New(), other: &recordRT{}}
	r.logins = egress.NewPlanLogins(func() (egress.LoginStore, error) { return v, nil }, map[string]string{})
	r.rt = Transport(serve(t, r.stub), r.other)
	return r
}

// route is the shipped egress worker route for worker, reaching the
// provider through the e2e transport.
func (r *rig) route(t *testing.T, worker string, signIn bool) http.Handler {
	t.Helper()
	h, err := egress.NewWorkerRoute(egress.WorkerRouteConfig{
		Route: egress.Codex(), Worker: worker, SignIn: signIn, Logins: r.logins, Transport: r.rt, Audit: noAudit{},
		Quota: r.usage.Quota,
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func call(h http.Handler, method, path, ctype, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:18432"+path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// signIn drives the CLI's device-code sign-in through the sign-in route.
func (r *rig) signIn(t *testing.T) {
	t.Helper()
	h := r.route(t, "signin", true)
	w := call(h, "POST", "/api/accounts/deviceauth/usercode", "application/json", `{"client_id":"app_synthetic"}`)
	var uc struct{ Device, User, Interval string }
	if w.Code != 200 {
		t.Fatalf("usercode: %d %s", w.Code, w.Body)
	}
	var raw map[string]string
	json.Unmarshal(w.Body.Bytes(), &raw)
	uc.Device, uc.User = raw["device_auth_id"], raw["user_code"]
	if _, _, err := egress.Codex().SignInLink("http://127.0.0.1:18432/codex/device", uc.User); err != nil {
		t.Fatalf("user code %q: %v", uc.User, err)
	}
	poll := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"device_auth_id": uc.Device, "user_code": uc.User})
		return call(h, "POST", "/api/accounts/deviceauth/token", "application/json", string(b))
	}
	if w := poll(); w.Code != http.StatusForbidden {
		t.Fatalf("poll before approval: %d %s", w.Code, w.Body)
	}
	if r.stub.Approve("WRONG-CODE") || !r.stub.Approve(uc.User) {
		t.Fatal("approve")
	}
	w = poll()
	var ct map[string]string
	if json.Unmarshal(w.Body.Bytes(), &ct); w.Code != 200 || ct["authorization_code"] == "" {
		t.Fatalf("poll after approval: %d %s", w.Code, w.Body)
	}
	f := url.Values{
		"client_id": {"app_synthetic"}, "code": {ct["authorization_code"]}, "code_verifier": {ct["code_verifier"]},
		"grant_type": {"authorization_code"}, "redirect_uri": {"http://127.0.0.1:18432/deviceauth/callback"},
	}
	w = call(h, "POST", "/oauth/token", "application/x-www-form-urlencoded", f.Encode())
	if w.Code != 200 {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	for _, v := range r.stub.Tokens() {
		if strings.Contains(w.Body.String(), v) {
			t.Fatal("an issued token reached the sign-in worker")
		}
	}
}

// The shipped worker route signs in and runs against the stub through the
// e2e transport: the real tokens reach only the stub, placeholders reach
// only the worker, and a responses call streams Answer back.
func TestRouteSignsInAndRunsAgainstTheStub(t *testing.T) {
	r := newRig(t)
	r.signIn(t)

	var auth struct{ Tokens map[string]string }
	b, err := r.logins.AuthJSON("codex", "w1")
	if err != nil || json.Unmarshal(b, &auth) != nil {
		t.Fatalf("auth file: %v", err)
	}
	ph := auth.Tokens
	for _, v := range r.stub.Tokens() {
		if bytes.Contains(b, []byte(v)) {
			t.Fatal("the worker's auth file holds an issued token")
		}
	}
	h := r.route(t, "w1", false)
	bearer := []string{"Authorization", "Bearer " + ph["access_token"], "Chatgpt-Account-Id", ph["account_id"]}
	if w := call(h, "GET", "/backend-api/codex/models?client_version=0.1.0", "", "", bearer...); w.Code != 200 {
		t.Fatalf("models: %d %s", w.Code, w.Body)
	}
	body := `{"model":"gpt-x","stream":true,"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}]}`
	w := call(h, "POST", "/backend-api/codex/responses", "application/json", body, bearer...)
	if w.Code != 200 || !strings.Contains(w.Body.String(), Answer) || !strings.Contains(w.Body.String(), "response.completed") {
		t.Fatalf("responses: %d %s", w.Code, w.Body)
	}

	// A refresh rotates the token set; the old access token stops working.
	// Tokens keeps listing every token issued before it, the first
	// sign-in's id_token included, and every id_token carries the canary.
	old, before := r.stub.Tokens()[0], r.stub.Tokens()
	rb, _ := json.Marshal(map[string]string{"client_id": "app_synthetic", "grant_type": "refresh_token", "refresh_token": ph["refresh_token"], "scope": "openid profile email"})
	if w := call(h, "POST", "/oauth/token", "application/json", string(rb)); w.Code != 200 || strings.Contains(w.Body.String(), Canary) {
		t.Fatalf("refresh: %d %s", w.Code, w.Body)
	}
	if r.stub.Tokens()[0] == old {
		t.Fatal("refresh did not rotate")
	}
	after := strings.Join(r.stub.Tokens(), "\n")
	for _, v := range before {
		if !strings.Contains(after, v) {
			t.Fatal("Tokens forgot a token issued before the refresh")
		}
	}
	ids := 0
	for _, v := range r.stub.Tokens() {
		if strings.Count(v, ".") == 2 && !strings.HasPrefix(v, Canary) {
			ids++
			if !strings.Contains(v, Canary) {
				t.Fatal("an id_token carries no canary")
			}
		}
	}
	if ids != 2 {
		t.Fatalf("Tokens lists %d id_tokens after a sign-in and a refresh, not 2", ids)
	}
	b, _ = r.logins.AuthJSON("codex", "w1")
	json.Unmarshal(b, &auth)
	bearer = []string{"Authorization", "Bearer " + auth.Tokens["access_token"], "Chatgpt-Account-Id", auth.Tokens["account_id"]}
	if w := call(h, "POST", "/backend-api/codex/responses", "application/json", body, bearer...); w.Code != 200 {
		t.Fatalf("responses after refresh: %d %s", w.Code, w.Body)
	}

	hits := r.stub.Hits()
	for _, ep := range egress.Codex().Endpoints {
		if hits[ep.Name] == 0 {
			t.Errorf("endpoint %s never reached the stub: %v", ep.Name, hits)
		}
	}
	if r.stub.Refused() != 0 || len(r.other.urls) != 0 {
		t.Fatalf("refused %d, off-stub %v", r.stub.Refused(), r.other.urls)
	}

	// A run call without the account's Chatgpt-Account-Id, or with another
	// account's, is refused, as a route that dropped the header would be.
	for _, acct := range []string{"", "acct-other"} {
		hdr := []string{"Authorization", "Bearer " + auth.Tokens["access_token"]}
		if acct != "" {
			hdr = append(hdr, "Chatgpt-Account-Id", acct)
		}
		if w := call(h, "POST", "/backend-api/codex/responses", "application/json", body, hdr...); w.Code != http.StatusUnauthorized {
			t.Fatalf("responses with account %q: %d %s", acct, w.Code, w.Body)
		}
	}
	if r.stub.Refused() != 2 {
		t.Fatalf("refused %d", r.stub.Refused())
	}
}

// REQ: RES-5
// A run call through the shipped worker route carries the stub's quota
// headers, and the route reads both pools into the plan's usage, as the
// owner's quota reading before a first run does (#1856). Sign-in calls
// carry none and read nothing.
func TestRunCallsReportThePlanQuota(t *testing.T) {
	r := newRig(t)
	r.signIn(t)
	if s := r.usage.Snapshot("codex"); len(s.Pools) != 0 {
		t.Fatalf("sign-in read quota: %+v", s.Pools)
	}
	b, _ := r.logins.AuthJSON("codex", "w1")
	var auth struct{ Tokens map[string]string }
	json.Unmarshal(b, &auth)
	bearer := []string{"Authorization", "Bearer " + auth.Tokens["access_token"], "Chatgpt-Account-Id", auth.Tokens["account_id"]}
	body := `{"model":"gpt-x","stream":true,"input":[]}`
	before := time.Now().Unix()
	w := call(r.route(t, "w1", false), "POST", "/backend-api/codex/responses", "application/json", body, bearer...)
	if w.Code != 200 || w.Header().Get("X-Codex-Primary-Used-Percent") != "12.5" {
		t.Fatalf("responses: %d %v", w.Code, w.Header())
	}
	want := map[string]struct {
		used   float64
		window int
	}{"primary": {PrimaryUsedPercent, PrimaryWindowMinutes}, "secondary": {WeeklyUsedPercent, WeeklyWindowMinutes}}
	pools := r.usage.Snapshot("codex").Pools
	if len(pools) != len(want) {
		t.Fatalf("pools %+v", pools)
	}
	for _, q := range pools {
		wq, ok := want[q.Pool]
		if !ok || q.UsedPercent != wq.used || q.WindowMinutes != wq.window || q.Exhausted || q.Worker != "w1" ||
			q.ResetAt < before+int64(wq.window)*60 || q.ResetAt > time.Now().Unix()+int64(wq.window)*60 {
			t.Errorf("pool %+v, want %+v", q, wq)
		}
	}
	if r.stub.Refused() != 0 {
		t.Fatalf("refused %d", r.stub.Refused())
	}
}

// The stub refuses what the provider would: an undeclared path, a token
// it did not issue (a placeholder), and an exchange whose redirect was not
// rewritten to the auth host.
func TestStubRefuses(t *testing.T) {
	s := New()
	do := func(host, method, path, ctype, body string, hdr ...string) int {
		req := httptest.NewRequest(method, "https://"+host+path, strings.NewReader(body))
		req.Host = host
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		return w.Code
	}
	cases := []struct {
		host, method, path, ctype, body string
		hdr                             []string
		want                            int
	}{
		{"chatgpt.com", "GET", "/backend-api/other", "", "", nil, 404},
		{"auth.openai.com", "POST", "/backend-api/codex/responses", "application/json", "{}", nil, 404},
		{"chatgpt.com", "POST", "/backend-api/codex/responses", "application/json", `{"stream":true}`, []string{"Authorization", "Bearer agentos-ph-access-x"}, 401},
		{"chatgpt.com", "GET", "/backend-api/codex/models", "", "", nil, 401},
		{"auth.openai.com", "POST", "/api/accounts/deviceauth/token", "application/json", `{"device_auth_id":"x","user_code":"y"}`, nil, 401},
		{"auth.openai.com", "POST", "/oauth/token", "application/json", `{"grant_type":"refresh_token","refresh_token":"x"}`, nil, 401},
	}
	for _, c := range cases {
		if got := do(c.host, c.method, c.path, c.ctype, c.body, c.hdr...); got != c.want {
			t.Errorf("%s %s%s: %d, want %d", c.method, c.host, c.path, got, c.want)
		}
	}

	// A code exchange with the forwarder's own callback, as a route that
	// skipped the rewrite would send it, is refused.
	s.code, s.verify = "c", "v"
	f := url.Values{"grant_type": {"authorization_code"}, "code": {"c"}, "code_verifier": {"v"}, "redirect_uri": {"http://127.0.0.1:18432/deviceauth/callback"}}
	if got := do("auth.openai.com", "POST", "/oauth/token", "application/x-www-form-urlencoded", f.Encode()); got != 401 {
		t.Fatalf("unrewritten redirect: %d", got)
	}
	if s.Hits()["code"] != 0 || s.Refused() != len(cases)+1 {
		t.Fatalf("hits %v refused %d", s.Hits(), s.Refused())
	}
}

// Only requests for the Codex hosts go to the stub, matched by host name
// whatever the port; one on a scheme other than https fails rather than
// reaching the fallback. Every other request goes to the fallback, so the
// e2e build changes nothing else.
func TestTransportSendsOnlyCodexHostsToTheStub(t *testing.T) {
	r := newRig(t)
	for _, u := range []string{"https://example.com/x", "https://api.openai.com/v1/responses", "https://chatgpt.com.evil.example/", "https://example.com:443/chatgpt.com"} {
		req := httptest.NewRequest("GET", u, nil)
		resp, err := r.rt.RoundTrip(req)
		if err != nil || resp.StatusCode != 599 {
			t.Fatalf("%s: %v %v", u, resp, err)
		}
	}
	for _, u := range []string{"http://chatgpt.com/backend-api/codex/models", "http://auth.openai.com:80/oauth/token", "ftp://chatgpt.com:443/x"} {
		req := httptest.NewRequest("GET", u, nil)
		if resp, err := r.rt.RoundTrip(req); err == nil {
			t.Fatalf("%s: %v, want an error", u, resp.StatusCode)
		}
	}
	if len(r.other.urls) != 4 || r.stub.Refused() != 0 {
		t.Fatalf("fallback %v, stub refused %d", r.other.urls, r.stub.Refused())
	}
	for i, u := range []string{"https://chatgpt.com/nothing", "https://chatgpt.com:443/nothing", "https://CHATGPT.com:8443/nothing", "https://auth.openai.com:443/nothing"} {
		req := httptest.NewRequest("GET", u, nil)
		resp, err := r.rt.RoundTrip(req)
		if err != nil || resp.StatusCode != 404 || r.stub.Refused() != i+1 {
			t.Fatalf("%s: %v %v, stub refused %d", u, resp, err, r.stub.Refused())
		}
	}
	if len(r.other.urls) != 4 {
		t.Fatalf("fallback %v", r.other.urls)
	}
}
