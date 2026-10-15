package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: CRED-5, CRED-1, A14, A3, ADP-10, DEV-2, E12, RES-5, OP-8

// fakeLogins stands in for the vault's plan logins (#1015): one real token
// set per provider, and the placeholders each worker holds instead.
type fakeLogins struct {
	mu      sync.Mutex
	real    map[string]string // field -> real value
	ph      map[string]string // placeholder -> field, for worker "w1"
	commits int
	signIns int
	swapErr error
	// commitErr makes the vault write fail after a good swap.
	commitErr error
	lastSwap  map[string]string
}

func newFakeLogins(t *testing.T) *fakeLogins {
	return &fakeLogins{
		real: map[string]string{
			"access_token":  synthetic(t, "canary-access-"),
			"refresh_token": synthetic(t, "canary-refresh-"),
		},
		ph: map[string]string{"ph-access-w1": "access_token", "ph-refresh-w1": "refresh_token"},
	}
}

func (f *fakeLogins) Resolve(provider, worker, placeholder string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if provider != "codex" || worker != "w1" {
		return "", false
	}
	field, ok := f.ph[placeholder]
	if !ok {
		return "", false
	}
	return f.real[field], true
}

func (f *fakeLogins) ForWorker(provider, worker string) Swapper {
	return fakeSwap{f, false}
}

func (f *fakeLogins) ForSignIn(provider, worker string) Swapper {
	return fakeSwap{f, true}
}

func (f *fakeLogins) committed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.commits
}

type fakeSwap struct {
	f      *fakeLogins
	signIn bool
}

func (s fakeSwap) Swap(adapter string, creds map[string]string) (map[string]string, func() error, error) {
	if s.f.swapErr != nil {
		return nil, nil, s.f.swapErr
	}
	phs := map[string]string{}
	for k := range creds {
		phs[k] = "ph-new-" + k
	}
	return phs, func() error {
		s.f.mu.Lock()
		defer s.f.mu.Unlock()
		if s.f.commitErr != nil {
			return s.f.commitErr
		}
		s.f.commits++
		if s.signIn {
			s.f.signIns++
		}
		s.f.lastSwap = creds
		for k, v := range creds {
			s.f.real[k] = v
		}
		return nil
	}, nil
}

// upstream records what reached the provider and answers with reply.
type planUpstream struct {
	mu    sync.Mutex
	urls  []string
	reqs  []*http.Request
	body  [][]byte
	reply func(w http.ResponseWriter, r *http.Request)
}

func (u *planUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	var b []byte
	if r.Body != nil {
		b, _ = io.ReadAll(r.Body)
	}
	u.mu.Lock()
	u.urls = append(u.urls, r.URL.String())
	u.reqs = append(u.reqs, r)
	u.body = append(u.body, b)
	u.mu.Unlock()
	rec := httptest.NewRecorder()
	if u.reply != nil {
		u.reply(rec, r)
	} else {
		rec.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(rec, "data: {\"type\":\"response.completed\"}\n\n")
	}
	return rec.Result(), nil
}

func (u *planUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.urls)
}

type rig1014 struct {
	logins *fakeLogins
	up     *planUpstream
	audit  *auditLog
	quota  []QuotaReading
	use    []PlanUse
	h      http.Handler
}

func newWorkerRig(t *testing.T, signIn bool) *rig1014 {
	t.Helper()
	r := &rig1014{logins: newFakeLogins(t), up: &planUpstream{}, audit: &auditLog{}}
	h, err := NewWorkerRoute(WorkerRouteConfig{
		Route: Codex(), Worker: "w1", SignIn: signIn, Logins: r.logins,
		Transport: r.up, Audit: r.audit,
		Quota: func(q QuotaReading) { r.quota = append(r.quota, q) },
		Meter: func(u PlanUse) { r.use = append(r.use, u) },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

func (r *rig1014) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

// codexBody is a responses request in the pinned CLI's shape (#809): no
// top-level tools, tools in an additional_tools input item.
func codexBody(tools string) string {
	return `{"model":"gpt-x","stream":true,"tool_choice":"auto","include":["reasoning.encrypted_content"],` +
		`"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},` +
		`{"type":"additional_tools","role":"developer","tools":` + tools + `}]}`
}

const clientTools = `[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"wait"},{"type":"custom","name":"exec"}]}]`

func responses(body string) *http.Request {
	req := httptest.NewRequest("POST", "http://127.0.0.1:18432/backend-api/codex/responses", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer ph-access-w1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Chatgpt-Account-Id", "acct-synthetic")
	req.Header.Set("Cookie", "c=leak")
	return req
}

// A declared run request reaches the provider with the real login
// injected; the worker sends and receives placeholders only.
func TestWorkerRouteInjectsAtDeclaredEndpoint(t *testing.T) {
	r := newWorkerRig(t, false)
	r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Set-Cookie", "s=1")
		// A provider that echoes the login must not hand it to the worker.
		io.WriteString(w, "data: "+r.logins.real["access_token"]+"\n\n")
	}
	w := r.do(responses(codexBody(clientTools)))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if r.up.count() != 1 || r.up.urls[0] != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("upstream saw %v", r.up.urls)
	}
	got := r.up.reqs[0]
	if got.Header.Get("Authorization") != "Bearer "+r.logins.real["access_token"] {
		t.Fatal("the real access token was not injected")
	}
	if got.Header.Get("Cookie") != "" || got.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("headers not held to the allowlist: %v", got.Header)
	}
	if got.Header.Get("Chatgpt-Account-Id") != "acct-synthetic" {
		t.Fatal("declared header dropped")
	}
	if strings.Contains(w.Body.String(), r.logins.real["access_token"]) || w.Header().Get("Set-Cookie") != "" {
		t.Fatal("the real login reached the worker")
	}
	if ev := r.audit.last(t); !ev.Allowed || ev.Machine != "w1" || ev.Adapter != "codex" || ev.Operation != "responses" {
		t.Fatalf("journaled as %+v", ev)
	}
	if len(r.use) != 1 || r.use[0].Endpoint != "responses" || r.use[0].Worker != "w1" || r.use[0].RequestBytes == 0 || r.use[0].ResponseBytes == 0 {
		t.Fatalf("metered as %+v", r.use)
	}
}

// The models list carries its one declared query parameter; any other is
// refused.
func TestWorkerRouteModelsQuery(t *testing.T) {
	r := newWorkerRig(t, false)
	req := httptest.NewRequest("GET", "/backend-api/codex/models?client_version=0.162.1", nil)
	req.Header.Set("Authorization", "Bearer ph-access-w1")
	if w := r.do(req); w.Code != http.StatusOK {
		t.Fatalf("models: %d %s", w.Code, w.Body)
	}
	if r.up.urls[0] != "https://chatgpt.com/backend-api/codex/models?client_version=0.162.1" {
		t.Fatalf("upstream saw %v", r.up.urls)
	}
	for _, q := range []string{"?client_version=1&x=2", "?client_version=1&client_version=2", "?other=1", "?client_version=a%2Fb"} {
		req := httptest.NewRequest("GET", "/backend-api/codex/models"+q, nil)
		req.Header.Set("Authorization", "Bearer ph-access-w1")
		if w := r.do(req); w.Code != http.StatusForbidden {
			t.Fatalf("query %s: %d", q, w.Code)
		}
	}
	if r.up.count() != 1 {
		t.Fatal("a refused query reached the provider")
	}
}

// Undeclared requests fail by absence and are journaled with host and path
// only: no query, header or body.
func TestWorkerRouteRefusesUndeclared(t *testing.T) {
	r := newWorkerRig(t, false)
	cases := []*http.Request{
		httptest.NewRequest("GET", "/backend-api/wham/usage", nil),
		httptest.NewRequest("POST", "/backend-api/codex/analytics?secret=x", strings.NewReader("payload-canary")),
		httptest.NewRequest("GET", "/backend-api/codex/responses", nil),
		httptest.NewRequest("POST", "/backend-api/codex/./responses", strings.NewReader("{}")),
		httptest.NewRequest("POST", "/backend-api/codex/%72esponses", strings.NewReader("{}")),
		httptest.NewRequest("POST", "/backend-api//codex/responses", strings.NewReader("{}")),
		// Sign-in endpoints are not declared for a run worker.
		httptest.NewRequest("POST", "/api/accounts/deviceauth/usercode", strings.NewReader("{}")),
		httptest.NewRequest("CONNECT", "chatgpt.com:443", nil),
	}
	for _, req := range cases {
		req.Header.Set("Authorization", "Bearer ph-access-w1")
		w := r.do(req)
		if w.Code != http.StatusForbidden || w.Header().Get(DeniedHeader) == "" {
			t.Fatalf("%s %s: %d", req.Method, req.URL, w.Code)
		}
		ev := r.audit.last(t)
		if ev.Allowed || strings.Contains(ev.Path, "secret") || strings.Contains(ev.Reason, "payload") {
			t.Fatalf("%s %s journaled as %+v", req.Method, req.URL, ev)
		}
	}
	if r.up.count() != 0 {
		t.Fatalf("undeclared requests reached %v", r.up.urls)
	}
}

// N1 (#1014): no endpoint upgrades to a WebSocket, whose frames the body
// check would never read.
func TestWorkerRouteRefusesUpgrade(t *testing.T) {
	r := newWorkerRig(t, false)
	req := responses(codexBody(clientTools))
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	if w := r.do(req); w.Code != http.StatusForbidden {
		t.Fatalf("upgrade: %d", w.Code)
	}
	req = httptest.NewRequest("GET", "/backend-api/codex/models?client_version=1", nil)
	req.Header.Set("Authorization", "Bearer ph-access-w1")
	req.Header.Set("Upgrade", "websocket")
	if w := r.do(req); w.Code != http.StatusForbidden {
		t.Fatalf("upgrade on models: %d", w.Code)
	}
	if r.up.count() != 0 {
		t.Fatal("an upgrade reached the provider")
	}
}

// A request without the worker's own placeholder is refused: another
// worker's placeholder, a real-looking token, or none.
func TestWorkerRouteNeedsOwnPlaceholder(t *testing.T) {
	r := newWorkerRig(t, false)
	for _, auth := range []string{"", "Bearer ph-access-w2", "Bearer sk-guest-own", "Basic ph-access-w1", "Bearer ph-access-w1 x"} {
		req := responses(codexBody(clientTools))
		req.Header.Set("Authorization", auth)
		if w := r.do(req); w.Code != http.StatusForbidden {
			t.Fatalf("authorization %q: %d", auth, w.Code)
		}
	}
	if r.up.count() != 0 {
		t.Fatal("an unresolved request reached the provider")
	}
}

// W4's carry-over: hosted tools are refused by an allow-list of client-side
// types, wherever the CLI puts tools (#809: additional_tools input items).
func TestWorkerRouteBodyCheck(t *testing.T) {
	refused := map[string]string{
		"hosted in additional_tools": codexBody(`[{"type":"web_search"}]`),
		"made-up type":               codexBody(`[{"type":"image_generation_v9"}]`),
		"nested in namespace":        codexBody(`[{"type":"namespace","name":"x","tools":[{"type":"web_search"}]}]`),
		"top-level tools":            `{"model":"m","input":[],"tools":[{"type":"web_search_preview"}]}`,
		"other input item":           `{"model":"m","input":[{"type":"message","role":"user","tools":[{"type":"file_search"}]}]}`,
		"type spelled differently":   codexBody(`[{"type":"Function"}]`),
		"no type":                    codexBody(`[{"name":"x"}]`),
		"tool not an object":         codexBody(`["web_search"]`),
		"tools not an array":         codexBody(`{"type":"web_search"}`),
		"hosted tool_choice":         `{"model":"m","input":[],"tool_choice":{"type":"web_search"}}`,
		"additional_tools no list":   `{"model":"m","input":[{"type":"additional_tools","role":"developer"}]}`,
		"unparseable":                `{"model":`,
		"trailing data":              codexBody(clientTools) + `{}`,
		"not an object":              `[1]`,
		// E10's relay rule, and keys the pinned CLI does not send (#809).
		"web_search_options":      withKey(`"web_search_options":{}`),
		"background":              withKey(`"background":true`),
		"stored prompt":           withKey(`"prompt":{"id":"pmpt_x"}`),
		"store true":              withKey(`"store":true`),
		"store not a bool":        withKey(`"store":"false"`),
		"conversation":            withKey(`"conversation":"conv_x"`),
		"previous_response_id":    withKey(`"previous_response_id":"resp_x"`),
		"unknown top-level key":   withKey(`"zz_future":1`),
		"key spelled differently": withKey(`"Tools":[]`),
		"hosted in message content": `{"model":"m","input":[{"type":"message","role":"user",` +
			`"content":[{"type":"input_text","text":"hi"},{"type":"web_search"}]}]}`,
		"unknown input item":     `{"model":"m","input":[{"type":"web_search_call","action":{}}]}`,
		"input item no type":     `{"model":"m","input":[{"role":"user","content":"hi"}]}`,
		"input not a list":       `{"model":"m","input":{"type":"message"}}`,
		"tools under reasoning":  withKey(`"reasoning":{"effort":"low","tools":[{"type":"web_search"}]}`),
		"tools under text":       withKey(`"text":{"tools":[{"type":"web_search"}]}`),
		"tools in function call": `{"model":"m","input":[{"type":"function_call","name":"x","arguments":"{}","tools":[{"type":"web_search"}]}]}`,
	}
	for name, body := range refused {
		r := newWorkerRig(t, false)
		w := r.do(responses(body))
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", name, w.Code)
		}
		if r.up.count() != 0 {
			t.Fatalf("%s reached the provider", name)
		}
		ev := r.audit.last(t)
		if ev.Allowed || strings.Contains(ev.Reason, `"`) || strings.Contains(ev.Reason, "gpt-x") {
			t.Fatalf("%s journaled as %+v", name, ev)
		}
	}
	r := newWorkerRig(t, false)
	r.do(responses(codexBody(`[{"type":"web_search"}]`)))
	if ev := r.audit.last(t); !strings.Contains(ev.Reason, "web_search") {
		t.Fatalf("the refused tool type is not named: %+v", ev)
	}

	// Only declared client-side types: forwarded, as the route's own
	// encoding of what it checked.
	r = newWorkerRig(t, false)
	if w := r.do(responses(codexBody(clientTools))); w.Code != http.StatusOK {
		t.Fatalf("client tools: %d %s", w.Code, w.Body)
	}
	var sent map[string]any
	if err := json.Unmarshal(r.up.body[0], &sent); err != nil || sent["model"] != "gpt-x" {
		t.Fatalf("forwarded body %s", r.up.body[0])
	}
	// E10: store is forced off when the CLI leaves it out.
	if sent["store"] != false {
		t.Fatalf("store not set false: %s", r.up.body[0])
	}

	// The CLI's full request shape passes, with store:false kept.
	r = newWorkerRig(t, false)
	full := withKey(`"instructions":"be brief","parallel_tool_calls":false,"store":false,` +
		`"reasoning":{"effort":"medium","summary":"auto"},"prompt_cache_key":"k","text":{"verbosity":"low"},` +
		`"tools":[{"type":"function","name":"f","parameters":{"type":"object","properties":{"tools":{"type":"string"}}}}]`)
	full = strings.Replace(full, `"input":[`, `"input":[{"type":"reasoning","summary":[{"type":"summary_text","text":"s"}],"encrypted_content":"e"},`+
		`{"type":"function_call","name":"f","arguments":"{}","call_id":"c1"},{"type":"function_call_output","call_id":"c1","output":"ok"},`+
		`{"type":"custom_tool_call","name":"exec","input":"ls","call_id":"c2"},{"type":"custom_tool_call_output","call_id":"c2","output":"ok"},`+
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"x"}]},`, 1)
	if w := r.do(responses(full)); w.Code != http.StatusOK {
		t.Fatalf("CLI request shape: %d %s", w.Code, w.Body)
	}
}

// withKey adds one top-level key to a CLI-shaped body.
func withKey(kv string) string {
	return "{" + kv + "," + codexBody(clientTools)[1:]
}

// A compressed request body is refused rather than forwarded unread.
func TestWorkerRouteRefusesEncodedBody(t *testing.T) {
	r := newWorkerRig(t, false)
	req := responses(codexBody(clientTools))
	req.Header.Set("Content-Encoding", "zstd")
	if w := r.do(req); w.Code != http.StatusForbidden || r.up.count() != 0 {
		t.Fatalf("encoded body: %d, upstream %d", w.Code, r.up.count())
	}
}

func refreshReq(rt string) *http.Request {
	b, _ := json.Marshal(map[string]string{"client_id": "app_synthetic", "grant_type": "refresh_token", "refresh_token": rt, "scope": "openid profile email"})
	req := httptest.NewRequest("POST", "/oauth/token", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// releaseCheck fails the test if anything reaches the worker before the
// vault holds the new login.
type releaseCheck struct {
	*httptest.ResponseRecorder
	t      *testing.T
	logins *fakeLogins
	before int
}

func (c *releaseCheck) WriteHeader(s int) {
	if s == http.StatusOK && c.logins.committed() == c.before {
		c.t.Error("the swapped response was released before the vault write")
	}
	c.ResponseRecorder.WriteHeader(s)
}

func (c *releaseCheck) Write(b []byte) (int, error) {
	if c.logins.committed() == c.before {
		c.t.Error("the swapped response was released before the vault write")
	}
	return c.ResponseRecorder.Write(b)
}

func tokenReply(t *testing.T) (map[string]string, func(http.ResponseWriter, *http.Request)) {
	tok := map[string]string{
		"access_token":  synthetic(t, "canary-new-access-"),
		"refresh_token": synthetic(t, "canary-new-refresh-"),
		"id_token":      synthetic(t, "canary-new-id-"),
	}
	return tok, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": tok["access_token"], "refresh_token": tok["refresh_token"], "id_token": tok["id_token"],
			"expires_in": 864000, "token_type": "bearer", "scope": "openid profile email offline_access",
		})
	}
}

// The refresh carries the real refresh token at its declared body field,
// and its response comes back as placeholders, stored before release.
func TestWorkerRouteRefresh(t *testing.T) {
	r := newWorkerRig(t, false)
	tok, reply := tokenReply(t)
	r.up.reply = reply
	oldRefresh := r.logins.real["refresh_token"]
	w := &releaseCheck{httptest.NewRecorder(), t, r.logins, 0}
	r.h.ServeHTTP(w, refreshReq("ph-refresh-w1"))
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body)
	}
	if r.up.urls[0] != "https://auth.openai.com/oauth/token" {
		t.Fatalf("upstream %v", r.up.urls)
	}
	var sent map[string]string
	json.Unmarshal(r.up.body[0], &sent)
	if sent["refresh_token"] != oldRefresh || sent["grant_type"] != "refresh_token" {
		t.Fatal("the real refresh token was not injected at its field")
	}
	if r.up.reqs[0].Header.Get("Authorization") != "" {
		t.Fatal("the refresh carried an Authorization header")
	}
	out := w.Body.String()
	for _, v := range tok {
		if strings.Contains(out, v) {
			t.Fatal("a refreshed credential reached the worker")
		}
	}
	if !strings.Contains(out, `"access_token":"ph-new-access_token"`) || r.logins.committed() != 1 || r.logins.signIns != 0 {
		t.Fatalf("not swapped through the worker's swapper: %s", out)
	}

	// Any other field, or an unknown placeholder, is refused unsent.
	r2 := newWorkerRig(t, false)
	for _, req := range []*http.Request{refreshReq("ph-refresh-w2"), refreshReq(oldRefresh)} {
		if w := r2.do(req); w.Code != http.StatusForbidden {
			t.Fatalf("unresolved refresh: %d", w.Code)
		}
	}
	extra := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"ph-refresh-w1","redirect_uri":"https://evil.example"}`))
	if w := r2.do(extra); w.Code != http.StatusForbidden {
		t.Fatalf("undeclared refresh field: %d", w.Code)
	}
	code := httptest.NewRequest("POST", "/oauth/token", strings.NewReader("grant_type=authorization_code&code=x"))
	code.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := r2.do(code); w.Code != http.StatusForbidden {
		t.Fatalf("a run worker's code exchange: %d", w.Code)
	}
	if r2.up.count() != 0 {
		t.Fatal("a refused refresh reached the provider")
	}
}

// A refresh response outside its declared shape, or an error, never
// reaches the worker; nothing is stored.
func TestWorkerRouteRefreshDropped(t *testing.T) {
	canary := synthetic(t, "canary-leak-")
	replies := map[string]func(http.ResponseWriter, *http.Request){
		"undeclared field": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"access_token":"`+canary+`","refresh_token":"r-`+canary+`","api_key":"`+canary+`"}`)
		},
		"error status": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"error":"refresh_token_reused","access_token":"`+canary+`"}`)
		},
		"encoded": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			io.WriteString(w, canary)
		},
	}
	for name, reply := range replies {
		r := newWorkerRig(t, false)
		r.up.reply = reply
		w := r.do(refreshReq("ph-refresh-w1"))
		if w.Code < 400 || strings.Contains(w.Body.String(), canary) || r.logins.committed() != 0 {
			t.Fatalf("%s: %d %q, commits %d", name, w.Code, w.Body, r.logins.committed())
		}
		if ev := r.audit.last(t); strings.Contains(ev.Reason, canary) {
			t.Fatalf("%s journaled the body", name)
		}
	}
	r := newWorkerRig(t, false)
	_, r.up.reply = tokenReply(t)
	r.logins.swapErr = errors.New("vault locked")
	if w := r.do(refreshReq("ph-refresh-w1")); w.Code < 400 || strings.Contains(w.Body.String(), "canary") {
		t.Fatalf("failed swap: %d %s", w.Code, w.Body)
	}
}

// CRED-5: when the vault write fails after a good swap, the worker gets
// neither the real tokens nor placeholders for a login the vault does not
// hold, on refresh and on the sign-in code exchange alike.
func TestWorkerRouteVaultWriteFails(t *testing.T) {
	cases := map[string]struct {
		signIn bool
		req    func() *http.Request
	}{
		"refresh":       {false, func() *http.Request { return refreshReq("ph-refresh-w1") }},
		"code exchange": {true, func() *http.Request { return codeExchange("http://127.0.0.1:18432/deviceauth/callback") }},
	}
	for name, c := range cases {
		r := newWorkerRig(t, c.signIn)
		tok, reply := tokenReply(t)
		r.up.reply = reply
		r.logins.commitErr = errors.New("vault write failed")
		w := r.do(c.req())
		out := w.Body.String()
		if w.Code != http.StatusBadGateway || !strings.Contains(out, ReasonUnswappable) {
			t.Fatalf("%s: %d %q", name, w.Code, out)
		}
		if strings.Contains(out, "ph-new-") || strings.Contains(out, "canary") {
			t.Fatalf("%s: released %q", name, out)
		}
		for _, v := range tok {
			if strings.Contains(out, v) {
				t.Fatalf("%s: a real credential reached the worker", name)
			}
		}
		if r.logins.committed() != 0 || r.logins.lastSwap != nil {
			t.Fatalf("%s: a login was stored", name)
		}
		if ev := r.audit.last(t); ev.Reason != ReasonUnswappable {
			t.Fatalf("%s journaled %q", name, ev.Reason)
		}
	}
}

// Quota headers the broker reads on its own connection land as pool
// readings; a credits or limit-reached signal reads as used up (#809).
func TestWorkerRouteQuotaReadings(t *testing.T) {
	r := newWorkerRig(t, false)
	r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("X-Codex-Primary-Used-Percent", "42.5")
		h.Set("X-Codex-Primary-Window-Minutes", "300")
		h.Set("X-Codex-Primary-Reset-At", "1792000000")
		h.Set("X-Codex-Secondary-Used-Percent", "7")
		h.Set("X-Codex-Secondary-Window-Minutes", "10080")
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {}\n\n")
	}
	if w := r.do(responses(codexBody(clientTools))); w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	got := map[string]QuotaReading{}
	for _, q := range r.quota {
		got[q.Pool] = q
	}
	p, s := got["primary"], got["secondary"]
	if p.UsedPercent != 42.5 || p.WindowMinutes != 300 || p.ResetAt != 1792000000 || p.Exhausted || p.Provider != "codex" || p.Worker != "w1" {
		t.Fatalf("primary %+v", p)
	}
	if s.UsedPercent != 7 || s.WindowMinutes != 10080 || s.Exhausted {
		t.Fatalf("secondary %+v", s)
	}

	for _, sig := range []string{"X-Codex-Credits-Has-Credits", "X-Codex-Rate-Limit-Reached-Type"} {
		r := newWorkerRig(t, false)
		r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(sig, "false")
			w.Header().Set("Content-Type", "text/event-stream")
		}
		r.do(responses(codexBody(clientTools)))
		used := false
		for _, q := range r.quota {
			used = used || q.Exhausted
		}
		if !used {
			t.Fatalf("%s did not read as used up: %+v", sig, r.quota)
		}
	}
}

// DEV-2, E12: an upstream name that resolves into the home network is
// refused at dial, journaled, and never connected.
func TestWorkerRouteRefusesPrivateAnswer(t *testing.T) {
	var dialed atomic.Int32
	g := netguard.New(netguard.Config{
		Resolver: &stubResolver{"192.168.1.20"},
		Connect: func(context.Context, string, string) (net.Conn, error) {
			dialed.Add(1)
			return nil, net.ErrClosed
		},
	})
	audit := &auditLog{}
	h, err := NewWorkerRoute(WorkerRouteConfig{Route: Codex(), Worker: "w1", Logins: newFakeLogins(t), Guard: g, Audit: audit})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, responses(codexBody(clientTools)))
	if w.Code != http.StatusForbidden || dialed.Load() != 0 {
		t.Fatalf("status %d, dialed %d", w.Code, dialed.Load())
	}
	if ev := audit.last(t); ev.Allowed || !strings.Contains(ev.Reason, "home-network") {
		t.Fatalf("journaled as %+v", ev)
	}
}

func TestWorkerRouteConfigRequired(t *testing.T) {
	ok := WorkerRouteConfig{Route: Codex(), Worker: "w1", Logins: newFakeLogins(t), Transport: &planUpstream{}, Audit: &auditLog{}}
	for name, mut := range map[string]func(*WorkerRouteConfig){
		"no worker":         func(c *WorkerRouteConfig) { c.Worker = "" },
		"no logins":         func(c *WorkerRouteConfig) { c.Logins = nil },
		"no auditor":        func(c *WorkerRouteConfig) { c.Audit = nil },
		"hosted tool":       func(c *WorkerRouteConfig) { c.Route.ToolTypes = append(c.Route.ToolTypes, "web_search") },
		"background key":    func(c *WorkerRouteConfig) { c.Route.BodyKeys = append(c.Route.BodyKeys, "background") },
		"stored prompt key": func(c *WorkerRouteConfig) { c.Route.BodyKeys = append(c.Route.BodyKeys, "prompt") },
		"no body shape":     func(c *WorkerRouteConfig) { c.Route.InputTypes = nil },
		"bad path":          func(c *WorkerRouteConfig) { c.Route.Endpoints[0].Path = "/a/../b" },
	} {
		c := ok
		c.Route = Codex()
		mut(&c)
		if _, err := NewWorkerRoute(c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func deviceReq(path, body string) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func codeExchange(redirect string) *http.Request {
	f := url.Values{
		"client_id": {"app_synthetic"}, "code": {"code-synthetic"}, "code_verifier": {"verifier-synthetic"},
		"grant_type": {"authorization_code"}, "redirect_uri": {redirect},
	}
	req := httptest.NewRequest("POST", "/oauth/token", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// W5's carry-over: a sign-in worker reaches the device-auth endpoints and
// the code exchange on the auth host only; redirect_uri is rewritten to the
// auth host (#809); the first token set is stored before release and the
// worker gets placeholders.
func TestWorkerRouteSignIn(t *testing.T) {
	r := newWorkerRig(t, true)
	tok, reply := tokenReply(t)
	r.up.reply = func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/oauth/token" {
			reply(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"device_auth_id":"d","user_code":"ABCD-1234","interval":"5"}`)
	}
	for _, p := range []string{"/api/accounts/deviceauth/usercode", "/api/accounts/deviceauth/token"} {
		if w := r.do(deviceReq(p, `{"client_id":"app_synthetic"}`)); w.Code != http.StatusOK {
			t.Fatalf("%s: %d", p, w.Code)
		}
	}
	w := &releaseCheck{httptest.NewRecorder(), t, r.logins, 0}
	r.h.ServeHTTP(w, codeExchange("http://127.0.0.1:18432/deviceauth/callback"))
	if w.Code != http.StatusOK {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	want := []string{
		"https://auth.openai.com/api/accounts/deviceauth/usercode",
		"https://auth.openai.com/api/accounts/deviceauth/token",
		"https://auth.openai.com/oauth/token",
	}
	for i, u := range want {
		if r.up.urls[i] != u {
			t.Fatalf("upstream %v", r.up.urls)
		}
	}
	f, _ := url.ParseQuery(string(r.up.body[2]))
	if f.Get("redirect_uri") != "https://auth.openai.com/deviceauth/callback" || f.Get("code") != "code-synthetic" || len(f) != 5 {
		t.Fatalf("exchange form %v", f)
	}
	for _, v := range tok {
		if strings.Contains(w.Body.String(), v) {
			t.Fatal("a signed-in credential reached the worker")
		}
	}
	if r.logins.signIns != 1 || r.logins.lastSwap["refresh_token"] != tok["refresh_token"] {
		t.Fatal("the sign-in was not stored through the sign-in swapper")
	}

	// A sign-in worker has no run endpoints and no refresh.
	if w := r.do(responses(codexBody(clientTools))); w.Code != http.StatusForbidden {
		t.Fatalf("run from sign-in: %d", w.Code)
	}
	if w := r.do(refreshReq("ph-refresh-w1")); w.Code != http.StatusForbidden {
		t.Fatalf("refresh from sign-in: %d", w.Code)
	}
}

// Only the forwarder's own callback is rewritten; anything else is
// refused, not passed through.
func TestWorkerRouteSignInRedirect(t *testing.T) {
	for _, red := range []string{
		"https://auth.openai.com/deviceauth/callback",
		"http://127.0.0.1:18432.evil.example/deviceauth/callback",
		"http://127.0.0.1:18433/deviceauth/callback",
		"http://127.0.0.1:18432/other",
		"http://127.0.0.1:18432/deviceauth/callback?x=1",
		"",
	} {
		r := newWorkerRig(t, true)
		if w := r.do(codeExchange(red)); w.Code != http.StatusForbidden {
			t.Fatalf("redirect %q: %d", red, w.Code)
		}
		if r.up.count() != 0 {
			t.Fatalf("redirect %q reached the provider", red)
		}
	}
	r := newWorkerRig(t, true)
	req := codeExchange("http://127.0.0.1:18432/deviceauth/callback")
	b, _ := io.ReadAll(req.Body)
	req = httptest.NewRequest("POST", "/oauth/token", strings.NewReader(string(b)+"&scope=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if w := r.do(req); w.Code != http.StatusForbidden {
		t.Fatalf("extra form key: %d", w.Code)
	}
}

// The verification link reaches the page only as the declared auth host's
// own page; a look-alike stops sign-in.
func TestSignInLink(t *testing.T) {
	route := Codex()
	for _, ok := range []string{"http://127.0.0.1:18432/codex/device", "https://auth.openai.com/codex/device"} {
		link, code, err := route.SignInLink(ok, "ABCD-1234")
		if err != nil || link != "https://auth.openai.com/codex/device" || code != "ABCD-1234" {
			t.Fatalf("%s: %q %q %v", ok, link, code, err)
		}
	}
	for _, bad := range []string{
		"https://auth.openai.com.evil.example/codex/device",
		"https://auth-openai.com/codex/device",
		"https://evil.example/codex/device?u=https://auth.openai.com",
		"https://user@auth.openai.com/codex/device",
		"http://auth.openai.com/codex/device",
		"https://auth.openai.com/codex/device?next=x",
		"https://auth.openai.com/other",
		"http://127.0.0.1:18433/codex/device",
		"",
	} {
		if link, _, err := route.SignInLink(bad, "ABCD-1234"); err == nil || link != "" {
			t.Fatalf("%q passed as %q", bad, link)
		}
	}
	for _, code := range []string{"", "abcd<script>", strings.Repeat("A", 40)} {
		if _, _, err := route.SignInLink("https://auth.openai.com/codex/device", code); err == nil {
			t.Fatalf("code %q passed", code)
		}
	}
}

// The broker opens and closes a provider worker's route over the vault
// process's control socket; a refusal is an error, so the machine does not
// start without its route (A14, RES-5).
func TestA14RouteControlOpensAndClosesOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var calls []string
	refuse := false
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		if refuse {
			http.Error(w, "locked", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/open" {
			io.WriteString(w, `{"dir":"/run/x/pw-a"}`)
		}
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := RouteControl{Socket: sock}
	got, err := c.Open("pw-a")
	if err != nil || got != "/run/x/pw-a" {
		t.Fatalf("open: %q, %v", got, err)
	}
	c.Close("pw-a")
	mu.Lock()
	want := []string{"POST /open?machine=pw-a", "POST /close?machine=pw-a"}
	if strings.Join(calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls %v, want %v", calls, want)
	}
	refuse = true
	mu.Unlock()
	if _, err := c.Open("pw-a"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("a locked open returned %v, want ErrVaultLocked", err)
	} else if strings.Contains(err.Error(), "\n") {
		t.Fatalf("a locked open's error spans lines: %q", err)
	}
	if _, err := c.Seed("pw-a"); !errors.Is(err, ErrVaultLocked) {
		t.Fatalf("a locked seed returned %v, want ErrVaultLocked", err)
	}
	if _, err := (RouteControl{Socket: filepath.Join(dir, "none.sock")}).Open("pw-a"); err == nil {
		t.Fatal("an unreachable control socket returned no error")
	}
}

// countingBody counts what a handler reads of a request body.
type countingBody struct {
	n atomic.Int64
	r io.Reader
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingBody) Close() error { return nil }

// A request without this worker's placeholder is refused before any of its
// body is read, so a caller holding no credential cannot make the vault
// process buffer a body (CRED-8, egress K28).
func TestWorkerRouteRefusesBeforeReadingTheBody(t *testing.T) {
	r := newWorkerRig(t, false)
	for _, auth := range []string{"", "Bearer ph-access-w2"} {
		req := responses(codexBody(clientTools))
		body := &countingBody{r: strings.NewReader(strings.Repeat("x", 1<<20))}
		req.Body = body
		req.Header.Set("Authorization", auth)
		if w := r.do(req); w.Code != http.StatusForbidden {
			t.Fatalf("authorization %q: %d", auth, w.Code)
		}
		if n := body.n.Load(); n != 0 {
			t.Fatalf("authorization %q: %d body bytes read before the placeholder check", auth, n)
		}
	}
}

// controlStub serves reply on a unix socket in place of agentos-egress.
func controlStub(t *testing.T, h http.HandlerFunc) RouteControl {
	t.Helper()
	dir, err := os.MkdirTemp("", "rc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "p.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return RouteControl{Socket: sock}
}

// Open hands the machine only an absolute, clean directory named for the
// worker it asked for, whatever the vault process replies (A14).
func TestA14RouteControlChecksTheDirectory(t *testing.T) {
	for _, dir := range []string{"run/x/pw-a", "/run/x/pw-b", "/run/x/../y/pw-a", "/run/x/pw-a/", "/run/x//pw-a", "/"} {
		c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"dir": dir})
		})
		if got, err := c.Open("pw-a"); err == nil {
			t.Errorf("reply %q: opened %q", dir, got)
		}
	}
}

// Seed returns the placeholder files the vault process minted for the
// worker, for agentosd to put in the machine before it starts (#1015).
func TestCRED5RouteControlSeedsTheWorker(t *testing.T) {
	var path string
	c := controlStub(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path + "?" + r.URL.RawQuery
		json.NewEncoder(w).Encode(map[string][]byte{CodexAuthFile: []byte(`{"tokens":{}}`)})
	})
	got, err := c.Seed("pw-a")
	if err != nil {
		t.Fatal(err)
	}
	if path != "POST /seed?machine=pw-a" {
		t.Fatalf("called %q", path)
	}
	if len(got) != 1 || string(got[CodexAuthFile]) != `{"tokens":{}}` {
		t.Fatalf("seed %q", got)
	}
}
