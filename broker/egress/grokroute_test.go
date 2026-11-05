package egress

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// REQ: CRED-5, CRED-1

// grokLogins is fakeLogins holding a Grok login for worker w1: it resolves
// for provider grok only and records every provider it was asked for, so a
// test sees a placeholder never resolved against another provider's login.
type grokLogins struct {
	*fakeLogins
	amu   sync.Mutex
	asked []string
}

func (g *grokLogins) Resolve(provider, worker, placeholder string) (string, bool) {
	g.amu.Lock()
	g.asked = append(g.asked, provider)
	g.amu.Unlock()
	if provider != "grok" {
		return "", false
	}
	return g.fakeLogins.Resolve("codex", worker, placeholder)
}

func (g *grokLogins) resolved() []string {
	g.amu.Lock()
	defer g.amu.Unlock()
	return append([]string(nil), g.asked...)
}

type grokRig struct {
	logins *grokLogins
	up     *planUpstream
	audit  *auditLog
	h      http.Handler
}

func newGrokRig(t *testing.T) *grokRig {
	t.Helper()
	r := &grokRig{logins: &grokLogins{fakeLogins: newFakeLogins(t)}, up: &planUpstream{}, audit: &auditLog{}}
	h, err := NewWorkerRoute(WorkerRouteConfig{
		Route: Grok(), Worker: "w1", Logins: r.logins, Transport: r.up, Audit: r.audit,
		Quota: func(QuotaReading) {}, Signal: func(PlanSignal) {}, Meter: func(PlanUse) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	return r
}

func (r *grokRig) do(req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.h.ServeHTTP(w, req)
	return w
}

const grokBody = `{"model":"grok-x","stream":true,"store":false,"tool_choice":"auto",` +
	`"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],` +
	`"tools":[{"type":"function","name":"read_file"},{"type":"function","name":"run_terminal_cmd"}]}`

func grokReq(method, target, body, ph string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ph)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func grokRefresh(fields map[string]string) *http.Request {
	b, _ := json.Marshal(fields)
	req := httptest.NewRequest("POST", "/oauth2/token", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}

// The route declares exactly the CLI's run endpoints at the CLI's hosts:
// the model call and model list at the chat proxy, the refresh at the auth
// host. A run worker's placeholder is injected there and nowhere else; a
// request to any other path or position is refused before the login is
// looked up, and the route never asks for another provider's login.
func TestGrokRouteInjectsOnlyAtDeclaredEndpoints(t *testing.T) {
	want := []string{
		"models GET cli-chat-proxy.grok.com/v1/models read",
		"refresh POST auth.x.ai/oauth2/token refresh",
		"responses POST cli-chat-proxy.grok.com/v1/responses responses",
	}
	var got []string
	for _, e := range Grok().Endpoints {
		got = append(got, e.Name+" "+e.Method+" "+e.Host+e.Path+" "+string(e.Kind))
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("declared endpoints:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	r := newGrokRig(t)
	w := r.do(grokReq("POST", "http://127.0.0.1:18433/v1/responses", grokBody, "ph-access-w1"))
	if w.Code != http.StatusOK || r.up.count() != 1 {
		t.Fatalf("declared call: %d %s, upstream %d", w.Code, w.Body, r.up.count())
	}
	if r.up.urls[0] != "https://cli-chat-proxy.grok.com/v1/responses" {
		t.Fatalf("upstream %v", r.up.urls)
	}
	if got := r.up.reqs[0].Header.Get("Authorization"); got != "Bearer "+r.logins.real["access_token"] {
		t.Fatalf("injected %q", got)
	}

	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/chat/completions", grokBody},
		{"POST", "/v1/responses/compact", grokBody},
		{"GET", "/v1/models?x=1", ""},
		{"GET", "/v1/settings", ""},
		{"POST", "/oauth/token", grokBody},
		{"POST", "/backend-api/codex/responses", grokBody},
		{"GET", "/v1/responses", ""},
	} {
		before, asked := r.up.count(), len(r.logins.resolved())
		w := r.do(grokReq(c.method, c.path, c.body, "ph-access-w1"))
		if w.Code != http.StatusForbidden || r.up.count() != before || len(r.logins.resolved()) != asked {
			t.Errorf("%s %s: %d, upstream %d->%d, resolved %d->%d", c.method, c.path, w.Code, before, r.up.count(), asked, len(r.logins.resolved()))
		}
		if strings.Contains(w.Body.String(), r.logins.real["access_token"]) {
			t.Errorf("%s %s: the login reached the worker", c.method, c.path)
		}
	}

	// A placeholder at an undeclared position (a body field, a query
	// value, another header) is not a bearer and is never resolved.
	before := r.up.count()
	req := grokReq("POST", "/v1/responses", strings.Replace(grokBody, `"hi"`, `"ph-access-w1"`, 1), "ph-refresh-w1x")
	req.Header.Set("X-Api-Key", "ph-access-w1")
	if w := r.do(req); w.Code == http.StatusOK || r.up.count() != before {
		t.Fatalf("unknown bearer: %d, upstream %d", w.Code, r.up.count())
	}
	for _, p := range r.logins.resolved() {
		if p != "grok" {
			t.Fatalf("the route asked for provider %q's login", p)
		}
	}
	if a := r.audit.last(t); a.Allowed {
		t.Fatalf("refusal journaled as allowed: %+v", a)
	}
}

// A refresh with a field the route does not declare is refused and never
// sent: the worker cannot steer the exchange (a redirect, another client).
func TestGrokRouteRefusesUndeclaredRefreshField(t *testing.T) {
	r := newGrokRig(t)
	base := map[string]string{"client_id": "client_synthetic", "grant_type": "refresh_token", "refresh_token": "ph-refresh-w1"}
	for _, extra := range []string{"redirect_uri", "code", "audience", "resource"} {
		f := map[string]string{extra: "https://elsewhere.example.test/"}
		for k, v := range base {
			f[k] = v
		}
		if w := r.do(grokRefresh(f)); w.Code != http.StatusForbidden || r.up.count() != 0 {
			t.Fatalf("%s: %d, upstream %d", extra, w.Code, r.up.count())
		}
	}
	if r.logins.committed() != 0 {
		t.Fatal("a refused refresh committed a login")
	}
}

// The token response's every credential field comes back as a placeholder,
// stored before release; a canary never reaches the worker. A field the
// route does not declare fails the exchange and nothing is stored.
func TestGrokTokenResponseSwapsAllCredentialFields(t *testing.T) {
	r := newGrokRig(t)
	tok, reply := tokenReply(t)
	r.up.reply = reply
	w := &releaseCheck{httptest.NewRecorder(), t, r.logins.fakeLogins, 0}
	r.h.ServeHTTP(w, grokRefresh(map[string]string{"client_id": "client_synthetic", "grant_type": "refresh_token", "refresh_token": "ph-refresh-w1"}))
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body)
	}
	if r.up.urls[0] != "https://auth.x.ai/oauth2/token" {
		t.Fatalf("upstream %v", r.up.urls)
	}
	for _, v := range tok {
		if strings.Contains(w.Body.String(), v) || strings.Contains(strings.Join(w.Header().Values("X-Request-Id"), ""), v) {
			t.Fatal("a canary token field reached the worker")
		}
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"access_token", "refresh_token", "id_token"} {
		if got[f] != "ph-new-"+f {
			t.Errorf("%s came back as %v", f, got[f])
		}
		if r.logins.real[f] != tok[f] {
			t.Errorf("%s not stored", f)
		}
	}

	r = newGrokRig(t)
	leak := synthetic(t, "canary-extra-")
	r.up.reply = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": tok["access_token"], "session_token": leak})
	}
	rec := r.do(grokRefresh(map[string]string{"client_id": "client_synthetic", "grant_type": "refresh_token", "refresh_token": "ph-refresh-w1"}))
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), leak) || strings.Contains(rec.Body.String(), tok["access_token"]) {
		t.Fatalf("undeclared field: %d %s", rec.Code, rec.Body)
	}
	if r.logins.committed() != 0 {
		t.Fatal("a failed swap committed a login")
	}
}
