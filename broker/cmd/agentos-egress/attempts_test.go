package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: OP-8, ARC-7 (SR3-7-f1b, SR3-7-f1c)

// failoverRouter routes the default class to anthropic, then openai.
func failoverRouter(t *testing.T) *route.Router {
	t.Helper()
	rt, err := newRouter(route.Rule{"default": {{Provider: "anthropic", Model: "claude-test"}, {Provider: "openai", Model: "gpt-test"}}},
		map[string][]string{"agent": {"anthropic", "openai"}}, map[string]bool{"anthropic": true, "openai": true})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

// failingUpstream answers anthropic with status and openai with a served
// completion, counting the calls each provider got.
type failingUpstream struct {
	status int
	mu     sync.Mutex
	calls  map[string]int
}

func (u *failingUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	u.mu.Lock()
	if u.calls == nil {
		u.calls = map[string]int{}
	}
	provider := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2)[0]
	u.calls[provider]++
	u.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if provider == "anthropic" {
		w.WriteHeader(u.status)
		io.WriteString(w, `{"type":"error","error":{"type":"api_error","message":"x"}}`)
		return
	}
	io.WriteString(w, `{"id":"c","object":"chat.completion","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":19,"completion_tokens":6,"total_tokens":25}}`)
}

// serveAttempts runs one call through the egress composition with the
// broker's allowance header (none if attempts is "").
func serveAttempts(t *testing.T, up *failingUpstream, attempts string) (*httptest.ResponseRecorder, modelroute.Usage) {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","messages":[{"role":"user","content":"x"}]}`))
	req.Header.Set("Content-Type", "application/json")
	if attempts != "" {
		req.Header.Set(modelroute.HeaderAttempts, attempts)
	}
	w := httptest.NewRecorder()
	var ca callAudit
	ca.serve(failoverRouter(t), "agent", "private", up, w, req)
	var u modelroute.Usage
	if err := json.Unmarshal([]byte(w.Header().Get(modelroute.HeaderUsage)), &u); err != nil {
		t.Fatalf("usage trailer %q: %v", w.Header().Get(modelroute.HeaderUsage), err)
	}
	return w, u
}

// TestSR3_7f1bAttemptsFollowTheAllowance: the router fails over only as
// many times as the broker's meter holds (HeaderAttempts); a missing or
// unreadable allowance means one attempt.
func TestSR3_7f1bAttemptsFollowTheAllowance(t *testing.T) {
	for _, c := range []struct {
		header string
		served bool
	}{{"", false}, {"0", false}, {"x", false}, {"-1", false}, {"99", false}, {"1", true}, {"3", true}} {
		up := &failingUpstream{status: 504}
		w, u := serveAttempts(t, up, c.header)
		if got := up.calls["openai"] == 1; got != c.served {
			t.Errorf("allowance %q: second route contacted %d times", c.header, up.calls["openai"])
		}
		if !c.served && (w.Code != 504 || !u.Unserved || len(u.Failed) != 1) {
			t.Errorf("allowance %q: status %d, usage %+v; want the last provider status and one failed attempt", c.header, w.Code, u)
		}
	}
}

// TestSR3_7f1cTrailerCarriesFailedAttempts: the usage trailer carries each
// attempt the router failed over from, with the served usage, and says so
// when nothing was sent upstream.
func TestSR3_7f1cTrailerCarriesFailedAttempts(t *testing.T) {
	up := &failingUpstream{status: 504}
	w, u := serveAttempts(t, up, "1")
	if w.Code != 200 || u.Provider != "openai" || u.Input != 19 || u.Output != 6 || u.Unserved || u.None ||
		len(u.Failed) != 1 || u.Failed[0].Provider != "anthropic" || u.Failed[0].Status != 504 || !u.Failed[0].Full {
		t.Fatalf("status %d, usage %+v", w.Code, u)
	}

	up = &failingUpstream{status: 429}
	if _, u = serveAttempts(t, up, "1"); len(u.Failed) != 1 || u.Failed[0].Full {
		t.Errorf("429 attempt %+v, want input only", u.Failed)
	}

	// Refused before any route was sent: nothing to charge but the page.
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"nope","messages":[]}`))
	w = httptest.NewRecorder()
	var ca callAudit
	ca.serve(failoverRouter(t), "agent", "private", &failingUpstream{}, w, req)
	if got := w.Header().Get(modelroute.HeaderUsage); got != `{"none":true}` {
		t.Errorf("refused call trailer %q", got)
	}
}
