package route

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: PLN-7
//
// Package B2-1 (#1460, #1567): a late OpenAI error chunk is sanitised, a
// chunk whose error is null passes through, and a cancelled call is
// terminal in the router without cooling the route.

// A first chunk carrying "error": null is ordinary output, not an early
// error (#1460 L2, mutant M3).
func TestOpenAIStreamNullErrorPassesThrough(t *testing.T) {
	chunk := `{"error":null,"choices":[{"delta":{"content":"Hi"}}]}`
	src := "data: " + chunk + "\n\ndata: [DONE]\n\n"
	var out strings.Builder
	u, err := OpenAI().Stream(&out, func() {}, strings.NewReader(src), "default", false)
	if err != nil || !u.Complete {
		t.Fatalf("null error: %v %+v", err, u)
	}
	if want := "data: " + chunk + "\n\ndata: [DONE]\n\n"; out.String() != want {
		t.Fatalf("wrote %q, want %q", out.String(), want)
	}
}

// A late error chunk with the provider's account wording reaches the
// guest only as the generic error (#1460 L1).
func TestOpenAILateStreamErrorSanitisedThroughRouter(t *testing.T) {
	r := newRig(t, rigOpts{rule: Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}}}})
	full := fixture(t, "openai_stream.sse")
	first := string(full[:strings.Index(string(full), "\n\n")+2])
	late := "data: " + strings.TrimSpace(string(fixture(t, "openai_insufficient_quota.json"))) + "\n\n"
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", []byte(first+late)))
	w := r.do(t, "m1", `{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	body := w.Body.String()
	if strings.Contains(body, "insufficient_quota") || strings.Contains(body, "quota") || strings.Contains(body, "[DONE]") ||
		!strings.Contains(body, "provider stream error") {
		t.Fatalf("%d %s", w.Code, body)
	}
}

// A call whose context is cancelled (the meter's call time limit) stops
// the router: no later route is tried and the route it was on
// is not cooled (#1567).
func TestCancelledCallIsTerminalAndCoolsNothing(t *testing.T) {
	r := newRig(t, rigOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	r.up.set(hostAnthropic, func(w http.ResponseWriter, req *http.Request) {
		cancel()
		<-req.Context().Done()
		serveFixture(502, "application/json", []byte(`{"type":"error","error":{"type":"api_error","message":"x"}}`))(w, req)
	})
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(simpleChat)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, anyAttempt(req))
	assertTimedOut(t, r, w)
	if n := r.up.count(hostOpenAI); n != 0 {
		t.Fatalf("a cancelled call tried another route (%d calls)", n)
	}
	if st := r.router.Stats()["anthropic/claude-fixture"]; st.Failovers != 0 {
		t.Fatalf("a cancelled call counted a failover: %+v", st)
	}
	// The route is not cooling: the next call is served from it.
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	if w := r.do(t, "m1", simpleChat); w.Code != 200 || r.up.count(hostOpenAI) != 0 {
		t.Fatalf("route cooled after a cancelled call: %d %s", w.Code, w.Body)
	}
}

// A stream cancelled before its first byte is terminal too.
func TestCancelledStreamIsTerminalAndCoolsNothing(t *testing.T) {
	r := newRig(t, rigOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	r.up.set(hostAnthropic, func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		cancel()
		<-req.Context().Done()
	})
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{"model":"default","stream":true,"messages":[{"role":"user","content":"hi"}]}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, anyAttempt(req))
	assertTimedOut(t, r, w)
	if n := r.up.count(hostOpenAI); n != 0 {
		t.Fatalf("a cancelled stream tried another route (%d calls)", n)
	}
	if st := r.router.Stats()["anthropic/claude-fixture"]; st.Failovers != 0 {
		t.Fatalf("a cancelled stream counted a failover: %+v", st)
	}
}

// assertTimedOut checks the guest's answer and the single audit record of
// a cancelled call: 504 timeout, one denied decision, no failover.
func assertTimedOut(t *testing.T, r *rig, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusGatewayTimeout || !strings.Contains(w.Body.String(), `"code":"timeout"`) || w.Header().Get("Retry-After") != "" {
		t.Fatalf("guest answer: %d %q %v", w.Code, w.Body, w.Header())
	}
	if len(r.decisions) != 1 || r.decisions[0].Outcome != Denied || r.decisions[0].Status != http.StatusGatewayTimeout {
		t.Fatalf("decisions: %+v", r.decisions)
	}
}
