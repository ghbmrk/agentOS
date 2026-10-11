package route

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: OP-8, ARC-7 (SR3-7-f1a, SR3-7-f1b, SR3-7-f1c)

// anyAttempt is req allowed every attempt the router asks for, as a
// caller with no meter to bound it would install (SR3-7-f1b).
func anyAttempt(req *http.Request) *http.Request {
	return req.WithContext(WithAttempt(req.Context(), func() bool { return true }))
}

// failedBody asks for 3000 output tokens, the meter's reservation.
const failedBody = `{"model":"default","messages":[{"role":"user","content":"x"}],"max_tokens":3000}`

// failedIn is failedBody's input estimate as the meter makes it.
var failedIn = meter.Tokens(int64(len(failedBody)))

// openAIServed is the OpenAI fixture's usage as the meter weighs it.
const openAIServed = 19 + 6

// newFailoverMeter composes the meter (machine cap tokens), Routed and
// the default two-route rule (anthropic, then openai).
func newFailoverMeter(t *testing.T, r *rig, tokens int64) *meter.Meter {
	t.Helper()
	m, err := meter.Open(meter.Config{
		Path:       filepath.Join(t.TempDir(), "meter.json"),
		MachineCap: meter.Limits{Calls: 1000, Tokens: tokens},
		OverallCap: meter.Limits{Calls: 1000, Tokens: 1 << 40},
		MaxReserve: 6000, DefaultReserve: 700,
		Now: func() time.Time { return r.clock() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func doMetered(t *testing.T, m *meter.Meter, r *rig) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(failedBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	m.Wrap("m1", Routed(r.router)("m1")).ServeHTTP(w, req)
	return w.Result()
}

// TestSR3_7f1aFailedAttemptsAreCharged: each attempt the router sent and
// failed over from is charged: 401 and 429 their input estimate; 5xx and
// 529 the full output reservation, or the usage their error body reports
// (never below the input estimate); the served attempt as before.
func TestSR3_7f1aFailedAttemptsAreCharged(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
		want   int64 // the failed attempt's charge
	}{
		{"504", 504, `{"type":"error","error":{"type":"timeout_error","message":"x"}}`, failedIn + 3000},
		{"529", 529, `{"type":"error","error":{"type":"overloaded_error","message":"x"}}`, failedIn + 3000},
		{"500", 500, `{"type":"error","error":{"type":"api_error","message":"x"}}`, failedIn + 3000},
		{"502", 502, ``, failedIn + 3000},
		{"503", 503, ``, failedIn + 3000},
		{"429", 429, `{"type":"error","error":{"type":"rate_limit_error","message":"x"}}`, failedIn},
		{"401", 401, `{"type":"error","error":{"type":"authentication_error","message":"x"}}`, failedIn},
		{"529 reporting usage", 529, `{"type":"error","error":{"type":"overloaded_error","message":"x"},"usage":{"input_tokens":5,"output_tokens":100}}`, 105},
		{"529 reporting less than input", 529, `{"type":"error","error":{"type":"overloaded_error","message":"x"},"usage":{"input_tokens":1,"output_tokens":1}}`, failedIn},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, rigOpts{maxOut: 6000})
			m := newFailoverMeter(t, r, 1<<40)
			r.up.set(hostAnthropic, serveFixture(c.status, "application/json", []byte(c.body)))
			r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
			if resp := doMetered(t, m, r); resp.StatusCode != 200 {
				t.Fatalf("status %d", resp.StatusCode)
			}
			if got, want := m.Usage("m1").Tokens, openAIServed+c.want; got != want {
				t.Errorf("charged %d, want %d (served %d + failed attempt %d)", got, want, openAIServed, c.want)
			}
		})
	}
}

// TestSR3_7f1aStreamFailureIsCharged: a stream that fails before the
// guest saw a byte fails over, and the failed attempt is charged its
// full output reservation.
func TestSR3_7f1aStreamFailureIsCharged(t *testing.T) {
	r := newRig(t, rigOpts{maxOut: 6000})
	m := newFailoverMeter(t, r, 1<<40)
	r.up.set(hostAnthropic, serveFixture(200, "text/event-stream", []byte("event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"x\"}}\n\n")))
	r.up.set(hostOpenAI, serveFixture(200, "text/event-stream", fixture(t, "openai_stream.sse")))
	body := strings.Replace(failedBody, `"max_tokens"`, `"stream":true,"max_tokens"`, 1)
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	w := httptest.NewRecorder()
	m.Wrap("m1", Routed(r.router)("m1")).ServeHTTP(w, req)
	if r.up.count(hostOpenAI) != 1 {
		t.Fatalf("no failover: %d %s", w.Code, w.Body)
	}
	if got, least := m.Usage("m1").Tokens, meter.Tokens(int64(len(body)))+3000; got < least {
		t.Errorf("charged %d, want at least the failed attempt's %d", got, least)
	}
}

// TestSR3_7f1aNoRouteServed: when every route fails over, the guest gets
// the last provider status and the meter charges each attempt, not the
// guest's error page.
func TestSR3_7f1aNoRouteServed(t *testing.T) {
	r := newRig(t, rigOpts{maxOut: 6000})
	m := newFailoverMeter(t, r, 1<<40)
	r.up.set(hostAnthropic, serveFixture(503, "application/json", nil))
	r.up.set(hostOpenAI, serveFixture(503, "application/json", nil))
	if resp := doMetered(t, m, r); resp.StatusCode != 503 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got, want := m.Usage("m1").Tokens, 2*(failedIn+3000); got != want {
		t.Errorf("charged %d, want two full reservations, %d", got, want)
	}
}

// TestSR3_7f1aServedFirstTimeUnchanged: a call served by its first route
// is charged its usage alone.
func TestSR3_7f1aServedFirstTimeUnchanged(t *testing.T) {
	r := newRig(t, rigOpts{maxOut: 6000, rule: Rule{"default": {{Provider: "openai", Model: "gpt-fixture"}, {Provider: "anthropic", Model: "claude-fixture"}}}})
	m := newFailoverMeter(t, r, 1<<40)
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if resp := doMetered(t, m, r); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := m.Usage("m1").Tokens; got != openAIServed {
		t.Errorf("charged %d, want %d", got, openAIServed)
	}
}

// TestSR3_7f1bBoundBeforeTheNextAttempt: when the meter cannot cover one
// more attempt at its worst charge, the router stops failing over before
// sending it and answers with the last provider status.
func TestSR3_7f1bBoundBeforeTheNextAttempt(t *testing.T) {
	r := newRig(t, rigOpts{maxOut: 6000})
	// Room for the first attempt's reservation, not a second.
	m := newFailoverMeter(t, r, failedIn+3000+100)
	r.up.set(hostAnthropic, serveFixture(504, "application/json", nil))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if resp := doMetered(t, m, r); resp.StatusCode != 504 {
		t.Errorf("status %d, want the last provider status 504", resp.StatusCode)
	}
	if n := r.up.count(hostOpenAI); n != 0 {
		t.Errorf("second route contacted %d times past the bound", n)
	}
	if got, want := m.Usage("m1").Tokens, failedIn+3000; got != want {
		t.Errorf("charged %d, want one full reservation %d", got, want)
	}

	// With room, the same call fails over and is charged both attempts.
	r2 := newRig(t, rigOpts{maxOut: 6000})
	m2 := newFailoverMeter(t, r2, 2*(failedIn+3000))
	r2.up.set(hostAnthropic, serveFixture(504, "application/json", nil))
	r2.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	if resp := doMetered(t, m2, r2); resp.StatusCode != 200 {
		t.Errorf("status %d with room for two attempts", resp.StatusCode)
	}
}

// TestSR3_7f1cUsageCarriesFailedAttempts: the router's usage report
// carries each failed attempt and its class, and reaches the caller even
// when no route served the call.
func TestSR3_7f1cUsageCarriesFailedAttempts(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(429, "application/json", nil))
	r.up.set(hostOpenAI, serveFixture(504, "application/json", nil))
	var got []Usage
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(failedBody))
	req = req.WithContext(WithUsage(anyAttempt(req).Context(), func(_ string, u Usage) { got = append(got, u) }))
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, req)
	if w.Code != 504 || len(got) != 1 {
		t.Fatalf("status %d, %d reports", w.Code, len(got))
	}
	u := got[0]
	if !u.Unserved || len(u.Failed) != 2 || u.Failed[0].Full || u.Failed[0].Provider != "anthropic" || u.Failed[0].Status != 429 ||
		!u.Failed[1].Full || u.Failed[1].Provider != "openai" || u.Failed[1].Status != 504 {
		t.Errorf("report %+v", u)
	}
}

// TestSR3_7f1aFailedThenProviderError: a call that fails over and is then
// answered by the next provider's own error, with no usage, is charged
// the failed attempt's full reservation on top of the error page.
func TestSR3_7f1aFailedThenProviderError(t *testing.T) {
	r := newRig(t, rigOpts{maxOut: 6000})
	m := newFailoverMeter(t, r, 1<<40)
	r.up.set(hostAnthropic, serveFixture(504, "application/json", nil))
	r.up.set(hostOpenAI, serveFixture(400, "application/json", []byte(`{"error":{"type":"invalid_request_error","message":"x"}}`)))
	if resp := doMetered(t, m, r); resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got, least := m.Usage("m1").Tokens, failedIn+3000; got < least {
		t.Errorf("charged %d, want at least the failed attempt's full reservation %d", got, least)
	}
}

// TestSR3_7f1bNoHookNoExtraAttempt: a router asked without a WithAttempt
// hook fails closed: it sends no attempt past the first and answers with
// that provider's status.
func TestSR3_7f1bNoHookNoExtraAttempt(t *testing.T) {
	r := newRig(t, rigOpts{})
	r.up.set(hostAnthropic, serveFixture(504, "application/json", nil))
	r.up.set(hostOpenAI, serveFixture(200, "application/json", fixture(t, "openai_completion.json")))
	req, _ := http.NewRequest("POST", "/v1/chat/completions", strings.NewReader(failedBody))
	w := httptest.NewRecorder()
	r.router.Handler("m1").ServeHTTP(w, req)
	if w.Code != 504 {
		t.Errorf("status %d, want the first provider's 504", w.Code)
	}
	if n := r.up.count(hostOpenAI); n != 0 {
		t.Errorf("second route contacted %d times without a hook", n)
	}
}
