package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: LOOP-5, ADP-4, CAP-9, REV-5

var testPrices = prices{
	"openai/gpt-test":       {Input: 2, Output: 8},
	"openai/gpt-eval":       {Input: 1, Output: 8},
	"anthropic/claude-eval": {Input: 1, Output: 4},
	"openai/gpt-big":        {Input: 2, Output: 30},
	"openai/gpt-in":         {Input: 3, Output: 8},
	"openai/a":              {Input: 10, Output: 1},
	"openai/b":              {Input: 1, Output: 10},
	"openai/c":              {Input: 10, Output: 10},
	"anthropic/claude-a":    {Input: 50, Output: 50},
}

// A replay machine's model calls (LOOP-5) are routed by the rule of the
// tree under evaluation, but only among the routes the owner granted the
// agent machine, under its private-data allowance, and always as private
// data (replay K1). A rule naming a provider the owner did not grant gets
// no route; an unreadable rule fails the call; without a rule the active
// one applies.
func TestLOOP5EvaluationRuleOnlyReordersGrantedRoutes(t *testing.T) {
	var mu sync.Mutex
	var models []string
	ev := &evalRoute{From: "agent", Grants: []string{"openai"}, PrivateOK: map[string]bool{"openai": true},
		Active: route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}, Prices: testPrices}
	sock := serveModel(t, testRouter(t), ev, func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Model string }
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		models = append(models, body.Model)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
	evaluation := modelroute.Evaluation(modelroute.Config{OverCeiling: func(string) {}, Socket: sock, Label: func(string) string { return "public" },
		Denied: func(string, modelroute.Denial) {}})
	ask := func(rule string) *http.Response {
		var b []byte
		if rule != "" {
			b = []byte(rule)
		}
		return chat(evaluation("eval-0a1b", b))
	}

	if resp := ask(`{"default":[{"provider":"openai","model":"gpt-eval"}]}`); resp.StatusCode != 200 {
		t.Fatalf("granted rule: %d", resp.StatusCode)
	}
	if resp := ask(""); resp.StatusCode != 200 {
		t.Fatalf("active rule: %d", resp.StatusCode)
	}
	mu.Lock()
	if len(models) != 2 || models[0] != "gpt-eval" || models[1] != "gpt-test" {
		t.Fatalf("provider saw models %q", models)
	}
	mu.Unlock()
	if resp := ask(`{"default":[{"provider":"anthropic","model":"claude-eval"}]}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("ungranted provider: %d", resp.StatusCode)
	}
	if resp := ask(`{"default":`); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unreadable rule: %d", resp.StatusCode)
	}
	if len(models) != 2 {
		t.Fatalf("a refused rule reached a provider: %q", models)
	}
}

// Only replay machines carry a rule, and only when the vault process was
// given evaluation access: a live machine sending one, or a replay machine
// with no -eval-from, is refused before any route.
func TestLOOP5RuleRefusedOutsideEvaluation(t *testing.T) {
	c := &custody{now: time.Now, notify: func(string) {}}
	rule := base64.StdEncoding.EncodeToString([]byte(`{"default":[{"provider":"openai","model":"x"}]}`))
	for _, tc := range []struct {
		machine string
		ev      *evalRoute
		want    int
	}{
		{"agent", &evalRoute{From: "agent"}, http.StatusBadRequest},
		{"eval-0a1b", nil, http.StatusServiceUnavailable},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
		r.Header.Set(modelroute.HeaderMachine, tc.machine)
		r.Header.Set(modelroute.HeaderRule, rule)
		modelHandler(c, testRouter(t), tc.ev).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Errorf("%s: %d, want %d", tc.machine, w.Code, tc.want)
		}
	}
}

// Security C1 on #62 (arbitrator's amendment): a tree under evaluation may
// route only to models priced, per token, at most like the dearest route
// in the active rule, from this process's own price table. A dearer or
// unpriced model is refused before any provider sees the call, and the
// refusal names the ceiling so the broker reports the tree as not
// evaluated, never as passing or failing.
func TestLOOP5EvaluationRoutesStayUnderTheActivePriceCeiling(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ev := &evalRoute{From: "agent", Grants: []string{"openai"}, PrivateOK: map[string]bool{"openai": true},
		Active: route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}, Prices: testPrices}
	sock := serveModel(t, testRouter(t), ev, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		io.WriteString(w, `{}`)
	})
	var denied []modelroute.Denial
	evaluation := modelroute.Evaluation(modelroute.Config{OverCeiling: func(string) {}, Socket: sock, Label: func(string) string { return "private" },
		Denied: func(_ string, d modelroute.Denial) { denied = append(denied, d) }})
	for _, model := range []string{"gpt-big", "gpt-in", "gpt-unknown"} {
		rule := `{"default":[{"provider":"openai","model":"gpt-eval"},{"provider":"openai","model":"` + model + `"}]}`
		resp := chat(evaluation("eval-0a1b", []byte(rule)))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: %d", model, resp.StatusCode)
		}
	}
	mu.Lock()
	if calls != 0 {
		t.Fatalf("a provider saw %d refused calls", calls)
	}
	mu.Unlock()
	if len(denied) != 3 || denied[0].Reason != modelroute.ReasonEvalCeiling || denied[2].Reason != modelroute.ReasonEvalCeiling {
		t.Fatalf("denials %+v", denied)
	}

	// An unpriced active rule gives no ceiling: every evaluation call is
	// refused.
	unpriced := &evalRoute{From: "agent", Grants: []string{"openai"}, PrivateOK: map[string]bool{"openai": true},
		Active: route.Rule{"default": {{Provider: "openai", Model: "gpt-unknown"}}}, Prices: testPrices}
	evaluation = modelroute.Evaluation(modelroute.Config{OverCeiling: func(string) {}, Socket: serveModel(t, testRouter(t), unpriced, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		io.WriteString(w, `{}`)
	}), Label: func(string) string { return "private" }, Denied: func(string, modelroute.Denial) {}})
	if resp := chat(evaluation("eval-0a1b", []byte(`{"default":[{"provider":"openai","model":"gpt-eval"}]}`))); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unpriced active rule: %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 0 {
		t.Fatalf("a provider saw %d refused calls", calls)
	}
}

// Each route a tree names must be no dearer, in input and in output price,
// than one route of the active rule on a provider the agent machine is
// granted: two cheap-on-one-axis active routes do not admit a route dear
// on both, and an ungranted dear active route raises no ceiling (L3 F2).
func TestLOOP5CeilingIsOneDominatingGrantedRoute(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	ev := &evalRoute{From: "agent", Grants: []string{"openai"}, PrivateOK: map[string]bool{"openai": true},
		Active: route.Rule{"default": {{Provider: "openai", Model: "a"}, {Provider: "openai", Model: "b"}, {Provider: "anthropic", Model: "claude-a"}}},
		Prices: testPrices}
	sock := serveModel(t, testRouter(t), ev, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
	evaluation := modelroute.Evaluation(modelroute.Config{OverCeiling: func(string) {}, Socket: sock, Label: func(string) string { return "private" },
		Denied: func(string, modelroute.Denial) {}})
	ask := func(model string) int {
		return chat(evaluation("eval-0a1b", []byte(`{"default":[{"provider":"openai","model":"`+model+`"}]}`))).StatusCode
	}
	if c := ask("c"); c != http.StatusForbidden {
		t.Fatalf("route dear on both axes: %d", c)
	}
	if c := ask("b"); c != 200 {
		t.Fatalf("an active route itself: %d", c)
	}
	if c := chat(evaluation("eval-0a1b", nil)).StatusCode; c != 200 {
		t.Fatalf("the active rule, with an ungranted dear route: %d", c)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("provider saw %d calls, want 2", calls)
	}
}
