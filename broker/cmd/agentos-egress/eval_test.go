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
		Active: route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}}
	sock := serveModel(t, testRouter(t), ev, func(w http.ResponseWriter, r *http.Request) {
		var body struct{ Model string }
		json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		models = append(models, body.Model)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
	evaluation := modelroute.Evaluation(modelroute.Config{Socket: sock, Label: func(string) string { return "public" },
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
