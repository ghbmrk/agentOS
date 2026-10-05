package main

import (
	"io"
	"net/http"
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/route"
)

// REQ: REV-5, CAP-9

// W3-builder (security C-3c-6): a Loop 1 builder machine (modelroute.
// BuilderPrefix) takes -builder-from's grants, always as private data
// whatever label the broker sends, never grants of its own; with no
// -builder-from it has none.
func TestBuilderMachinesTakeBuilderFromsGrantsAsPrivate(t *testing.T) {
	if _, err := builderGrants(grants{"lb-x": {"openai"}}, ""); err == nil {
		t.Fatal("-grant gave a builder machine grants of its own")
	}
	for _, from := range []string{"lb-x", "eval-x"} {
		if _, err := builderGrants(grants{"agent": {"openai"}, from: {"openai"}}, from); err == nil {
			t.Fatalf("-builder-from named %s", from)
		}
	}
	// L3 S5 on #126: a -builder-from with no grants is a mistake, not a
	// builder with no model access.
	if _, err := builderGrants(grants{"agent": {"openai"}}, "agnet"); err == nil {
		t.Fatal("-builder-from named a machine with no grants")
	}
	rule := route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}
	// Security R1 on #126: -eval-from never names builders' grants.
	for _, from := range []string{"lb-", "lb-x", "eval-x"} {
		if _, _, err := modelRouting(rule, grants{"agent": {"openai"}}, nil, "agent", from); err == nil {
			t.Fatalf("-eval-from %s was accepted", from)
		}
	}
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}
	for _, tc := range []struct {
		name      string
		from      string
		privateOK map[string]bool
		machine   string
		want      int
	}{
		{"builder, provider allowed private data", "agent", map[string]bool{"openai": true}, "lb-0a1b", 200},
		{"builder sent as public is still private", "agent", map[string]bool{}, "lb-0a1b", http.StatusForbidden},
		{"agent sent as public", "agent", map[string]bool{}, "agent", 200},
		{"no -builder-from", "", map[string]bool{"openai": true}, "lb-0a1b", http.StatusForbidden},
	} {
		// The same setup run uses, so the router sees the builder's
		// grants (L3 MUST 1 on #126).
		g, rt, err := modelRouting(rule, grants{"agent": {"openai"}}, tc.privateOK, tc.from, "")
		if err != nil {
			t.Fatal(err)
		}
		sock := serveModelGrants(t, rt, nil, g, ok)
		fwd := modelroute.Forward(modelroute.Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, modelroute.Denial) {}})
		if resp := chat(fwd(tc.machine)); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}
