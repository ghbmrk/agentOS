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
	if _, err := builderGrants(grants{"agent": {"openai"}}, "lb-x"); err == nil {
		t.Fatal("-builder-from named a builder machine")
	}
	g, err := builderGrants(grants{"agent": {"openai"}}, "agent")
	if err != nil || len(g[modelroute.BuilderPrefix]) != 1 {
		t.Fatalf("builder grants %v %v", g, err)
	}
	none, _ := builderGrants(grants{"agent": {"openai"}}, "")
	rule := route.Rule{"default": {{Provider: "openai", Model: "gpt-test"}}}
	ok := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}
	for _, tc := range []struct {
		name      string
		g         grants
		privateOK map[string]bool
		machine   string
		want      int
	}{
		{"builder, provider allowed private data", g, map[string]bool{"openai": true}, "lb-0a1b", 200},
		{"builder sent as public is still private", g, map[string]bool{}, "lb-0a1b", http.StatusForbidden},
		{"agent sent as public", g, map[string]bool{}, "agent", 200},
		{"no -builder-from", none, map[string]bool{"openai": true}, "lb-0a1b", http.StatusForbidden},
	} {
		rt, err := newRouter(rule, tc.g, tc.privateOK)
		if err != nil {
			t.Fatal(err)
		}
		sock := serveModelGrants(t, rt, nil, tc.g, ok)
		fwd := modelroute.Forward(modelroute.Config{Socket: sock, Label: func(string) string { return "public" }, Denied: func(string, modelroute.Denial) {}})
		if resp := chat(fwd(tc.machine)); resp.StatusCode != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}
}
