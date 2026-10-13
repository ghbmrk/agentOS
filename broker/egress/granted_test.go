package egress

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ: CRED-5, A11

// Config.Granted grants per request what Grants does not (CRED-5f-mr-grant:
// a key stored at setup grants its provider to the agent machine). It is
// asked with the machine's grants entry and the adapter; its answer can
// change while the proxy serves, and it never takes back a static grant.
func TestGrantedAddsPerRequestGrants(t *testing.T) {
	r := newRig(t, map[string][]string{"m1": {"anthropic"}})
	stored := false
	var asked []string
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key"), Anthropic("openai-key")},
		Grants:    map[string][]string{"m1": {"anthropic"}},
		Vault:     r.vault,
		Transport: r.transport,
		Audit:     r.audit,
		Granted: func(grantsOf, adapter string) bool {
			asked = append(asked, grantsOf+"/"+adapter)
			return stored && grantsOf == "m1" && adapter == "openai"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(machine, path string) int {
		w := httptest.NewRecorder()
		p.Handler(machine).ServeHTTP(w, chat(path))
		return w.Code
	}
	if c := do("m1", "/openai/v1/chat/completions"); c != http.StatusForbidden || r.provider.count() != 0 {
		t.Fatalf("not yet granted: %d", c)
	}
	stored = true
	if c := do("m1", "/openai/v1/chat/completions"); c != http.StatusOK || r.provider.count() != 1 {
		t.Fatalf("granted: %d", c)
	}
	if c := do("m2", "/openai/v1/chat/completions"); c != http.StatusForbidden || r.provider.count() != 1 {
		t.Fatalf("another machine: %d", c)
	}
	// A static grant is served without asking.
	asked = nil
	do("m1", "/anthropic/v1/messages")
	if len(asked) != 0 {
		t.Fatalf("asked for a static grant: %v", asked)
	}
}
