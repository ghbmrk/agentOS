package egress

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// REQ: CRED-5, A11

// Config.Granted grants per request what Grants does not (CRED-5f-mr-grant:
// a key stored at setup grants its provider to the agent machine). It is
// asked with the calling machine and the adapter; its answer can
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
		Granted: func(machine, adapter string) bool {
			asked = append(asked, machine+"/"+adapter)
			return stored && machine == "m1" && adapter == "openai"
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

// Granted is asked about the calling machine, never the grants entry a
// replay or builder machine borrows: a key stored for the agent grants
// the agent alone, so an eval replay or a builder served on the agent's
// grants is refused the stored-key provider (CRED-5f-mr-grant, S1).
func TestGrantedAsksTheCallingMachine(t *testing.T) {
	r := newRig(t, map[string][]string{"agent": {"anthropic"}})
	var asked []string
	p, err := New(Config{
		Adapters:  []Adapter{OpenAI("openai-key"), Anthropic("openai-key")},
		Grants:    map[string][]string{"agent": {"anthropic"}},
		Vault:     r.vault,
		Transport: r.transport,
		Audit:     r.audit,
		Granted: func(machine, adapter string) bool {
			asked = append(asked, machine)
			return machine == "agent" && adapter == "openai"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(h http.Handler) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, chat("/openai/v1/chat/completions"))
		return w.Code
	}
	if c := do(p.HandlerFor("agent", "private", r.audit)); c != http.StatusOK || r.provider.count() != 1 {
		t.Fatalf("agent: %d", c)
	}
	for _, m := range []string{"eval-0a1b", "lb-0a1b"} {
		asked = nil
		if c := do(p.HandlerWithGrantsOf(m, "agent", "private", r.audit)); c != http.StatusForbidden || r.provider.count() != 1 {
			t.Fatalf("%s on the agent's grants: %d", m, c)
		}
		if len(asked) != 1 || asked[0] != m {
			t.Fatalf("%s: Granted asked %v", m, asked)
		}
	}
	// The borrowed static grant still serves the replay.
	w := httptest.NewRecorder()
	p.HandlerWithGrantsOf("eval-0a1b", "agent", "private", r.audit).ServeHTTP(w, chat("/anthropic/v1/messages"))
	if w.Code != http.StatusOK {
		t.Fatalf("static grant on replay: %d", w.Code)
	}
}
