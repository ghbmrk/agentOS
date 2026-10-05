package egress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: REV-5, ADP-10, CRED-5

// HandlerFor serves the proxy from a process of its own (P2-4): the broker
// that owns the guest socket names the machine and its REV-5 label for each
// request, and receives that request's decisions. The label given wins
// over Config.Label, and the per-request auditor replaces Config.Audit.
func TestHandlerForTakesLabelAndAuditPerRequest(t *testing.T) {
	r := newRig(t, map[string][]string{"m1": {"openai"}})
	search := `{"model":"m","tools":[{"type":"web_search"}]}`
	send := func(label string, a Auditor) int {
		w := httptest.NewRecorder()
		r.proxy.HandlerFor("m1", label, a).ServeHTTP(w, httptest.NewRequest("POST", "/openai/v1/chat/completions", strings.NewReader(search)))
		return w.Code
	}
	mine := &auditLog{}
	for _, label := range []string{"private", "", "Public"} {
		if c := send(label, mine); c != http.StatusForbidden {
			t.Fatalf("label %q: server tool got %d", label, c)
		}
	}
	if ev := mine.last(t); ev.Machine != "m1" || ev.Allowed || ev.Status != http.StatusForbidden {
		t.Fatalf("per-request audit got %+v", ev)
	}
	if len(r.audit.evs) != 0 {
		t.Fatalf("Config.Audit saw %d per-request decisions", len(r.audit.evs))
	}
	if c := send(LabelPublic, mine); c != 200 {
		t.Fatalf("public: %d", c)
	}
	if !strings.Contains(r.provider.seen[0].Header.Get("Authorization"), r.key) {
		t.Fatal("key not injected")
	}
	if c := send(LabelPublic, nil); c != http.StatusInternalServerError || r.provider.count() != 1 {
		t.Fatalf("nil auditor: %d, provider saw %d", c, r.provider.count())
	}
}

// REQ: LOOP-5

// A replay machine's calls use the agent machine's adapter grants but are
// admitted against the replay machine's own limits, so a burst of
// evaluation never holds the live agent's slots or spends its cap (L3 R1
// on #62).
func TestLOOP5ReplayCallsCountAgainstTheReplayMachine(t *testing.T) {
	r := newRig(t, nil)
	p, err := New(Config{
		Adapters: []Adapter{OpenAI("openai-key")}, Grants: map[string][]string{"agent": {"openai"}},
		Vault: r.vault, Audit: r.audit, Transport: r.transport, Cap: Cap{Requests: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(h http.Handler) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, chat("/openai/v1/chat/completions"))
		return w.Code
	}
	eval := p.HandlerWithGrantsOf("eval-0a1b", "agent", "private", r.audit)
	if c := do(eval); c != 200 {
		t.Fatalf("replay call under the agent's grants: %d", c)
	}
	if c := do(eval); c != http.StatusTooManyRequests {
		t.Fatalf("replay machine over its own cap: %d", c)
	}
	if c := do(p.HandlerFor("agent", "private", r.audit)); c != 200 {
		t.Fatalf("live agent after a replay burst: %d", c)
	}
	if c := do(p.HandlerWithGrantsOf("eval-0a1b", "nobody", "private", r.audit)); c != http.StatusForbidden {
		t.Fatalf("grants of an ungranted machine: %d", c)
	}
}
