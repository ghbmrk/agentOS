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
