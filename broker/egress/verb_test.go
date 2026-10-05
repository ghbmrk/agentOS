package egress

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: ADP-10, ADP-2

// mailAdapter declares one read and one effectful operation.
func mailAdapter() Adapter {
	return Adapter{
		Name: "mail", Host: "mail.example.com", Credential: "openai-key",
		Inject: Injection{Header: "Authorization", Prefix: "Bearer "},
		Operations: []Operation{
			{Name: "list", Verb: VerbRead, Method: "GET", Path: "/v1/messages"},
			{Name: "send", Verb: VerbSend, Method: "POST", Path: "/v1/send"},
		},
	}
}

// TestADP10VerbClassAppliedBeforeForwarding: a request matching an
// operation whose verb is not read is denied and reported before anything
// is sent, because no intent path for proxy-forwarded effects exists yet
// (E9). Reads are forwarded as before.
func TestADP10VerbClassAppliedBeforeForwarding(t *testing.T) {
	r := newRig(t, nil)
	p, err := New(Config{
		Adapters:  []Adapter{mailAdapter()},
		Grants:    map[string][]string{"m1": {"mail"}},
		Vault:     r.vault,
		Transport: r.transport,
		Audit:     r.audit,
	})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, httptest.NewRequest("POST", "/mail/v1/send", strings.NewReader(`{}`)))
	if w.Code != http.StatusForbidden || r.provider.count() != 0 {
		t.Fatalf("effectful operation: status %d, %d upstream requests", w.Code, r.provider.count())
	}
	if ev := r.audit.last(t); ev.Allowed || ev.Operation != "send" || !strings.Contains(ev.Reason, "intent") {
		t.Fatalf("audit %+v", ev)
	}
	w = httptest.NewRecorder()
	p.Handler("m1").ServeHTTP(w, httptest.NewRequest("GET", "/mail/v1/messages", nil))
	if w.Code != http.StatusOK || r.provider.count() != 1 {
		t.Fatalf("read operation: status %d, %d upstream requests", w.Code, r.provider.count())
	}
}

// TestADP2EveryOperationMapsToOneFixedVerb: an operation with no verb, or
// a verb outside the broker's closed list, is refused at construction.
func TestADP2EveryOperationMapsToOneFixedVerb(t *testing.T) {
	for _, verb := range []string{"", "post-ish", "READ"} {
		a := mailAdapter()
		a.Operations = []Operation{{Name: "x", Verb: verb, Method: "GET", Path: "/v1/x"}}
		if _, err := New(Config{Adapters: []Adapter{a}, Vault: emptyVault{}, Audit: &auditLog{}}); err == nil {
			t.Errorf("verb %q accepted", verb)
		}
	}
	for _, a := range []Adapter{OpenAI("k"), Anthropic("k")} {
		for _, op := range a.Operations {
			if op.Verb != VerbRead {
				t.Errorf("%s %s is %q; model inference is a read", a.Name, op.Name, op.Verb)
			}
		}
	}
}
