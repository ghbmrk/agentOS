package route

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: CAP-9, REV-5, OP-8
//
// HandlerFor takes the label, the egress handler, and an auditor per
// request, as the vault process gets them from the forwarding broker.

func (r *rig) doFor(t *testing.T, machine, label string, audit func(Decision)) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(simpleChat))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.router.HandlerFor(machine, label, r.px.HandlerFor(machine, label, r), audit).ServeHTTP(w, req)
	return w
}

func TestHandlerForTakesLabelPerRequest(t *testing.T) {
	// The configured label says private and no provider is allowed for
	// private data; only the per-request label decides here.
	r := newRig(t, rigOpts{labels: map[string]string{"m1": "private"}})
	r.up.set(hostAnthropic, serveFixture(200, "application/json", fixture(t, "anthropic_message.json")))
	if w := r.do(t, "m1", simpleChat); w.Code != http.StatusForbidden {
		t.Fatalf("Handler with a private label: %d, want 403", w.Code)
	}
	for _, label := range []string{"private", "", "Public", "public "} {
		var got []Decision
		w := r.doFor(t, "m1", label, func(d Decision) { got = append(got, d) })
		if w.Code != http.StatusForbidden || len(got) != 1 || got[0].Outcome != Denied {
			t.Fatalf("label %q: %d %+v, want one 403 denial", label, w.Code, got)
		}
	}
	if r.up.count(hostAnthropic) != 0 {
		t.Fatal("a private call reached a provider not allowed for private data")
	}

	var got []Decision
	w := r.doFor(t, "m1", LabelPublic, func(d Decision) { got = append(got, d) })
	if w.Code != 200 || completionText(t, w) != "Checking the weather." {
		t.Fatalf("public: %d %s", w.Code, w.Body)
	}
	if len(got) != 1 || got[0].Outcome != Served || got[0].Usage == nil || !got[0].Usage.Reported {
		t.Fatalf("per-request audit: %+v", got)
	}
	r.mu.Lock()
	n := len(r.decisions)
	r.mu.Unlock()
	if n != 6 {
		t.Fatalf("Config.Audit saw %d decisions, want every one (6)", n)
	}
}

// The egress handler given per request is the one called, so its own
// denials (here the grant, checked again by the proxy) reach the guest
// and the per-request audit.
func TestHandlerForUsesGivenUpstream(t *testing.T) {
	r := newRig(t, rigOpts{})
	calls := 0
	up := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		w.Header().Set(deniedHeader, "1")
		http.Error(w, "egress denied: test", http.StatusForbidden)
	})
	var got []Decision
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(simpleChat))
	w := httptest.NewRecorder()
	r.router.HandlerFor("m1", LabelPublic, up, func(d Decision) { got = append(got, d) }).ServeHTTP(w, req)
	if calls != 1 || w.Code != http.StatusForbidden || len(got) != 1 || got[0].Reason != "egress denied" {
		t.Fatalf("calls=%d code=%d decisions=%+v", calls, w.Code, got)
	}
	if r.up.count(hostAnthropic)+r.up.count(hostOpenAI) != 0 {
		t.Fatal("the configured upstream was used")
	}
}
