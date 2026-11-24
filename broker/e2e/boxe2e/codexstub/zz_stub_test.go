package codexstub

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: HW-10

// A declared endpoint the stub has no handler for panics in New, naming
// the endpoint, so a route change shows up in the stub's own tests.
func TestNewPanicsOnAnEndpointWithNoHandler(t *testing.T) {
	h := handlers["models"]
	delete(handlers, "models")
	defer func() {
		handlers["models"] = h
		if r, _ := recover().(string); r != "codexstub: no handler for endpoint models" {
			t.Fatalf("recovered %q, want the models panic", r)
		}
	}()
	New()
}

// The redirect the code exchange must carry is the code endpoint's own
// host and the route's callback path, set only from the code endpoint:
// a route whose other endpoints sit on another host leaves it unchanged.
func TestNewTakesTheRedirectFromTheCodeEndpoint(t *testing.T) {
	if got, want := New().redirect, "https://auth.openai.com/deviceauth/callback"; got != want {
		t.Fatalf("redirect %q, want %q", got, want)
	}
	r := egress.Codex()
	for i := range r.Endpoints {
		if r.Endpoints[i].Kind != egress.KindCode {
			r.Endpoints[i].Host = "other.example"
		}
	}
	if got, want := newStub(r).redirect, "https://auth.openai.com/deviceauth/callback"; got != want {
		t.Fatalf("redirect %q, want %q", got, want)
	}
}

// Hosts lists each provider host once, in declaration order.
func TestHostsListsEachHostOnce(t *testing.T) {
	if got := strings.Join(New().Hosts(), " "); got != "chatgpt.com auth.openai.com" {
		t.Fatalf("hosts %q", got)
	}
}

type badBody struct{}

func (badBody) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

// A body the stub cannot read is refused with 400 and counted, before any
// endpoint is matched.
func TestStubRefusesAnUnreadableBody(t *testing.T) {
	s := New()
	req := httptest.NewRequest("POST", "https://auth.openai.com/api/accounts/deviceauth/usercode", badBody{})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	if w.Code != 400 || s.Refused() != 1 || s.Hits()["usercode"] != 0 {
		t.Fatalf("%d, refused %d, hits %v", w.Code, s.Refused(), s.Hits())
	}
}

// The user-code request needs a client_id in a JSON body; without one it
// is refused and no code is issued.
func TestUsercodeNeedsAClientID(t *testing.T) {
	for _, body := range []string{`{}`, `{"client_id":""}`, `not json`} {
		s := New()
		req := httptest.NewRequest("POST", "https://auth.openai.com/api/accounts/deviceauth/usercode", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code != 401 || s.Refused() != 1 || s.user != "" {
			t.Fatalf("%s: %d, refused %d, user %q", body, w.Code, s.Refused(), s.user)
		}
	}
}

// Each user code is random in the route's shape: two codes differ.
func TestUserCodesAreRandom(t *testing.T) {
	a, b := userCode(), userCode()
	if a == b || len(a) != 9 || a[4] != '-' {
		t.Fatalf("codes %q %q", a, b)
	}
}
