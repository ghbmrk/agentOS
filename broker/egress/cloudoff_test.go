package egress

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// REQ: ARC3-C2, ARC3-C4

// A CLI guest's cloud features with no known off switch are [Open]
// (guest/codex/ASSUMPTIONS.md ARC3-guest-cloud-off-1): their endpoints are absent from the
// route, so a request to one fails by absence, reaches no provider and
// carries no credential. The paths are the ChatGPT backend's cloud-task,
// remote-run and session-sync APIs the open-source CLI names; they are
// inferred from its source, not measured on 0.162.1.
func TestCLIGuestCloudEndpointRefusedNoCredential(t *testing.T) {
	r := newWorkerRig(t, false)
	cloud := []struct{ method, path string }{
		{"GET", "/backend-api/wham/tasks/list"},
		{"POST", "/backend-api/wham/tasks"},
		{"GET", "/backend-api/wham/environments"},
		{"POST", "/backend-api/wham/remote/run"},
		{"POST", "/backend-api/conversation"},
		{"GET", "/backend-api/conversations"},
		{"POST", "/backend-api/codex/sessions/sync"},
		{"POST", "/backend-api/codex/analytics-events/events"},
	}
	for _, c := range cloud {
		req := httptest.NewRequest(c.method, "http://127.0.0.1:18432"+c.path, strings.NewReader(codexBody(clientTools)))
		req.Header.Set("Authorization", "Bearer ph-access-w1")
		req.Header.Set("Content-Type", "application/json")
		w := r.do(req)
		if w.Code != 403 {
			t.Errorf("%s %s: %d, want 403", c.method, c.path, w.Code)
		}
		if strings.Contains(w.Body.String(), r.logins.real["access_token"]) {
			t.Errorf("%s %s: the real login reached the worker", c.method, c.path)
		}
	}
	if r.up.count() != 0 {
		t.Fatalf("a cloud request reached the provider: %v", r.up.urls)
	}
	// The run host carries only the model call and the model list: any
	// other path there is a cloud or remote feature the route must not
	// declare (ARC-3).
	for _, e := range Codex().Endpoints {
		if e.Host == "chatgpt.com" && e.Path != "/backend-api/codex/responses" && e.Path != "/backend-api/codex/models" {
			t.Errorf("codex route declares %s %s", e.Method, e.Path)
		}
	}
}

// With the cloud features off, the model call still goes out with the real
// login injected (ARC3-C4).
func TestCLIGuestModelEndpointStillInjected(t *testing.T) {
	r := newWorkerRig(t, false)
	w := r.do(responses(codexBody(clientTools)))
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body)
	}
	if r.up.count() != 1 || r.up.urls[0] != "https://chatgpt.com/backend-api/codex/responses" {
		t.Fatalf("upstream saw %v", r.up.urls)
	}
	if r.up.reqs[0].Header.Get("Authorization") != "Bearer "+r.logins.real["access_token"] {
		t.Fatal("the real access token was not injected")
	}
}
