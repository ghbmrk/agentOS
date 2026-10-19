package egress

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
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
		// A read goes bodiless, so it is refused for its path, not for
		// carrying a body.
		var body io.Reader = http.NoBody
		if c.method != "GET" {
			body = strings.NewReader(codexBody(clientTools))
		}
		req := httptest.NewRequest(c.method, "http://127.0.0.1:18432"+c.path, body)
		req.Header.Set("Authorization", "Bearer ph-access-w1")
		if c.method != "GET" {
			req.Header.Set("Content-Type", "application/json")
		}
		w := r.do(req)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "no declared endpoint matches") {
			t.Errorf("%s %s: %d %q, want 403 for no declared endpoint", c.method, c.path, w.Code, w.Body)
		}
		if strings.Contains(w.Body.String(), r.logins.real["access_token"]) {
			t.Errorf("%s %s: the real login reached the worker", c.method, c.path)
		}
	}
	if r.up.count() != 0 {
		t.Fatalf("a cloud request reached the provider: %v", r.up.urls)
	}
	// The route declares exactly the model call, the model list, the
	// refresh and the sign-in exchanges, on every host: any other endpoint
	// is a cloud, sync or telemetry feature the route must not declare
	// (ARC-3), and the credential would be injected there.
	want := []string{
		"code POST auth.openai.com/oauth/token code signin=true",
		"devicetoken POST auth.openai.com/api/accounts/deviceauth/token device signin=true",
		"models GET chatgpt.com/backend-api/codex/models read signin=false",
		"refresh POST auth.openai.com/oauth/token refresh signin=false",
		"responses POST chatgpt.com/backend-api/codex/responses responses signin=false",
		"usercode POST auth.openai.com/api/accounts/deviceauth/usercode device signin=true",
	}
	var got []string
	for _, e := range Codex().Endpoints {
		got = append(got, fmt.Sprintf("%s %s %s%s %s signin=%t", e.Name, e.Method, e.Host, e.Path, e.Kind, e.SignIn))
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("codex route endpoints:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
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
