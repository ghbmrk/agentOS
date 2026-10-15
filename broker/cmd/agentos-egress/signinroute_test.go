package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: CRED-5, CRED-1, ONB-3, CAP-9, A14

// signInCall posts body to path on the auth host's forwarder origin, over
// the worker's route socket, as the sign-in CLI does.
func signInCall(t *testing.T, sock, path, body string) int {
	t.Helper()
	cl := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		},
	}}
	req, _ := http.NewRequest("POST", "http://127.0.0.1:18432"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (r *workerRig) openVerb(t *testing.T, verb, machine string) string {
	t.Helper()
	w := r.call(verb, machine)
	if w.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", verb, machine, w.Code, w.Body)
	}
	var out struct{ Dir string }
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Dir == "" {
		t.Fatalf("%s %s: bad reply %q", verb, machine, w.Body)
	}
	return out.Dir
}

// #1264 c4e2: /signin opens a worker's route on the sign-in endpoints
// only (the owner's device-code sign-in, ONB step 6): the device-auth call
// reaches the auth host, and a model call is refused. A worker opened with
// /open gets the run endpoints and no sign-in endpoint, so a run worker
// cannot sign the box in to its own account.
func TestCRED5SignInOpensOnlyTheSignInEndpoints(t *testing.T) {
	r := newWorkerRig(t)
	sock := filepath.Join(r.openVerb(t, "signin", "pw-s"), RouteSocket)
	signInCall(t, sock, "/api/accounts/deviceauth/usercode", `{"client_id":"app_synthetic"}`)
	if len(r.up.seen) != 1 || r.up.seen[0].URL.String() != "https://auth.openai.com/api/accounts/deviceauth/usercode" {
		t.Fatalf("sign-in route: upstream saw %v", r.up.seen)
	}
	resp, err := through(t, sock, "ph-access-pw-s", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK || len(r.up.seen) != 1 {
		t.Fatalf("sign-in route served a model call: %d, upstream %d", resp.StatusCode, len(r.up.seen))
	}

	run := filepath.Join(r.open(t, "pw-r"), RouteSocket)
	if st := signInCall(t, run, "/api/accounts/deviceauth/usercode", `{"client_id":"app_synthetic"}`); st == http.StatusOK || len(r.up.seen) != 1 {
		t.Fatalf("run route served sign-in: %d, upstream %d", st, len(r.up.seen))
	}
	// A reopen with /open turns a sign-in worker's route into a run route.
	sock = filepath.Join(r.open(t, "pw-s"), RouteSocket)
	if st := signInCall(t, sock, "/api/accounts/deviceauth/usercode", `{"client_id":"app_synthetic"}`); st == http.StatusOK || len(r.up.seen) != 1 {
		t.Fatalf("reopened route served sign-in: %d", st)
	}
}

func TestCRED5LockedSignInOpensNoRoute(t *testing.T) {
	r := newWorkerRig(t)
	r.locked = true
	w := r.call("signin", "pw-s")
	if w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != errRouteLocked.Error() {
		t.Fatalf("locked signin: %d %q", w.Code, w.Body)
	}
	if w := r.call("signin", "wk-1"); w.Code != http.StatusBadRequest {
		t.Fatalf("signin for a non-provider machine: %d", w.Code)
	}
}

// /plan answers the plan's state for the runner (#1264 R3): granted is a
// stored login, private_ok the owner's per-plan mark. It carries no login
// value, refuses an unknown provider, and is one 503 line while locked.
func TestCRED5PlanVerbAnswersGrantedAndPrivate(t *testing.T) {
	r := newWorkerRig(t)
	state := planState{Granted: true}
	var asked []string
	r.p.plan = func(provider string) (planState, error) {
		asked = append(asked, provider)
		if r.locked {
			return planState{}, egress.ErrVaultLocked
		}
		return state, nil
	}
	plan := func(q string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ctl.ServeHTTP(w, httptest.NewRequest("POST", "/plan?"+q, nil))
		return w
	}
	w := plan("provider=codex")
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); w.Code != http.StatusOK || err != nil {
		t.Fatalf("plan: %d %q", w.Code, w.Body)
	}
	if len(got) != 2 || got["granted"] != true || got["private_ok"] != false {
		t.Fatalf("plan reply %v", got)
	}
	if w := plan("provider=openai"); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider: %d", w.Code)
	}
	if w := plan("machine=pw-a"); w.Code != http.StatusBadRequest {
		t.Fatalf("no provider: %d", w.Code)
	}
	r.locked = true
	if w := plan("provider=codex"); w.Code != http.StatusServiceUnavailable || strings.TrimSpace(w.Body.String()) != errRouteLocked.Error() {
		t.Fatalf("locked plan: %d %q", w.Code, w.Body)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v: only codex is a plan", asked)
	}
	gw := httptest.NewRecorder()
	r.ctl.ServeHTTP(gw, httptest.NewRequest("GET", "/plan?provider=codex", nil))
	if gw.Code < 400 {
		t.Fatalf("GET /plan: %d", gw.Code)
	}
}

// The vault process's plan state: granted once the plan login is stored,
// private_ok only with the owner's codex mark, nothing while locked.
func TestCRED5PlanStateReadsTheVault(t *testing.T) {
	r := newFastRig(t, true)
	logins := egress.NewPlanLogins(r.c.loginStore, map[string]string{})
	if _, err := r.c.planState(logins, "codex"); err != egress.ErrVaultLocked {
		t.Fatalf("locked: %v", err)
	}
	if err := r.c.confirm(r.unlock(t), r.code()); err != nil {
		t.Fatal(err)
	}
	if s, err := r.c.planState(logins, "codex"); err != nil || s.Granted || s.PrivateOK {
		t.Fatalf("before sign-in: %+v %v", s, err)
	}
	r.c.mu.Lock()
	err := r.c.v.Put("plan-login-codex", egress.LoginKind, []byte(`{"account_id":"acct-synthetic"}`))
	r.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s, err := r.c.planState(logins, "codex"); err != nil || !s.Granted || s.PrivateOK {
		t.Fatalf("signed in: %+v %v", s, err)
	}
	r.c.mu.Lock()
	err = r.c.v.Put(PrivateOKPrefix+"codex", KindPrivateOK, []byte("synthetic-mark"))
	r.c.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if s, err := r.c.planState(logins, "codex"); err != nil || !s.Granted || !s.PrivateOK {
		t.Fatalf("marked: %+v %v", s, err)
	}
}

// /signedin answers whether that worker's own sign-in stored the login
// (security review 2): the runner's only success signal for a sign-in. It
// answers per worker, with no login value, and false when nothing is wired.
func TestCRED5SignedInVerbAnswersForThatWorkerOnly(t *testing.T) {
	r := newWorkerRig(t)
	stored := func(machine string) (bool, int) {
		t.Helper()
		w := r.call("signedin", machine)
		if w.Code != http.StatusOK {
			return false, w.Code
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 1 {
			t.Fatalf("signedin %s: reply %q", machine, w.Body)
		}
		return got["stored"] == true, w.Code
	}
	if ok, code := stored("pw-s"); ok || code != http.StatusOK {
		t.Fatalf("unwired: %v %d", ok, code)
	}
	var asked []string
	r.p.signedIn = func(worker string) bool { asked = append(asked, worker); return worker == "pw-s" }
	if ok, _ := stored("pw-s"); !ok {
		t.Fatal("the sign-in worker's commit is not reported")
	}
	if ok, _ := stored("pw-r"); ok {
		t.Fatal("another worker reads as signed in")
	}
	if _, code := stored("wk-1"); code != http.StatusBadRequest {
		t.Fatalf("a non-provider machine: %d", code)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %v", asked)
	}
	gw := httptest.NewRecorder()
	r.ctl.ServeHTTP(gw, httptest.NewRequest("GET", "/signedin?machine=pw-s", nil))
	if gw.Code < 400 {
		t.Fatalf("GET /signedin: %d", gw.Code)
	}
}
