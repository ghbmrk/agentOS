package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
)

// REQ: CAP-9, CH-3

// A private run's route rechecks the owner's private-data answer before
// each content request, so a withdrawal reaches a run already admitted
// (#2359). The broker binds the run's label with /seed?private=1.

// privateRig is a worker rig whose plan answer the test flips.
func privateRig(t *testing.T) (*workerRig, *atomic.Bool) {
	t.Helper()
	r := newWorkerRig(t)
	var ok atomic.Bool
	ok.Store(true)
	r.p.plan = func(provider string) (planState, error) {
		if provider != planProvider {
			t.Errorf("plan asked for %q", provider)
		}
		return planState{Granted: true, PrivateOK: ok.Load()}, nil
	}
	return r, &ok
}

func (r *workerRig) seedPrivate(t *testing.T, machine string) {
	t.Helper()
	w := httptest.NewRecorder()
	r.ctl.ServeHTTP(w, httptest.NewRequest("POST", "/seed?machine="+machine+"&private=1", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("private seed %s: %d %s", machine, w.Code, w.Body)
	}
}

// content sends one responses call over sock and returns its status and
// whether the route itself refused it.
func content(t *testing.T, sock, machine string) (int, bool) {
	t.Helper()
	resp, err := through(t, sock, "ph-access-"+machine, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get(egress.DeniedHeader) == "1"
}

// Withdrawn after admission, before the run's first content request: that
// request is refused and reaches no provider.
func TestCAP9WithdrawBeforeFirstRequestRefusesIt(t *testing.T) {
	r, ok := privateRig(t)
	r.seedPrivate(t, "pw-a")
	sock := filepath.Join(r.open(t, "pw-a"), RouteSocket)
	ok.Store(false)
	if st, denied := content(t, sock, "pw-a"); st != http.StatusForbidden || !denied {
		t.Fatalf("content after withdrawal: %d denied=%v, want 403 from the route", st, denied)
	}
	if len(r.up.seen) != 0 {
		t.Fatalf("a withdrawn private run reached the provider: %v", r.up.seen)
	}
}

// Withdrawn between two requests: the first goes, the second is refused.
func TestCAP9WithdrawBetweenRequestsRefusesTheNext(t *testing.T) {
	r, ok := privateRig(t)
	r.seedPrivate(t, "pw-a")
	sock := filepath.Join(r.open(t, "pw-a"), RouteSocket)
	if st, _ := content(t, sock, "pw-a"); st != http.StatusOK {
		t.Fatalf("first content request: %d", st)
	}
	ok.Store(false)
	if st, denied := content(t, sock, "pw-a"); st != http.StatusForbidden || !denied {
		t.Fatalf("second content request: %d denied=%v, want 403", st, denied)
	}
	if len(r.up.seen) != 1 {
		t.Fatalf("upstream saw %d calls, want only the first", len(r.up.seen))
	}
	// Allowing again lets the run go on: the route asks per request.
	ok.Store(true)
	if st, _ := content(t, sock, "pw-a"); st != http.StatusOK {
		t.Fatalf("after allowing again: %d", st)
	}
}

// A public run (seeded without the label, or never seeded) is not bound:
// no private answer stops it.
func TestCAP9PublicRunIgnoresTheWithdrawal(t *testing.T) {
	r, ok := privateRig(t)
	ok.Store(false)
	if w := r.call("seed", "pw-a"); w.Code != http.StatusOK {
		t.Fatalf("seed: %d %s", w.Code, w.Body)
	}
	for _, m := range []string{"pw-a", "pw-b"} {
		sock := filepath.Join(r.open(t, m), RouteSocket)
		if st, _ := content(t, sock, m); st != http.StatusOK {
			t.Fatalf("public run %s: %d", m, st)
		}
	}
	if len(r.up.seen) != 2 {
		t.Fatalf("upstream saw %d calls, want 2", len(r.up.seen))
	}
}

// Sign-in traffic is not content: a route opened for sign-in reaches the
// provider whatever the private answer.
func TestCAP9SignInIgnoresTheWithdrawal(t *testing.T) {
	r, ok := privateRig(t)
	r.seedPrivate(t, "pw-s")
	ok.Store(false)
	sock := filepath.Join(r.openVerb(t, "signin", "pw-s"), RouteSocket)
	if st := signInCall(t, sock, "/api/accounts/deviceauth/usercode", `{"client_id":"app_synthetic"}`); st != http.StatusOK {
		t.Fatalf("sign-in after withdrawal: %d", st)
	}
	if len(r.up.seen) != 1 {
		t.Fatalf("upstream saw %v", r.up.seen)
	}
}

// An answer the route cannot read refuses private content: a locked
// vault, an unreadable plan, or no plan answer at all.
func TestCAP9UnreadableAnswerRefusesPrivateContent(t *testing.T) {
	for name, plan := range map[string]func(string) (planState, error){
		"locked":     func(string) (planState, error) { return planState{}, egress.ErrVaultLocked },
		"unreadable": func(string) (planState, error) { return planState{}, errors.New("synthetic read failure") },
		"none":       nil,
	} {
		t.Run(name, func(t *testing.T) {
			r, _ := privateRig(t)
			r.seedPrivate(t, "pw-a")
			sock := filepath.Join(r.open(t, "pw-a"), RouteSocket)
			r.p.mu.Lock()
			r.p.plan = plan
			r.p.mu.Unlock()
			if st, denied := content(t, sock, "pw-a"); st != http.StatusForbidden || !denied {
				t.Fatalf("content: %d denied=%v, want 403", st, denied)
			}
			if len(r.up.seen) != 0 {
				t.Fatal("refused content reached the provider")
			}
		})
	}
}

// The binding is the worker's, as its placeholders are: a reopen (restart)
// keeps it, a later unlabelled seed does not clear it, and /close drops it.
func TestCAP9BindingOutlivesAReopenNotAClose(t *testing.T) {
	r, ok := privateRig(t)
	r.seedPrivate(t, "pw-a")
	r.open(t, "pw-a")
	if w := r.call("seed", "pw-a"); w.Code != http.StatusOK {
		t.Fatalf("reseed: %d", w.Code)
	}
	sock := filepath.Join(r.open(t, "pw-a"), RouteSocket)
	ok.Store(false)
	if st, _ := content(t, sock, "pw-a"); st != http.StatusForbidden {
		t.Fatalf("reopened private run: %d, want 403", st)
	}
	if w := r.call("close", "pw-a"); w.Code != http.StatusOK {
		t.Fatalf("close: %d", w.Code)
	}
	r.p.mu.Lock()
	bound := r.p.private["pw-a"]
	r.p.mu.Unlock()
	if bound {
		t.Fatal("/close kept the private binding")
	}
	r.seedPrivate(t, "pw-b")
	r.open(t, "pw-b")
	r.p.closeAll()
	r.p.mu.Lock()
	n := len(r.p.private)
	r.p.mu.Unlock()
	if n != 0 {
		t.Fatalf("shutdown kept %d private bindings", n)
	}
}
