package main

// REQ: CRED-5, CAP-9, ONB-9

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/provagent"
	"github.com/ghbmrk/agentos/broker/vm"
)

// planServer answers /plan with planStatus and planBody, and /seed with
// seedStatus and seedBody, in place of agentos-egress.
func planServer(t *testing.T, planStatus int, planBody string, seedStatus int, seedBody string) *modelroute.RouteControl {
	t.Helper()
	dir, err := os.MkdirTemp("", "pp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	reply := func(w http.ResponseWriter, status int, body string) {
		if status == http.StatusOK {
			w.Write([]byte(body))
			return
		}
		http.Error(w, body, status)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/plan":
			reply(w, planStatus, planBody)
		case "/seed":
			reply(w, seedStatus, seedBody)
		}
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return modelroute.NewRouteControl(sock)
}

const lockedBody = "the vault is locked; no provider route can open"

// The runner's grant and private mark are the vault process's plan state.
// A locked vault reads as granted, so the run falls back on it (CAP-9);
// the private mark and the sign-in check stay closed whenever the vault
// cannot say (CRED-5).
func TestPlanStateWiresGrantAndPrivateMark(t *testing.T) {
	for _, c := range []struct {
		name                      string
		status                    int
		body                      string
		granted, privateOK, login bool
	}{
		{"granted and private", http.StatusOK, `{"granted":true,"private_ok":true}`, true, true, true},
		{"granted only", http.StatusOK, `{"granted":true}`, true, false, true},
		{"not signed in", http.StatusOK, `{}`, false, false, false},
		{"vault locked", http.StatusServiceUnavailable, lockedBody, true, false, false},
		{"route busy", http.StatusServiceUnavailable, "egress busy: too many provider calls", true, false, false},
		{"unreadable", http.StatusOK, `not json`, false, false, false},
		{"refused", http.StatusInternalServerError, "boom", false, false, false},
	} {
		r := providerRunner(nil, planServer(t, c.status, c.body, http.StatusOK, "{}"), &planNote{})
		if got := r.Granted("codex"); got != c.granted {
			t.Errorf("%s: Granted = %v", c.name, got)
		}
		if got := r.PrivateOK("codex"); got != c.privateOK {
			t.Errorf("%s: PrivateOK = %v", c.name, got)
		}
		if got := r.HasLogin("codex"); got != c.login {
			t.Errorf("%s: HasLogin = %v", c.name, got)
		}
		if r.SignInFor == nil {
			t.Errorf("%s: SignInFor is unwired", c.name)
		}
	}
	if r := providerRunner(nil, nil, nil); r.Granted("codex") || r.PrivateOK("codex") || r.HasLogin != nil || r.SignInFor != nil || r.SignIn != nil {
		t.Fatal("a runner without route control opened an owner-side input")
	}
}

// ONB-9: a run that finds no login sets the plan's sign-in line, once, and
// the owner's sign-in clears it.
func TestPlanSignInLineFollowsTheRunner(t *testing.T) {
	note := &planNote{}
	r := providerRunner(nil, planServer(t, http.StatusOK, `{"granted":true}`, http.StatusInternalServerError, "no plan login stored"), note)
	d := r.Decls["codex"]
	d.Q = provagent.Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: provagent.Allowed}
	r.Decls["codex"] = d
	r.ImageVersion = func(string) string { return "1" }
	var read []provagent.Reading
	for _, p := range d.Pools {
		read = append(read, provagent.Reading{Pool: p.Name, Left: 1})
	}
	r.Readings = func(string) []provagent.Reading { return read }
	r.Reserve = func() float64 { return 0 }
	if note.Note() != "" {
		t.Fatal("the line is set before any run")
	}
	_, err := r.Run(context.Background(), provagent.Request{Provider: "codex", Brief: "b", TaskClass: "code",
		Label: vm.Public, Class: admission.Experiment, MemMB: 256})
	var ref *provagent.Refusal
	if !errors.As(err, &ref) || ref.Reason != provagent.Unsigned {
		t.Fatalf("= %v, want unsigned", err)
	}
	if note.Note() != planSignInLine {
		t.Fatalf("line %q", note.Note())
	}
	r.SignedIn("codex")
	if note.Note() != "" {
		t.Fatalf("the line outlived the sign-in: %q", note.Note())
	}
}
