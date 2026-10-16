package main

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localsrv"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// REQ: ONB-3, ONB-9, CRED-5

var _ localsrv.PlanSignIn = (*pageSignIn)(nil)

// #1264 item 1: after setup, the Wi-Fi page signs a signed-out plan in
// again through the daemon's own runner, the one that set ONB-9's line.
// It is offered only while the line is on and the gate is open; the
// vault process's record that this worker's sign-in stored the login
// (the swap) clears the line.
func TestThePageSignsThePlanInThroughTheDaemonsRunner(t *testing.T) {
	var stored atomic.Bool
	rc := planServerStored(t, http.StatusOK, `{"granted":true}`, http.StatusOK, "{}", func(string) (int, string) {
		if stored.Load() {
			return http.StatusOK, `{"stored":true}`
		}
		return http.StatusOK, `{"stored":false}`
	})
	note := &planNote{}
	p := &pageSignIn{note: note}
	if p.Ready() {
		t.Fatal("offered before the runner is built")
	}
	if _, _, _, err := p.Start(context.Background()); err == nil {
		t.Fatal("started before the runner is built")
	}
	h := &signInMachine{machineHost{live: map[string]bool{}}}
	r := providerRunner(nil, rc, note, nil)
	r.Host = h
	r.Background = t.Context()
	r.SignInTimes = provagent.SignInTimes{Poll: 5 * time.Millisecond, Link: time.Second, Wall: time.Hour}
	p.r.Store(r)
	note.set("codex")
	if p.Ready() {
		t.Fatal("offered with the gate closed")
	}
	if _, _, _, err := p.Start(context.Background()); err == nil || len(h.live) != 0 {
		t.Fatalf("started with the gate closed: %v", err)
	}
	d := r.Decls["codex"]
	d.Q = provagent.Qualification{CLIVersion: "1", Evidence: "e", TermsURL: "https://t.test", TermsRead: "2026-10-01", Verdict: provagent.Allowed}
	r.Decls["codex"] = d
	r.ImageVersion = func(string) string { return "1" }
	note.clear("codex")
	if p.Ready() {
		t.Fatal("offered while the plan is signed in")
	}
	note.set("codex")
	if !p.Ready() {
		t.Fatal("not offered with the line on and the gate open")
	}
	link, code, from, err := p.Start(context.Background())
	if err != nil || link != d.SignInPage || code != "ABCD-EF23" || from != d.SignInFrom {
		t.Fatalf("start: %q %q %q %v", link, code, from, err)
	}
	if _, _, _, err := p.Start(context.Background()); err != localsrv.SignInBusy {
		t.Fatalf("second start: %v", err)
	}
	if note.Note() == "" {
		t.Fatal("the line cleared before the login was stored")
	}
	stored.Store(true)
	waitFor(t, "the line to clear", func() bool { return note.Note() == "" })
	if p.Ready() {
		t.Fatal("still offered once signed in")
	}
}

// #1264 item 3: the line promises other routes only when the owner's rule
// has one; plan-only, or when that is unknown, the work waits.
func TestThePlanLineSaysWhereTheWorkGoes(t *testing.T) {
	var others atomic.Bool
	note := &planNote{}
	note.set("codex")
	const only = "ChatGPT plan: I can't sign in to it, so its work waits until you sign in again. Sign in again on my Wi-Fi page."
	const routes = "ChatGPT plan: I can't sign in to it, so its work uses your other routes. Sign in again on my Wi-Fi page."
	if note.Note() != only {
		t.Fatalf("unknown: %q", note.Note())
	}
	note.others = others.Load
	if note.Note() != only {
		t.Fatalf("plan-only: %q", note.Note())
	}
	others.Store(true)
	if note.Note() != routes {
		t.Fatalf("other routes: %q", note.Note())
	}
	note.clear("codex")
	if note.Note() != "" {
		t.Fatalf("signed in: %q", note.Note())
	}
}
