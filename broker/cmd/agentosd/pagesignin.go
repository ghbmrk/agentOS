package main

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/provagent"
)

// pageSignIn is the Wi-Fi page's sign-in of the Codex plan after setup
// (ONB-3, ONB-9, #1264 item 1): the daemon's own runner, the one whose
// refusal set ONB-9's line and stopped the plan's work, so the sign-in
// that lands clears both (OnSignedIn). It implements localsrv.PlanSignIn.
// The runner is built after the page socket serves, so it is stored late;
// until then nothing is offered.
type pageSignIn struct {
	r    atomic.Pointer[provagent.Runner]
	note *planNote
}

// pagePlan is the plan the page signs in again: the one ONB-9's line names.
const pagePlan = "codex"

var errNotOffered = errors.New("plan sign-in: not offered")

// Ready is whether the plan is signed out (the line is on) and its
// sign-in would start now (CanSignIn: the gate is open).
func (p *pageSignIn) Ready() bool {
	r := p.r.Load()
	return r != nil && p.note.on.Load() && r.CanSignIn(pagePlan)
}

// Start starts the plan's sign-in and returns its page, code and issuer.
// Nothing the CLI printed but those crosses.
func (p *pageSignIn) Start(ctx context.Context) (link, code, from string, err error) {
	r := p.r.Load()
	if r == nil || !p.Ready() {
		return "", "", "", errNotOffered
	}
	link, code, err = r.StartSignIn(ctx, pagePlan, admission.Accepted, setupSignInMB)
	if err != nil {
		return "", "", "", signInErr(err)
	}
	return link, code, r.Decls[pagePlan].SignInFrom, nil
}
