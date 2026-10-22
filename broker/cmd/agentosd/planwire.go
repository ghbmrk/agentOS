package main

import (
	"errors"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/modelroute"
)

// planSignInLine is ONB-9's sign-in line for the Codex plan: STATUS says it
// once the runner finds no login or a refused one, until the owner signs in
// again (CRED-5, #1264). planOnlyLine is the line for an owner whose rule
// has no other route, whose plan work then waits rather than moves.
const (
	planSignInLine = "ChatGPT plan: I can't sign in to it, so its work uses your other routes. Sign in again on my Wi-Fi page."
	planOnlyLine   = "ChatGPT plan: I can't sign in to it, so its work waits until you sign in again. Sign in again on my Wi-Fi page."
)

// planNote holds the sign-in line. The runner sets it (SignIn) and clears it
// when a sign-in or resume lands (OnSignedIn), both under its own lock, so
// set and clear are plain stores. others reports whether the owner's rule
// holds a route besides the plan; nil or false reads as plan-only, so the
// line never promises a route that may not be there (#1264 item 3).
type planNote struct {
	on     atomic.Bool
	others func() bool
}

func (n *planNote) set(string)   { n.on.Store(true) }
func (n *planNote) clear(string) { n.on.Store(false) }

// Note is STATUS's plan sign-in line, or "".
func (n *planNote) Note() string {
	switch {
	case !n.on.Load():
		return ""
	case n.others != nil && n.others():
		return planSignInLine
	}
	return planOnlyLine
}

// planState asks the vault process for provider's plan state. It is the one
// place agentosd reads it, so every caller sees the same closed defaults.
type planState interface {
	Plan(provider string) (modelroute.PlanState, error)
}

// planGranted is the runner's Granted: the owner signed in to provider's
// plan. A locked vault cannot say, and reads as granted so the run asks for
// its seed and falls back on the locked vault (CAP-9) rather than refusing
// as ungranted; any other error is not granted.
func planGranted(p planState, provider string) bool {
	if p == nil {
		return false
	}
	s, err := p.Plan(provider)
	if err != nil {
		return errors.Is(err, modelroute.ErrVaultLocked)
	}
	return s.Granted
}

// signInState asks the vault process whether a sign-in worker's own
// sign-in stored the plan login.
type signInState interface {
	SignInStored(id string) (bool, error)
}

// planSignInStored is the runner's SignInStored: strictly whether sign-in
// worker id stored the login (not whether some login is stored), false
// whenever the vault process cannot say.
func planSignInStored(p signInState, id string) bool {
	if p == nil {
		return false
	}
	ok, err := p.SignInStored(id)
	return err == nil && ok
}

// planPrivateOK is the owner's per-plan private mark (CAP-9), false whenever
// the vault process cannot say.
func planPrivateOK(p planState, provider string) bool {
	if p == nil {
		return false
	}
	s, err := p.Plan(provider)
	return err == nil && s.PrivateOK
}
