package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync/atomic"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	ownerch "github.com/ghbmrk/agentos/broker/owner"
)

// Loop 2's passive checks in the daemon (W5a, loops S9). The guard runs as
// a scheduler source. Its Box is empty until each input exists in a
// verified form: the signed release's digests and the measured artifacts
// (the updater, W5b), installed packages against a signed advisory feed
// (security C3 on #54), and vault expiry metadata over the vault socket.
// Until then the digest names those checks as not run (loops S2). The
// drift check is not wired to the live tree copy either: both are this
// process's own copies of the pipeline's tree, so comparing them sees no
// outside change and could race an adoption into a false finding.
// FixturesLive stays off for the passive checks' fixtures until replay
// answers them (K-S1); the pipeline's PS1 grading is in place (change
// C24). Seeded findings' tree rules are answered by replay itself, so
// their fixtures are live (loop2Live, P3-4b). Guard.Report is called in
// process only; no socket reaches it.

// loop2Live are the checks whose regression fixtures go live now.
var loop2Live = map[loops.Check]bool{loops.CheckSeeded: true}

// loop2NotRun is why each check does not run on this box yet, for STATUS
// and the digest (potency C2 on W5a).
var loop2NotRun = map[loops.Check]string{
	loops.CheckHash:     "needs the updater",
	loops.CheckAdvisory: "needs a signed advisory feed",
	loops.CheckDrift:    "needs a check of what the machines hold",
	loops.CheckExpiry:   "needs the vault's expiry list",
}

// errNotPaused: the gate refused Loop 2's pause.
var errNotPaused = errors.New("loop2: the gate did not pause the grant")

// pauseGate is the gate as Loop 2's containment uses it.
type pauseGate interface {
	Submit(journal.Intent) (journal.Status, error)
	Authorize(context.Context, string) (journal.Status, error)
	Dispatch(context.Context, string) (journal.Status, error)
}

type pauseGateBox struct{ g pauseGate }

// loop2Contain pauses a grant on a finding from the broker's own Loop 2
// origin (loops K-S2): pausing only narrows, and works during STOP.
type loop2Contain struct{ gate atomic.Pointer[pauseGateBox] }

func (c *loop2Contain) Contain(ctx context.Context, t loops.Target, finding string) error {
	if t.Kind != "grant" {
		return fmt.Errorf("loop2: no pause for a %s yet", t.Kind)
	}
	b := c.gate.Load()
	if b == nil {
		return errors.New("loop2: gate not attached")
	}
	id := "loop2/pause/" + randHex(8)
	st, err := b.g.Submit(journal.Intent{ID: id, Origin: grants.OriginLoop2, Account: journal.BrokerAccount,
		Action: journal.ActionGrantPause, GrantRef: t.Name, Executor: grants.ExecutorName,
		// The check and finding behind the pause, for its record
		// (security L2 on W5a). The journal's redactor stores the
		// param as "[redacted]"; the full record, with this same
		// "<check>:<finding>", is the guard's evidence in loop2.json.
		Params: map[string]any{"finding": finding}})
	if err == nil && st.State == journal.Pending {
		st, err = b.g.Authorize(ctx, id)
	}
	if err == nil && st.State == journal.Authorized {
		st, err = b.g.Dispatch(ctx, id)
	}
	switch {
	case err != nil:
		return err
	case st.State != journal.Succeeded:
		return fmt.Errorf("%w (%s)", errNotPaused, st.State)
	}
	return nil
}

// loop2Notify texts the owner Loop 2's fixed-wording notices once the
// owner channel is attached. Urgency waits for CH-15's quiet-hours
// classes in the owner channel: until then every notice goes at once.
type loop2Notify struct {
	ch atomic.Pointer[ownerch.Channel]
}

func (n *loop2Notify) send(text string, _ bool) {
	if err := n.try(text); err != nil {
		log.Printf("loop2: owner notice not sent: %v", err)
	}
}

// try sends text to the owner, reporting whether it went.
func (n *loop2Notify) try(text string) error {
	ch := n.ch.Load()
	if ch == nil {
		return errors.New("owner channel not attached")
	}
	return ch.Inform(text)
}

// loop2Held reports the targets the gate still holds paused: a grant that
// exists and is paused. A resumed or revoked grant is not held.
func loop2Held(gs []grants.Grant) func(loops.Target) bool {
	held := map[string]bool{}
	for _, gr := range gs {
		held[gr.ID] = gr.Paused
	}
	return func(t loops.Target) bool { return t.Kind == "grant" && held[t.Name] }
}
