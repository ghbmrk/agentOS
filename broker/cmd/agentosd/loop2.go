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
// FixturesLive stays off until replay answers fixtures (K-S1); the
// pipeline's PS1 grading is in place (change C24).

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
		// (security L2 on W5a).
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
	ch := n.ch.Load()
	if ch == nil {
		log.Printf("loop2: owner notice not sent: owner channel not attached")
		return
	}
	if err := ch.Inform(text); err != nil {
		log.Printf("loop2: owner notice not sent: %v", err)
	}
}
