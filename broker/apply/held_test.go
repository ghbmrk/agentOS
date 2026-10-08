package apply

import (
	"context"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/reversible"
)

// REQ: UPD-6, REV-3, CH-16

// TestHeldEffectHoldsTheApplyAndTheRestart (UX-76-2, P2-rev3 carry): a
// restart cancels every effect still in its undo window (reversible RV6),
// so a planned update neither hands over nor restarts while one is held,
// and STATUS says why; once the last one is released it goes ahead.
func TestHeldEffectHoldsTheApplyAndTheRestart(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.held = r.clk.now().Add(10 * time.Minute)
	if ok, _ := r.a.Tick(ctx); ok || len(r.act.installed) != 0 || len(r.intents()) != 0 {
		t.Fatal("handed over while an approved action was in its undo window")
	}
	if got, want := r.a.Status(), "Update 1 will install once the actions you can still undo have run."; got != want {
		t.Fatalf("status %q, want %q", got, want)
	}
	r.clk.add(10 * time.Minute)
	if ok, err := r.a.Tick(ctx); !ok || err != nil || r.act.restarts != 1 {
		t.Fatalf("not applied once the hold ended: %v", err)
	}

	// After the slot write, a new hold keeps the box from restarting.
	r2 := newRig(t)
	rel := r2.release(1, false)
	r2.act0 = slowActivator{r2.act, func() { r2.held = r2.clk.now().Add(30 * time.Minute) }}
	r2.restart()
	r2.must(r2.a.Schedule(rel, "a1"))
	r2.clk.add(r2.a.cfg.Jitter)
	if ok, _ := r2.a.Tick(ctx); ok || len(r2.act.installed) != 1 || r2.act.restarts != 0 {
		t.Fatal("restarted while an approved action was in its undo window")
	}
	r2.clk.add(30 * time.Minute)
	if ok, err := r2.a.Tick(ctx); !ok || err != nil || r2.act.restarts != 1 {
		t.Fatalf("not restarted once the hold ended: %v", err)
	}
}

// TestHeldEffectsHoldAnUpdateForAtMostTheLongestWindow (UX-76-2): owner
// approvals that keep arriving cannot hold an update for ever: from when
// it became due, held effects hold it for at most the longest undo window
// a form may declare; a call, accepted work or STOP still hold it after.
func TestHeldEffectsHoldAnUpdateForAtMostTheLongestWindow(t *testing.T) {
	if DefaultHeldBound != reversible.MaxWindow {
		t.Fatalf("default bound %s, not the longest window %s", DefaultHeldBound, reversible.MaxWindow)
	}
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	for i := 0; i < 23; i++ {
		r.held = r.clk.now().Add(2 * time.Hour)
		r.clk.add(time.Hour)
		if ok, _ := r.a.Tick(ctx); ok {
			t.Fatalf("applied %d hours in, during holds", i+1)
		}
	}
	r.held = r.clk.now().Add(2 * time.Hour)
	r.clk.add(time.Hour) // 24 hours since it became due
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("held past the longest undo window: %v", err)
	}

	r2 := newRig(t)
	r2.must(r2.a.Schedule(r2.release(1, true), "a1"))
	r2.clk.add(25 * time.Hour)
	r2.held = r2.clk.now().Add(time.Hour)
	r2.working = true
	if ok, _ := r2.a.Tick(ctx); ok {
		t.Fatal("applied during accepted work after the held bound")
	}
	if got := r2.a.Status(); got != "Update 1 will install once the agent's current task is done." {
		t.Fatalf("status %q", got)
	}

	// Nil Held: nothing is held (the box has no reversible forms yet).
	r3 := newRig(t)
	rel := r3.release(1, true)
	a, err := New(Config{Journal: r3.eng, Activator: r3.act, Store: r3.store, Pipeline: r3.pipe, State: r3.state,
		InCall: func() bool { return false }, Working: func() bool { return false }, Now: r3.clk.now})
	if err != nil {
		t.Fatal(err)
	}
	r3.a, r3.pol.a = a, a
	r3.must(a.Schedule(rel, "a1"))
	if ok, err := a.Tick(ctx); !ok || err != nil {
		t.Fatalf("nil Held held the update: %v", err)
	}
}
