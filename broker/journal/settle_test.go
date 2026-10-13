package journal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// REQ: OP-4, OP-2

// flakyEvidence answers unknown while its service is down, then defers to
// the fake service, counting how often it was asked.
type flakyEvidence struct {
	plainExec
	mu    sync.Mutex
	down  int
	asked int
}

func (f *flakyEvidence) Reconcile(ctx context.Context, in Intent, a int) Outcome {
	f.mu.Lock()
	f.asked++
	down := f.down > 0
	f.down--
	f.mu.Unlock()
	if down {
		return Outcome{Result: ResultUnknown, Evidence: "service unavailable"}
	}
	return f.plainExec.Reconcile(ctx, in, a)
}

func crashedAfterEffect(t *testing.T, svc *fakeService) *MemStore {
	t.Helper()
	cs := &crashStore{MemStore: &MemStore{}, budget: 3}
	e := mustOpen(t, cs, newPolicy(), svc)
	must(e.Submit(intent("a", "acct")))
	must(e.Authorize(ctx, "a"))
	_, _ = e.Dispatch(ctx, "a")
	return cs.MemStore
}

// SettleUnknown asks again while evidence is unavailable, lifts the fence
// once it arrives, and never re-executes the effect.
func TestOP4SettleUnknownRetriesUnavailableEvidence(t *testing.T) {
	svc := newService()
	st := crashedAfterEffect(t, svc)
	f := &flakyEvidence{plainExec: plainExec{svc}, down: 3}
	e := mustOpen(t, st, newPolicy(), f)
	rep := e.SettleUnknown(ctx, time.Millisecond, 2*time.Millisecond)
	if len(rep.Unresolved) != 0 || len(rep.Resolved) != 1 || f.asked != 4 {
		t.Fatalf("report %+v after %d asks", rep, f.asked)
	}
	if got := e.Fenced("acct"); len(got) != 0 {
		t.Fatalf("still fenced: %v", got)
	}
	if s := must(e.Get("a")); s.State != Succeeded {
		t.Fatalf("a is %s", s.State)
	}
	if svc.effectCount("a") != 1 || svc.executeCount() != 1 {
		t.Fatalf("effects %d, executes %d: the effect ran again", svc.effectCount("a"), svc.executeCount())
	}
}

// Evidence that never settles keeps the account fenced until ctx ends.
func TestOP4SettleUnknownKeepsUncertainEffectsFenced(t *testing.T) {
	svc := newService()
	st := crashedAfterEffect(t, svc)
	f := &flakyEvidence{plainExec: plainExec{svc}, down: 1 << 30}
	e := mustOpen(t, st, newPolicy(), f)
	c, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	rep := e.SettleUnknown(c, time.Millisecond, 5*time.Millisecond)
	if len(rep.Unresolved) != 1 || f.asked < 2 {
		t.Fatalf("report %+v after %d asks", rep, f.asked)
	}
	if got := e.Fenced("acct"); len(got) != 1 {
		t.Fatalf("fence = %v", got)
	}
	if svc.executeCount() != 1 {
		t.Fatalf("executes %d: the effect ran again", svc.executeCount())
	}
}

// Unknown is not evidence: an owner resolve with it is refused while the
// attempt is still outcome_unknown, and the restart fence stays (#1371,
// mutant M10).
func TestOP2ResolveWithUnknownKeepsTheFence(t *testing.T) {
	svc := newService()
	st := crashedAfterEffect(t, svc)
	e := mustOpen(t, st, newPolicy(), &flakyEvidence{plainExec: plainExec{svc}, down: 1 << 30})
	if got := e.Fenced("acct"); len(got) != 1 {
		t.Fatalf("fence = %v", got)
	}
	before, err := e.RecordsAfter(0)
	if err != nil {
		t.Fatal(err)
	}
	// Refused up front, with the intent's status: nothing reaches the
	// journal (the record check behind it is a second line, not the guard).
	s, err := e.Resolve("a", 1, Outcome{Result: ResultUnknown, Evidence: "owner is not sure"}, "owner")
	if !errors.Is(err, ErrState) || s.State != OutcomeUnknown {
		t.Fatalf("resolve with unknown: %+v, %v", s, err)
	}
	if after, err := e.RecordsAfter(0); err != nil || len(after) != len(before) {
		t.Fatalf("records %d then %d, %v", len(before), len(after), err)
	}
	if s := must(e.Get("a")); s.State != OutcomeUnknown {
		t.Fatalf("a is %s", s.State)
	}
	if got := e.Fenced("acct"); len(got) != 1 {
		t.Fatalf("fence after resolve with unknown = %v", got)
	}
	must(e.Submit(intent("b", "acct")))
	must(e.Authorize(ctx, "b"))
	if _, err := e.Dispatch(ctx, "b"); !errors.Is(err, ErrUnreconciled) {
		t.Fatalf("dispatch behind the fence: %v", err)
	}
	if svc.executeCount() != 1 {
		t.Fatalf("executes %d", svc.executeCount())
	}
}

// Unconfirmed names a fenced intent only once settle rounds have missed
// it, and is empty again once evidence settles it (#1373).
func TestOP4UnconfirmedAfterMissedRounds(t *testing.T) {
	svc := newService()
	st := crashedAfterEffect(t, svc)
	f := &flakyEvidence{plainExec: plainExec{svc}, down: 2}
	e := mustOpen(t, st, newPolicy(), f)
	if got := e.Unconfirmed(1); len(got) != 0 {
		t.Fatalf("before any round: %+v", got)
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	e.SettleUnknown(c, time.Millisecond, time.Millisecond) // one round; evidence is down
	got := e.Unconfirmed(1)
	if len(got) != 1 || got[0].ID != "a" || got[0].Params != nil {
		t.Fatalf("after a missed round: %+v", got)
	}
	if len(e.Unconfirmed(2)) != 0 {
		t.Fatal("shown before two missed rounds")
	}
	e.SettleUnknown(ctx, time.Millisecond, time.Millisecond)
	if got := e.Unconfirmed(1); len(got) != 0 {
		t.Fatalf("after settling: %+v", got)
	}
}
