package journal

import (
	"context"
	"sync"
	"testing"
	"time"
)

// REQ: OP-4

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
