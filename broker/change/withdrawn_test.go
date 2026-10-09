package change

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-1, OP-4, CH-16, SR3-4f-2-r1b, SR3-4f-2-r1f

// cutShort makes the owner's UNDO fail just after the applier withdrew
// the release: the pipeline's next save fails, so no revert is journaled.
func cutShort(t *testing.T) (*env, Report) {
	t.Helper()
	e, r, w := pendingStaged(t)
	w.then = func(string) { e.store.Fail = errors.New("disk full") }
	if err := e.p.Revert(bg, r.Short, OriginOwner); err == nil {
		t.Fatal("undo ran without saving")
	}
	e.store.Fail = nil
	if a := e.adoption(r.ID); a.Reverted != "" {
		t.Fatalf("adoption %+v", a)
	}
	return e, r
}

// An owner UNDO that fails after the withdrawal is settled by the
// applier's next Tick as the owner's undo, not as a drop Loop 3 offers
// again.
func TestOwnerUndoCutShortAfterTheWithdrawalIsNotADrop(t *testing.T) {
	e, r := cutShort(t)
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner || e.image() != update.Digest([]byte("a")) {
		t.Fatalf("adoption %+v", a)
	}
}

// The same after a restart: the undo's why was saved before the applier
// was asked, so Resume's drop still records the owner's undo.
func TestOwnerUndoCutShortByARestartIsNotADrop(t *testing.T) {
	e, r := cutShort(t)
	e.reopen()
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner {
		t.Fatalf("adoption %+v", a)
	}
}

// A withdrawal refused in the handover window withdrew nothing: a later
// drop of the release (a newer one, a narrowing) is a drop, offered again.
func TestRefusedWithdrawalLeavesADrop(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.err = installing{}
	if e.p.Revert(bg, r.Short, OriginOwner) == nil {
		t.Fatal("undo succeeded")
	}
	e.reopen()
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyDropped {
		t.Fatalf("adoption %+v", a)
	}
}

// Any other Withdraw error may come after the applier saved the
// withdrawal (a store that fails after its rename): the why stays, so
// the drop Resume settles is the owner's undo, not a drop (r1f, C31).
func TestWithdrawalFailingAfterItsCommitIsNotADrop(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.err = errors.New("apply: sync state dir: input/output error")
	if e.p.Revert(bg, r.Short, OriginOwner) == nil {
		t.Fatal("undo succeeded")
	}
	e.reopen()
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner {
		t.Fatalf("adoption %+v", a)
	}
}

// A revert retried after a restart asks the applier again; its refusal
// leaves the why the first, successful withdrawal saved, so the drop
// that settles it is never offered again (Security re-sign point 1).
func TestRetriedRevertKeepsTheFirstWithdrawnWhy(t *testing.T) {
	for _, c := range []struct {
		name     string
		first    string // why of the revert cut short after Withdraw
		retry    string
		retryErr error
		want     string
	}{
		{"security, handover", WhySecurity, WhySecurity, installing{}, WhySecurity},
		{"security, failed", WhySecurity, WhySecurity, errors.New("disk full"), WhySecurity},
		{"owner, handover", WhyOwner, WhyOwner, installing{}, WhyOwner},
		{"owner, failed", WhyOwner, WhyOwner, errors.New("disk full"), WhyOwner},
		{"owner, then security refused", WhyOwner, WhySecurity, installing{}, WhyOwner},
	} {
		e, r, w := pendingStaged(t)
		w.then = func(string) { e.store.Fail = errors.New("disk full") }
		if e.p.revert(bg, r.ID, origin(c.first), c.first) == nil {
			t.Fatalf("%s: first revert ran without saving", c.name)
		}
		e.store.Fail = nil
		e.reopen()
		w2 := &withdrawer{err: c.retryErr}
		e.p.SetWithdrawer(w2)
		if e.p.revert(bg, r.ID, origin(c.retry), c.retry) == nil || len(w2.called()) != 1 {
			t.Fatalf("%s: retry not refused by the applier", c.name)
		}
		e.reopen()
		if err := e.p.StageDropped(bg, r.ID); err != nil {
			t.Fatal(c.name, err)
		}
		if a := e.adoption(r.ID); a.Reverted != c.want {
			t.Fatalf("%s: reverted %q, want %q", c.name, a.Reverted, c.want)
		}
	}
}

func origin(why string) string {
	if why == WhyOwner {
		return OriginOwner
	}
	return OriginPipeline
}

// If the restored why cannot be saved, the one saved before the applier
// was asked stays: a later drop is the owner's undo, erring toward the
// revert asked (C31).
func TestUnsavedRestoreKeepsTheWhy(t *testing.T) {
	e, r, w := pendingStaged(t)
	w.err = installing{}
	w.refused = func(string) { e.store.Fail = errors.New("disk full") }
	if e.p.Revert(bg, r.Short, OriginOwner) == nil {
		t.Fatal("undo succeeded")
	}
	e.store.Fail = nil
	if err := e.p.StageDropped(bg, r.ID); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner {
		t.Fatalf("adoption %+v", a)
	}
}

// The why is saved before the applier is asked; if it cannot be saved,
// nothing is withdrawn.
func TestWithdrawnWhyUnsavedAsksNoWithdrawal(t *testing.T) {
	e, r, w := pendingStaged(t)
	e.store.Fail = errors.New("disk full")
	if e.p.Revert(bg, r.Short, OriginOwner) == nil {
		t.Fatal("undo ran without saving")
	}
	e.store.Fail = nil
	if a := e.adoption(r.ID); len(w.called()) != 0 || a.WithdrawnFor != "" || a.Reverted != "" {
		t.Fatalf("adoption %+v, withdraw calls %q", a, w.called())
	}
}

// Only the drop takes the saved why: a revert that runs keeps its own.
// A Recheck revert STOP held withdrew the release; the owner's UNDO
// after Resume is recorded as the owner's.
func TestARevertThatRunsKeepsItsOwnWhy(t *testing.T) {
	e, r, _ := pendingStaged(t)
	if _, err := e.eng.Stop(bg); err != nil {
		t.Fatal(err)
	}
	if e.p.revert(bg, r.ID, OriginPipeline, WhySecurity) == nil {
		t.Fatal("auto revert ran during STOP")
	}
	if err := e.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	if err := e.p.Revert(bg, r.Short, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if a := e.adoption(r.ID); a.Reverted != WhyOwner {
		t.Fatalf("adoption %+v", a)
	}
}
