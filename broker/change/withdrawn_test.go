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

// A withdrawal the applier refused withdrew nothing: a later drop of the
// release (a newer one, a narrowing) is a drop, offered again.
func TestRefusedWithdrawalLeavesADrop(t *testing.T) {
	for name, err := range map[string]error{"handover": installing{}, "save": errors.New("disk full")} {
		e, r, w := pendingStaged(t)
		w.err = err
		if e.p.Revert(bg, r.Short, OriginOwner) == nil {
			t.Fatalf("%s: undo succeeded", name)
		}
		e.reopen()
		if err := e.p.StageDropped(bg, r.ID); err != nil {
			t.Fatal(name, err)
		}
		if a := e.adoption(r.ID); a.Reverted != WhyDropped {
			t.Fatalf("%s: adoption %+v", name, a)
		}
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
