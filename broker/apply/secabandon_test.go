package apply

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// REQ: UPD-8, UPD-1, CH-12
//
// MIG-4-adapters-e-sec-abandon (#3852): a security or stale withdrawal
// says the release will not start only once its Abandon is recorded
// (Abandoned). Before that, a reboot boots the counted entry and Resume
// commits it (the #3701 boundary), so Withdraw's refusal has Starts()
// true and STATUS says it may start, as #3832 did for a pin.

const (
	staleStatus    = "Update 1 is being withdrawn; I will not start it. Nothing is needed from you."
	staleMayStatus = "Update 1 is being withdrawn; it may start before I can undo it. Nothing is needed from you."
)

// Mutant: abandonOwed for a pin withdrawal only, and Withdraw says it
// will not start; drop the Abandoned guard on the wontStart case, and
// STATUS says it will not start.
func TestSecurityWithdrawAbandonFailedMayStart(t *testing.T) {
	r := installedHeld(t, true)
	r.act.abandonErr = errIO
	if err := r.a.Withdraw("a1", WhySecurity); !errors.Is(err, errIO) || !starts(t, err) {
		t.Fatalf("withdraw: %v", err)
	}
	if got := r.a.Status(); got != mayStart {
		t.Fatalf("status %q", got)
	}
	r.act.abandonErr = nil
	r.working = false
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.withdrawn()
}

// Once the Abandon took and is recorded, a later step that fails leaves
// Withdraw and STATUS saying it will not start.
// Mutant: drop the Abandoned save in withdrawHandoverLocked, and STATUS
// says it may start.
func TestSecurityWithdrawAfterTheAbandonTookWontStart(t *testing.T) {
	r := installedHeld(t, true)
	r.act.onAbandon = func() { r.afterSave = func() { r.state.Fail = errIO } }
	if err := r.a.Withdraw("a1", WhySecurity); !errors.Is(err, errIO) || starts(t, err) {
		t.Fatalf("withdraw: %v", err)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Withdrawing || pt.Pinned || !pt.Abandoned {
		t.Fatalf("applying %+v", pt)
	}
	if got := r.a.Status(); got != wontStart {
		t.Fatalf("status %q", got)
	}
	r.act.onAbandon, r.state.Fail = nil, nil
	r.working = false
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded || r.act.restarts != 0 {
		t.Fatalf("settled as %+v, restarts %d", st.Last, r.act.restarts)
	}
}

// A security fix whose mark save fails is not abandoned, so it may start
// at a reboot even though a process restart fails closed (A13).
// Mutant: restore starts: !pt.Security on the mark save.
func TestSecurityWithdrawMarkSaveFailsMayStart(t *testing.T) {
	r := installedHeld(t, true)
	r.state.Fail = errIO
	if err := r.a.Withdraw("a1", WhySecurity); !errors.Is(err, errIO) || !starts(t, err) {
		t.Fatalf("withdraw: %v", err)
	}
	r.state.Fail = nil
	if r.act.abandoned != 0 {
		t.Fatal("abandoned without the mark")
	}
	if got := r.a.Status(); got != mayStart {
		t.Fatalf("status %q", got)
	}
}

// A stale security fix (A13: the process restart lost its held release)
// says it may start until the Tick's Abandon is recorded, then that it
// will not; a reboot into the old root after that record is the
// withdrawal finishing, not a fallback.
// Mutant: drop the Abandoned guard on the stale line, and the first
// STATUS says it will not start; drop pt.Abandoned from Resume's
// withdrawal check, and the reboot is recorded as a fallback.
func TestStaleWithdrawSaysWontStartOnlyOnceAbandoned(t *testing.T) {
	ctx := context.Background()
	r := installedHeld(t, true)
	r.restart()
	r.must(r.a.Resume(ctx))
	if got := r.a.Status(); got != staleMayStatus {
		t.Fatalf("status before the Tick %q", got)
	}
	r.working = false
	r.act.abandonErr = errIO
	if ok, err := r.a.Tick(ctx); ok || !errors.Is(err, errIO) || r.act.restarts != 0 {
		t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
	}
	if got := r.a.Status(); got != staleMayStatus {
		t.Fatalf("status after a failed Abandon %q", got)
	}
	r.act.abandonErr = nil
	r.act.onAbandon = func() { r.afterSave = func() { r.state.Fail = errIO } }
	if ok, err := r.a.Tick(ctx); ok || !errors.Is(err, errIO) {
		t.Fatalf("tick: %v %v", ok, err)
	}
	if pt := r.saved().Applying; pt == nil || pt.Withdrawing || !pt.Abandoned {
		t.Fatalf("applying %+v", pt)
	}
	if got := r.a.Status(); got != staleStatus {
		t.Fatalf("status after the Abandon took %q", got)
	}
	r.act.onAbandon, r.state.Fail = nil, nil
	r.bootOldRoot()
	r.must(r.a.Resume(ctx))
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != doneNotHanded || r.a.FellBack(1) {
		t.Fatalf("settled as %+v, fell back %v", st.Last, r.a.FellBack(1))
	}
	for _, c := range r.pipe.calls {
		if strings.HasPrefix(c, "fail ") || strings.HasPrefix(c, "confirm ") {
			t.Fatalf("pipeline: %q", r.pipe.calls)
		}
	}
}
