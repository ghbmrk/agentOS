package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// REQ: UPD-4, UPD-1
//
// MIG-4-adapters-e-pin (#3699): pinned means no automatic update. A pin
// after the handover withdraws the release before any boot takes it
// (Abandon, DropStaged, the adoption dropped), marked durably first, and
// STATUS and the digest say so; once the box has booted the new slot the
// release stays (Security on #3701). A release pinned during its jitter
// says it is paused at once. A pinned channel submitting no plan is
// TestBusyBoxHoldsActivation.

const (
	pinnedStatus = "Update 1 is withdrawn because your update channel is pinned; I will not start it."
	pinnedDigest = "Update 1 was ready to start, but your update channel is pinned, so I withdrew it."
)

// pinWithdrawn: the handover was undone for the pin and the adoption
// dropped, with no fallback recorded and nothing restarted into; an
// unrelated reboot then boots the running root, and the owner is told.
func (r *rig) pinWithdrawn() {
	r.t.Helper()
	ctx := context.Background()
	if r.act.restarts != 0 || r.act.abandoned != 1 || r.a.FellBack(1) {
		r.t.Fatalf("activator %+v, fell back %v", r.act, r.a.FellBack(1))
	}
	if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != donePinned {
		r.t.Fatalf("settled as %+v, applying %+v", st.Last, st.Applying)
	}
	if _, ok, _ := r.store.Staged(); ok {
		r.t.Fatal("still staged")
	}
	r.dropsAre("a1")
	if got := r.a.Status(); got != pinnedStatus {
		r.t.Fatalf("status %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != pinnedDigest {
		r.t.Fatalf("digest %q", d)
	}
	// The failure path: an unrelated reboot. The running root boots.
	r.must(r.act.Restart(ctx))
	if r.act.boot.UsrRootHash != strings.Repeat(oldHash, 32) {
		r.t.Fatalf("booted the pinned-against release: %+v", r.act.boot)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 0 {
		r.t.Fatalf("installed %+v", in)
	}
	if len(r.pipe.failed) != 0 || r.a.FellBack(1) {
		r.t.Fatalf("judged a fallback: %+v", r.pipe)
	}
	if got := r.a.Status(); got != pinnedStatus {
		r.t.Fatalf("status after the reboot %q", got)
	}
	r.paused = false
	if got := r.a.Status(); got != "" {
		r.t.Fatalf("status once unpinned %q", got)
	}
}

// Item 1 and 3: a pin after the handover, by Pin or by the next Tick,
// withdraws a security fix or an ordinary release alike, and STATUS stops
// promising a restart as soon as the channel is pinned.
// Mutant: drop the Paused branch in restartIfHandedOver, and the Tick
// case keeps the release; drop withdrawLocked from Pin, and the Pin case
// does.
func TestPinAfterHandoverWithdrawsTheRelease(t *testing.T) {
	for _, security := range []bool{true, false} {
		for _, by := range []string{"Pin", "Tick"} {
			t.Run(fmt.Sprintf("%s security=%v", by, security), func(t *testing.T) {
				r := installedHeld(t, security)
				r.paused = true
				if got := r.a.Status(); got != pinnedStatus {
					t.Fatalf("status once pinned %q", got)
				}
				if by == "Pin" {
					r.must(r.a.Pin(context.Background()))
				} else if ok, err := r.a.Tick(context.Background()); ok || err != nil {
					t.Fatalf("tick: %v %v", ok, err)
				}
				r.working = false
				r.pinWithdrawn()
			})
		}
	}
}

// A pin is not taken while the release is being installed: Pin refuses
// with the handover error, and the same Tick withdraws the release once
// the activator took it; Pin then succeeds.
func TestPinWhileInstallingIsNotTaken(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	var during error
	r.act.onInstall = func() {
		r.paused = true
		during = r.a.Pin(ctx)
	}
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.act.onInstall = nil
	if starts(t, during) {
		t.Fatal("an install in flight said it may start")
	}
	r.must(r.a.Pin(ctx))
	r.pinWithdrawn()
}

// The withdrawal is marked before the slot is abandoned. A failed Abandon
// keeps the pin from being taken, and the release is never restarted into,
// across a process restart; once the Abandon took, a reboot before the
// record is cleared is not judged a fallback.
// Mutant: drop the mark (save) in withdrawLocked, and the cut case
// records a fallback.
func TestPinWithdrawalSurvivesACut(t *testing.T) {
	ctx := context.Background()
	t.Run("abandon fails", func(t *testing.T) {
		r := installedHeld(t, false)
		r.paused = true
		r.act.abandonErr = errIO
		if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) || !errors.Is(err, errIO) {
			t.Fatalf("pin taken: %v", err)
		}
		if pt := r.saved().Applying; pt == nil || !pt.Withdrawing || !pt.Pinned {
			t.Fatalf("applying %+v", pt)
		}
		r.restart()
		r.must(r.a.Resume(ctx))
		r.paused, r.working = false, false // even unpinned, it never starts
		if ok, err := r.a.Tick(ctx); ok || !errors.Is(err, errIO) || r.act.restarts != 0 {
			t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
		}
		if got := r.a.Status(); got != pinnedStatus {
			t.Fatalf("status %q", got)
		}
		r.act.abandonErr = nil
		r.paused = true
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		r.pinWithdrawn()
	})
	t.Run("reboot after the abandon", func(t *testing.T) {
		r := installedHeld(t, false)
		r.paused = true
		r.act.onAbandon = func() { r.state.Fail = errIO }
		if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) {
			t.Fatalf("pin taken: %v", err)
		}
		r.act.onAbandon, r.state.Fail = nil, nil
		r.must(r.act.Restart(ctx))
		r.restart()
		r.must(r.a.Resume(ctx))
		if st := r.saved(); st.Applying != nil || st.Last == nil || st.Last.Kind != donePinned || r.a.FellBack(1) || len(r.pipe.failed) != 0 {
			t.Fatalf("settled as %+v, fell back %v, pipeline %+v", st.Last, r.a.FellBack(1), r.pipe)
		}
		if got := r.a.Status(); got != pinnedStatus {
			t.Fatalf("status %q", got)
		}
	})
}

// A pin that lands while the box decides to restart: once the restart is
// under way Pin says the release may start; a pin seen before it is under
// way holds it, and the next Tick withdraws it.
// Mutant: drop Paused from the check under the lock before the restart,
// and the second case restarts.
func TestPinRacesTheRestart(t *testing.T) {
	ctx := context.Background()
	t.Run("restart under way", func(t *testing.T) {
		r := installedHeld(t, false)
		r.working = false
		var during error
		r.act.onRestart = func() {
			r.paused = true
			during = r.a.Pin(ctx)
		}
		if ok, err := r.a.Tick(ctx); !ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		if !starts(t, during) {
			t.Fatal("a restart under way did not say it may start")
		}
	})
	t.Run("pinned before it", func(t *testing.T) {
		r := installedHeld(t, false)
		r.working = false
		r.atBusy = func() { r.paused = true }
		if ok, err := r.a.Tick(ctx); ok || err != nil || r.act.restarts != 0 {
			t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
		}
		if ok, err := r.a.Tick(ctx); ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		r.pinWithdrawn()
	})
}

// Once the box has booted the new slot, a pin keeps it: going back would
// be a downgrade. It commits as usual and is reported installed.
func TestPinAfterTheNewSlotBootedKeepsIt(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, true), "a1"))
	r.act.pending = true // booted, health check not run yet
	if ok, err := r.a.Tick(ctx); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(ctx))
	r.paused = true
	r.must(r.a.Pin(ctx))
	if r.act.abandoned != 0 {
		t.Fatal("abandoned a booted release")
	}
	if got := r.a.Status(); got == pinnedStatus {
		t.Fatalf("status %q", got)
	}
	r.act.boot.Blessed = true
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("installed %+v", in)
	}
	if got := r.a.Status(); got != "" {
		t.Fatalf("status %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != "Update 1 is installed." {
		t.Fatalf("digest %q", d)
	}
}

// Item 4: a release pinned during its jitter says it is paused at once,
// not "soon".
// Mutant: drop Paused from Status's due test.
func TestPinnedDuringTheJitterSaysPaused(t *testing.T) {
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	r.paused = true
	if got := r.a.Status(); got != "Update 1 waits because your update channel is pinned." {
		t.Fatalf("status %q", got)
	}
	r.paused = false
	if got := r.a.Status(); got != "Update 1 will install soon. Nothing is needed from you." {
		t.Fatalf("status %q", got)
	}
}

// Security blocker on #3812: a pin between the clerk's own checks and the
// handover. Pin finds nothing applied and returns nil, so the pin is
// reported taken; execute then refuses, and nothing becomes the next boot.
// Mutant: drop the Paused check in execute, and the release is handed over
// and installs at the next boot.
func TestPinBetweenAuthorizeAndExecuteIsRefused(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	r.must(r.a.Schedule(r.release(1, false), "a1"))
	r.clk.add(7 * time.Hour) // past the jitter
	var pinErr error
	r.atDispatch = func() {
		r.paused = true
		pinErr = r.a.Pin(ctx)
	}
	r.hold = true
	if ok, err := r.a.Tick(ctx); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.hold = false
	r.tick()
	if pinErr != nil {
		t.Fatalf("pin: %v", pinErr)
	}
	if st := r.step(); st.Phase != kernel.PFailed || st.Detail != RPaused {
		t.Fatalf("logged %+v, want failed %q", st, RPaused)
	}
	if len(r.act.installed) != 0 || r.saved().Applying != nil {
		t.Fatalf("handed over after the pin: installed %v, applying %+v", r.act.installed, r.saved().Applying)
	}
	if got := r.a.Status(); got != "Update 1 waits because your update channel is pinned." {
		t.Fatalf("status %q", got)
	}
	r.must(r.act.Restart(ctx))
	r.restart()
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 0 {
		t.Fatalf("installed %+v", in)
	}
}

// Security release 2 on #3812: a pin withdrawal cut before its Abandon
// took, then a reboot into the counted entry: the box runs the new slot,
// so STATUS does not say it will not start it; the release stays (the
// #3701 boundary).
// Mutant: drop the handover-boot gate on the Pinned case in Status.
func TestPinnedLineOnlyInTheHandoverBoot(t *testing.T) {
	ctx := context.Background()
	r := installedHeld(t, false)
	r.paused = true
	r.act.abandonErr = errIO
	if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) {
		t.Fatalf("pin taken: %v", err)
	}
	r.act.abandonErr = nil
	r.act.pending = true // the new slot boots; health check not run yet
	r.must(r.act.Restart(ctx))
	r.restart()
	r.must(r.a.Resume(ctx))
	r.must(r.a.Pin(ctx))
	if got := r.a.Status(); got == pinnedStatus {
		t.Fatalf("status %q while the new slot runs", got)
	}
	r.act.boot.Blessed = true
	r.must(r.a.Resume(ctx))
	if in, _ := r.store.Installed(); in.Version != 1 {
		t.Fatalf("installed %+v", in)
	}
}

// L3 release 3 on #3812: an unreadable boot is not taken for "nothing
// can start": the pin is not reported taken.
// Mutant: Pin returns nil when Booted fails.
func TestPinWithAnUnreadableBootIsNotTaken(t *testing.T) {
	r := installedHeld(t, false)
	r.paused = true
	r.act.bootedErr = errIO
	if err := r.a.Pin(context.Background()); !errors.Is(err, errIO) || !starts(t, err) {
		t.Fatalf("pin taken: %v", err)
	}
	if r.act.abandoned != 0 {
		t.Fatal("abandoned on an unreadable boot")
	}
	r.act.bootedErr = nil
	r.must(r.a.Pin(context.Background()))
	r.working = false
	r.pinWithdrawn()
}

// Security release 1 on #3822: a pin withdrawal whose Abandon failed,
// or a pin not yet marked, while the boot cannot be read: no Tick
// restarts, so STATUS promises neither a start nor a restart; once the
// boot reads as the handover boot it says withdrawn.
// Mutant: drop the unreadable-boot case from Status.
func TestPinnedLineWithAnUnreadableBoot(t *testing.T) {
	const held = "Update 1 waits because your update channel is pinned; I will not restart into it."
	for _, marked := range []bool{true, false} {
		r := installedHeld(t, false)
		r.paused = true
		if marked {
			r.act.abandonErr = errIO
			if err := r.a.Pin(context.Background()); !errors.Is(err, ErrApplying) {
				t.Fatalf("pin taken: %v", err)
			}
			if pt := r.saved().Applying; pt == nil || !pt.Pinned {
				t.Fatalf("not marked pinned: %+v", pt)
			}
		}
		r.act.bootedErr = errIO
		if got := r.a.Status(); got != held {
			t.Fatalf("marked %v: status %q", marked, got)
		}
		if _, err := r.a.Tick(context.Background()); err == nil || r.act.restarts != 0 {
			t.Fatalf("marked %v: tick %v, restarts %d", marked, err, r.act.restarts)
		}
		r.act.bootedErr, r.act.abandonErr = nil, nil
		if got := r.a.Status(); got != pinnedStatus {
			t.Fatalf("marked %v: status %q", marked, got)
		}
	}
}
