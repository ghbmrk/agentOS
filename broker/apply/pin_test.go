package apply

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/control"
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
	pinnedStatus = "Update 1 was withdrawn because you pinned your update channel. Nothing is needed from you."
	heldStatus   = "Update 1 is held because you pinned your update channel; I will not start it. Nothing is needed from you."
	pinnedMayRun = "Update 1 was ready to start before you pinned your update channel, so it may have started already. Nothing is needed from you."
	// pinnedMayStart: in the handover boot, a restart is under way or the
	// pin withdrawal's Abandon did not take (#3832).
	pinnedMayStart = "Update 1 was ready to start before you pinned your update channel, and it may still start. Nothing is needed from you."
	// The new slot runs, its health check pending (#3830).
	pinnedStarted = "Update 1 had started before you pinned your update channel; I am checking it. Nothing is needed from you."
	startedStatus = "Update 1 has started; I am checking it. Nothing is needed from you."
	pinnedWait    = "Update 1 waits because you pinned your update channel. Nothing is needed from you."
	pinnedDigest  = "Update 1 was ready to start, but you pinned your update channel, so I withdrew it."
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
				if got := r.a.Status(); got != heldStatus {
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
// across a process restart, though Pin and STATUS say it may start, since
// a reboot would boot the counted entry (#3832); once the Abandon took, a
// reboot before the record is cleared is not judged a fallback.
// Mutant: drop the mark (save) in withdrawLocked, and the cut case
// records a fallback.
func TestPinWithdrawalSurvivesACut(t *testing.T) {
	ctx := context.Background()
	t.Run("abandon fails", func(t *testing.T) {
		r := installedHeld(t, false)
		r.paused = true
		r.act.abandonErr = errIO
		if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) || !errors.Is(err, errIO) || !starts(t, err) {
			t.Fatalf("pin taken, or said it will not start: %v", err)
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
		if got := r.a.Status(); got != pinnedMayStart {
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

// #3832: once the pin withdrawal's Abandon took, it is recorded, so a
// later step that fails leaves Pin saying it will not start, and STATUS
// says held; before that record, both say it may start.
// Mutant: drop the Abandoned save in withdrawHandoverLocked, and STATUS
// says it may start.
func TestPinAfterTheAbandonTookSaysHeld(t *testing.T) {
	ctx := context.Background()
	r := installedHeld(t, false)
	r.paused = true
	r.act.onAbandon = func() { r.afterSave = func() { r.state.Fail = errIO } }
	if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) || starts(t, err) {
		t.Fatalf("pin: %v", err)
	}
	if pt := r.saved().Applying; pt == nil || !pt.Withdrawing || !pt.Pinned || !pt.Abandoned {
		t.Fatalf("applying %+v", pt)
	}
	if got := r.a.Status(); got != heldStatus {
		t.Fatalf("status %q", got)
	}
	r.act.onAbandon, r.state.Fail = nil, nil
	r.working = false
	if ok, err := r.a.Tick(ctx); ok || err != nil || r.act.restarts != 0 {
		t.Fatalf("tick: %v %v, restarts %d", ok, err, r.act.restarts)
	}
	if got := r.a.Status(); got != pinnedStatus {
		t.Fatalf("status %q", got)
	}
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
		var status string
		r.act.onRestart = func() {
			r.paused = true
			during = r.a.Pin(ctx)
			status = r.a.Status()
		}
		if ok, err := r.a.Tick(ctx); !ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		if !starts(t, during) {
			t.Fatal("a restart under way did not say it may start")
		}
		// #3829; mutant: drop the restart check from installedLineLocked.
		if status != pinnedMayStart {
			t.Fatalf("status during the restart %q", status)
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
	if got := r.a.Status(); got != pinnedWait {
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
	if got := r.a.Status(); got != pinnedWait {
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
	if got := r.a.Status(); got != pinnedStarted {
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

// #3829 (release findings of #3828's reviews, its UX lens): STATUS for a
// release the activator took, for each state of the pin (none, the
// channel pinned, a pin withdrawal under way, both) and the boot (the
// handover boot, a later one, unreadable). Only the handover boot is
// promised a next step: a restart unpinned, none pinned or marked, and a
// Tick there does exactly that. A later boot (the new slot running, its
// health check not run yet) or an unreadable one may already run it.
// Each wait or problem line ends with what the owner needs (CH-12).
// Mutants: drop pt.Pinned from installedLineLocked, and a marked
// withdrawal after an unpin promises a restart; take every boot for
// unreadable, or for the handover boot, and the other rows fail.
func TestInstalledStatusByPinAndBoot(t *testing.T) {
	const (
		installing = "Update 1 is installing; I will restart and check it."
		mayRun     = "Update 1 may have started already. Nothing is needed from you."
	)
	for _, boot := range []string{"handover", "later", "unreadable"} {
		for _, marked := range []bool{false, true} {
			for _, pinned := range []bool{false, true} {
				name := fmt.Sprintf("%s boot marked=%v pinned=%v", boot, marked, pinned)
				t.Run(name, func(t *testing.T) {
					ctx := context.Background()
					r := installedHeld(t, false)
					if marked {
						r.paused, r.act.abandonErr = true, errIO
						if err := r.a.Pin(ctx); !errors.Is(err, ErrApplying) {
							t.Fatalf("pin taken: %v", err)
						}
						if pt := r.saved().Applying; pt == nil || !pt.Pinned {
							t.Fatalf("not marked pinned: %+v", pt)
						}
						r.act.abandonErr = nil
					}
					r.paused = pinned
					switch boot {
					case "later":
						r.act.pending = true
						r.must(r.act.Restart(ctx))
						r.restart()
						r.must(r.a.Resume(ctx))
					case "unreadable":
						r.act.bootedErr = errIO
					}
					want := mayRun
					switch {
					case boot == "handover" && !marked && !pinned:
						want = installing
					case boot == "handover" && marked:
						want = pinnedMayStart // its Abandon failed (#3832)
					case boot == "handover":
						want = heldStatus
					case boot == "later" && (marked || pinned):
						want = pinnedStarted
					case boot == "later":
						want = startedStatus
					case marked || pinned:
						want = pinnedMayRun
					}
					if got := r.a.Status(); got != want {
						t.Fatalf("status %q, want %q", got, want)
					}
					if boot != "handover" {
						return
					}
					r.working = false
					restarts := r.act.restarts
					if _, err := r.a.Tick(ctx); err != nil {
						t.Fatalf("tick: %v", err)
					}
					if started := r.act.restarts > restarts; started != (want == installing) {
						t.Fatalf("%q, but the tick restarted: %v", want, started)
					}
				})
			}
		}
	}
}

// Security release 1 on #3822: no Tick restarts a pinned handover while
// the boot cannot be read; once it reads as the handover boot, STATUS
// says held, or that it may start after a failed Abandon (#3832).
func TestPinnedLineWithAnUnreadableBoot(t *testing.T) {
	for _, marked := range []bool{true, false} {
		r := installedHeld(t, false)
		r.paused = true
		if marked {
			r.act.abandonErr = errIO
			if err := r.a.Pin(context.Background()); !errors.Is(err, ErrApplying) {
				t.Fatalf("pin taken: %v", err)
			}
		}
		r.act.bootedErr = errIO
		if got := r.a.Status(); got != pinnedMayRun {
			t.Fatalf("marked %v: status %q", marked, got)
		}
		if _, err := r.a.Tick(context.Background()); err == nil || r.act.restarts != 0 {
			t.Fatalf("marked %v: tick %v, restarts %d", marked, err, r.act.restarts)
		}
		r.act.bootedErr, r.act.abandonErr = nil, nil
		want := heldStatus
		if marked {
			want = pinnedMayStart // its Abandon failed (#3832)
		}
		if got := r.a.Status(); got != want {
			t.Fatalf("marked %v: status %q", marked, got)
		}
	}
}

// #3830 (combined release 1 and delta later 2 on #3831): every STATUS and
// digest line of the applier, each with the previous-version line where
// it can carry one, fits one 160-septet GSM-7 segment at large version
// numbers, in the basic set only (no extension character costs two
// septets), and each wait or problem line ends saying what the owner
// needs (CH-12).
// Mutant: append the previous-version line after "Nothing is needed",
// or use fellBackLine-plus-withPreviousRoot again.
func TestApplyLinesFitOneSegment(t *testing.T) {
	const v, n = 1_000_000_000, 999_999_999
	const none = " Nothing is needed from you."
	needs := map[string]string{} // line: the end it must have; "" any
	for _, f := range []string{wontStartLine, mayStartLine, staleLine, startedLine, mayRunLine,
		pinnedHeldLine, pinnedMayStartLine, pinnedStartedLine, pinnedMayRunLine} {
		needs[fmt.Sprintf(f, v)] = none
	}
	for why, f := range waitLines {
		end := none
		if why == busyStop {
			end = " it installs after RESUME."
		}
		needs[fmt.Sprintf(f, v)] = end
	}
	for _, prev := range []bool{false, true} {
		needs[pinnedText(v, n, prev)] = none
		needs[fellBackText(v, n, prev)] = ""
		needs[unrecordedText(v, n, prev)] = " You can retry it on my Wi-Fi page."
		needs[withPreviousRoot(fmt.Sprintf(pinnedDigestLine, v), n, prev)] = ""
		needs[withPreviousRoot(fmt.Sprintf("Update %d is installed.", v), n, prev)] = ""
		needs[withPreviousRoot(fmt.Sprintf("Update %d was not installed; I will try again.", v), n, prev)] = ""
	}
	needs[previousRootText(n)] = ""
	needs[otherRootText(v)] = none
	for l, end := range needs {
		if !control.IsGSM7(l) || utf8.RuneCountInString(l) > 160 || !strings.HasSuffix(l, end) {
			t.Errorf("%d characters, GSM-7 %v, want end %q: %q", utf8.RuneCountInString(l), control.IsGSM7(l), end, l)
		}
	}
}
