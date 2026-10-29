package apply

import (
	"context"
	"strings"
	"testing"
	"time"
)

// SR3-4f-r1-f2: when no apply is in flight and the box runs another root
// than the update store's installed release, STATUS says the box runs the
// previous version, with no restart promise: execute's save before Stage
// ended the other-root promise, so a later release that fails, falls back
// or is withdrawn must not leave the owner told nothing.

// REQ: UPD-1, UPD-1a, CH-12

const prevSentence = "I am running the previous version, not update 1."

const prevLine = prevSentence + " Nothing is needed from you; a later update will replace it."

// checkPrevious asserts STATUS in this boot and a later old-root boot.
func (r *rig) checkPrevious(want string) {
	r.t.Helper()
	for i := 0; i < 2; i++ {
		if got := r.a.Status(); got != want {
			r.t.Fatalf("status in boot %s: %q", r.act.boot.ID, got)
		}
		r.bootOldRoot()
	}
}

func TestPreviousRootAfterNextReleaseWithdrawn(t *testing.T) {
	for _, c := range []struct {
		name string
		arm  func(r *rig)
	}{
		{"install fails", func(r *rig) { r.act.installErr = errIO }},
		{"handover unrecorded", func(r *rig) { r.act.onInstall = func() { r.state.Fail = errIO } }},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := mirroredOnOldRoot(t)
			r.restart()
			r.must(r.a.Schedule(r.release(2, false), "a2"))
			r.clk.add(7 * time.Hour)
			c.arm(r)
			if ok, err := r.a.Tick(context.Background()); ok || err != nil {
				t.Fatalf("tick: %v %v", ok, err)
			}
			r.act.installErr, r.state.Fail = nil, nil
			r.must(r.a.Withdraw("a2", "undo"))
			r.checkPrevious(prevLine)
		})
	}
}

func TestPreviousRootAfterNextStageFails(t *testing.T) {
	r, _ := settleOnOldRoot(t)
	r.restart()
	r.must(r.a.Schedule(r.release(2, true), "a2"))
	if _, err := r.a.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.must(r.a.Withdraw("a2", "undo"))
	r.checkPrevious(prevLine)
}

func TestPreviousRootAfterNextFallsBack(t *testing.T) {
	r := mirroredOnOldRoot(t)
	r.restart()
	r.must(r.a.Schedule(r.release(2, false), "a2"))
	r.clk.add(7 * time.Hour)
	r.act.failBoot = true
	if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.restart()
	r.must(r.a.Resume(context.Background()))
	if l := r.saved().Last; l == nil || l.Kind != doneFellBack || l.Version != 2 {
		t.Fatalf("settled as %+v", l)
	}
	want := fellBackLine(2) + " " + prevSentence
	if got := r.a.Status(); got != want {
		t.Fatalf("status: %q", got)
	}
	if d := r.a.Digest(); len(d) != 1 || d[0] != want {
		t.Fatalf("digest: %q", d)
	}
}

func TestPreviousRootAfterInstalled(t *testing.T) {
	r, _ := handedOver(t, false)
	r.restart()
	r.must(r.a.Resume(context.Background()))
	r.settledInstalled()
	r.bootOldRoot()
	if got := r.a.Status(); got != prevLine {
		t.Fatalf("status: %q", got)
	}
}

// The line needs a readable boot and an idle applier, and ends once the
// installed release runs.
func TestPreviousRootLineIsQuiet(t *testing.T) {
	t.Run("apply waiting", func(t *testing.T) {
		r := mirroredOnOldRoot(t)
		r.restart()
		r.must(r.a.Schedule(r.release(2, false), "a2"))
		if got := r.a.Status(); strings.Contains(got, "previous version") {
			t.Fatalf("status: %q", got)
		}
	})
	t.Run("apply in flight", func(t *testing.T) {
		r := mirroredOnOldRoot(t)
		r.restart()
		r.must(r.a.Schedule(r.release(2, false), "a2"))
		r.clk.add(7 * time.Hour)
		r.act.failBoot = true
		if ok, err := r.a.Tick(context.Background()); !ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		if s := r.a.Status(); strings.Contains(s, "previous version") {
			t.Fatalf("status before the settle: %q", s)
		}
	})
	t.Run("boot unreadable", func(t *testing.T) {
		r := mirroredOnOldRoot(t)
		r.restart()
		r.must(r.a.Schedule(r.release(2, false), "a2"))
		r.clk.add(7 * time.Hour)
		r.act.installErr = errIO
		if ok, err := r.a.Tick(context.Background()); ok || err != nil {
			t.Fatalf("tick: %v %v", ok, err)
		}
		r.act.installErr = nil
		r.must(r.a.Withdraw("a2", "undo"))
		r.act.bootedErr = errIO
		if got := r.a.Status(); got != "" {
			t.Fatalf("status: %q", got)
		}
	})
	t.Run("installed root runs", func(t *testing.T) {
		r, _ := settleOnOldRoot(t)
		r.bootNewRoot()
		if got := r.a.Status(); got != "" {
			t.Fatalf("status: %q", got)
		}
	})
}

// Combined release 1 on #3831's delta: the withdrawn line with the
// previous-version line, as STATUS says it, puts that line before
// "Nothing is needed from you." (CH-12).
// Mutants: append the previous-version line after it in Status, or drop
// it there.
func TestPreviousRootAfterNextReleasePinned(t *testing.T) {
	r := mirroredOnOldRoot(t)
	r.restart()
	r.must(r.a.Schedule(r.release(2, false), "a2"))
	r.clk.add(7 * time.Hour)
	r.act.onInstall = func() { r.working = true } // holds the restart
	if ok, err := r.a.Tick(context.Background()); ok || err != nil {
		t.Fatalf("tick: %v %v", ok, err)
	}
	r.act.onInstall = nil
	r.paused = true
	r.must(r.a.Pin(context.Background()))
	const want = "Update 2 was withdrawn because you pinned your update channel. " + prevSentence + " Nothing is needed from you."
	if got := r.a.Status(); got != want {
		t.Fatalf("status %q", got)
	}
}
