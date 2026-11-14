package daemon

// REQ: KRN-7, CH-12

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// RESUME names the steps the kernel's STOP cancelled, read through
// bothStops before the lift, and says nothing of a cancel when it
// cancelled none (#5665); the first RESUME since agentosd started gives
// the general note, since the STOP in force may predate it (L3, Security
// on #5734). Catches a note said after a STOP that cancelled nothing, one
// dropped after a STOP that cancelled two, or a count trusted across a
// restart.
func TestResumeNamesTheKernelsCancelsOnlyWhenThereAreAny(t *testing.T) {
	head := "Resumed. Held actions may now run."
	for n, want := range map[int]string{
		0: head,
		2: head + " STOP cancelled 2 actions; they stay cancelled, so ask again for any you still want.",
	} {
		k := &fakeKernel{cancelled: n}
		dir := withKernel(t, k)
		text(t, dir, owner, "STOP")
		if r := resume(t, dir); r != head+" "+control.StopCancelledNote {
			t.Errorf("%d cancelled, the first RESUME since start: %q", n, r)
		}
		text(t, dir, owner, "STOP")
		if r := resume(t, dir); r != want {
			t.Errorf("%d cancelled: %q, want %q", n, r, want)
		}
	}
}

// bothStops reads the count only from a stopped kernel: one not stopped
// cancelled nothing this RESUME lifts, a setup-only kernel holds no plan,
// and one not answering is an error, so RESUME keeps the general note.
func TestBothStopsReadsTheCancelsOfTheStopInForce(t *testing.T) {
	for _, c := range []struct {
		name    string
		k       *fakeKernel
		n       int
		wantErr bool
	}{
		{"stopped", &fakeKernel{stopped: true, cancelled: 3}, 3, false},
		{"not stopped", &fakeKernel{cancelled: 3}, 0, false},
		{"setup only", &fakeKernel{setup: true, cancelled: 3}, 0, false},
		{"down", &fakeKernel{down: true, stopped: true, cancelled: 3}, 0, true},
		{"read refused", &fakeKernel{stopped: true, uncounted: true}, 0, true},
		{"count still open", &fakeKernel{stopped: true, cancelled: 1, open: true}, 0, true},
	} {
		b := &bothStops{k: c.k}
		n, err := b.StopCancelled()
		if n != c.n || (err != nil) != c.wantErr {
			t.Errorf("%s: %d %v, want %d (error %v)", c.name, n, err, c.n, c.wantErr)
		}
	}
	if r := (&bothStops{k: &fakeKernel{down: true}}); !strings.Contains(control.CancelledNote(r), "STOP may have cancelled some") {
		t.Errorf("a kernel not answering dropped the note: %q", control.CancelledNote(r))
	}
}

// A RESUME that fails after the kernel may have lifted its STOP is
// followed by a re-STOP, which may restart the kernel's count: its failure
// reply names what was read before it, and the next RESUME keeps the
// general note, in this process (lossOpen) and after a restart (a fresh
// bothStops starts open); one after a RESUME that succeeded reads the
// count again (L3, Security on #5734). Security's repro: three lost, a
// plan logged before the re-STOP, agentosd restarted, the kernel's count
// now 1. Catches the owner told less than the first STOP's loss.
func TestAFailedResumeLeavesTheLossOpen(t *testing.T) {
	head := "Resumed. Held actions may now run."
	k := &fakeKernel{cancelled: 3}
	dir := withKernel(t, k)
	text(t, dir, owner, "STOP")
	k.set(func(k *fakeKernel) { k.lost = true })
	// The first RESUME since start: the count is not yet trusted, so the
	// failure names the general note (control's handler test pins the count).
	if r, want := resume(t, dir), "RESUME failed to record. Still stopped. "+control.StopCancelledNote; r != want {
		t.Fatalf("RESUME with its answer lost: %q, want %q", r, want)
	}
	k.set(func(k *fakeKernel) { k.lost, k.cancelled = false, 1 }) // the re-STOP restarted the count
	if r, want := resume(t, dir), head+" "+control.StopCancelledNote; r != want {
		t.Fatalf("the retried RESUME: %q, want %q", r, want)
	}
	text(t, dir, owner, "STOP")
	if r, want := resume(t, dir), head+" STOP cancelled 1 action; it stays cancelled, so ask again if you still want it."; r != want {
		t.Fatalf("after a RESUME that succeeded: %q, want %q", r, want)
	}

	// agentosd restarted after the failed RESUME: the kernel is still
	// stopped with the restarted count, and the fresh process trusts none.
	k2 := &fakeKernel{stopped: true, cancelled: 1}
	dir2 := withKernel(t, k2)
	text(t, dir2, owner, "STOP") // the owner STOPs again: the kernel adds nothing
	if r, want := resume(t, dir2), head+" "+control.StopCancelledNote; r != want {
		t.Fatalf("the RESUME after a restart: %q, want %q", r, want)
	}
}
