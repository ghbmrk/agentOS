package daemon

// REQ: KRN-7, CH-12

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// RESUME names the steps the kernel's STOP cancelled, read through
// bothStops before the lift, and says nothing of a cancel when it
// cancelled none (#5665). Catches a note said after a STOP that cancelled
// nothing, or one dropped after a STOP that cancelled two.
func TestResumeNamesTheKernelsCancelsOnlyWhenThereAreAny(t *testing.T) {
	for n, want := range map[int]string{
		0: "Resumed. Held actions may now run.",
		2: "Resumed. Held actions may now run. STOP cancelled 2 actions; they stay cancelled, so ask again for any you still want.",
	} {
		k := &fakeKernel{cancelled: n}
		dir := withKernel(t, k)
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
// followed by a re-STOP, which may restart the kernel's count; the next
// RESUME then keeps the general note rather than read a 0 as no loss, and
// one after a RESUME that succeeded reads the count again (L3 on #5734).
// Catches the retried RESUME going silent on the first STOP's cancels.
func TestAFailedResumeLeavesTheLossOpen(t *testing.T) {
	k := &fakeKernel{cancelled: 2, lost: true}
	dir := withKernel(t, k)
	text(t, dir, owner, "STOP")
	if r := resume(t, dir); !strings.HasPrefix(r, "RESUME failed") {
		t.Fatalf("RESUME with its answer lost: %q", r)
	}
	k.set(func(k *fakeKernel) { k.lost, k.cancelled = false, 0 }) // the re-STOP restarted the count
	if r, want := resume(t, dir), "Resumed. Held actions may now run. "+control.StopCancelledNote; r != want {
		t.Fatalf("the retried RESUME: %q, want %q", r, want)
	}
	text(t, dir, owner, "STOP")
	if r, want := resume(t, dir), "Resumed. Held actions may now run."; r != want {
		t.Fatalf("after a RESUME that succeeded: %q, want %q", r, want)
	}
}
