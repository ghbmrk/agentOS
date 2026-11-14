package daemon

// REQ: KRN-7, CH-12

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
)

// RESUME names the steps the kernel's STOP cancelled, read through
// bothStops before the lift, and says nothing of a cancel when it
// cancelled none (#5665), from the first STOP this process sends to a
// kernel not stopped; a STOP in force when agentosd started may predate
// it, so its RESUME gives the general note (L3, Security on #5734).
// Catches a note said after a STOP that cancelled nothing, one dropped
// after a STOP that cancelled two, or a count trusted across a restart.
func TestResumeNamesTheKernelsCancelsOnlyWhenThereAreAny(t *testing.T) {
	head := "Resumed. Held actions may now run."
	for n, want := range map[int]string{
		0: head,
		2: head + " STOP cancelled 2 actions; they stay cancelled, so ask again for any you still want.",
	} {
		k := &fakeKernel{cancelled: n}
		dir := withKernel(t, k)
		text(t, dir, owner, "STOP")
		if r := resume(t, dir); r != want {
			t.Errorf("%d cancelled: %q, want %q", n, r, want)
		}
	}
	// The kernel was stopped when this process started.
	k := &fakeKernel{stopped: true}
	dir := withKernel(t, k)
	text(t, dir, owner, "STOP")
	if r, want := resume(t, dir), head+" "+control.StopCancelledNote; r != want {
		t.Errorf("a STOP in force at start: %q, want %q", r, want)
	}
	text(t, dir, owner, "STOP")
	if r := resume(t, dir); r != head {
		t.Errorf("the next STOP, seen whole: %q, want %q", r, head)
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
		b := &bothStops{k: c.k, whole: true}
		n, err := b.StopCancelled()
		if n != c.n || (err != nil) != c.wantErr {
			t.Errorf("%s: %d %v, want %d (error %v)", c.name, n, err, c.n, c.wantErr)
		}
	}
	if _, err := (&bothStops{k: &fakeKernel{stopped: true}}).StopCancelled(); err == nil {
		t.Error("a count not seen whole was trusted")
	}
	if r := (&bothStops{k: &fakeKernel{down: true}, whole: true}); !strings.Contains(control.CancelledNote(r), "STOP may have cancelled some") {
		t.Errorf("a kernel not answering dropped the note: %q", control.CancelledNote(r))
	}
}

// A RESUME that fails after the kernel may have lifted its STOP is
// followed by a re-STOP, which may restart the kernel's count: its failure
// reply names what was read before it, in a form that waits for a RESUME
// that works, and the next RESUME keeps the general note, in this process
// (whole) and after a restart (the kernel is stopped at start); one after
// a RESUME that succeeded reads the count again (L3, Security on #5734).
// Security's repro: three lost, a plan logged before the re-STOP,
// agentosd restarted, the kernel's count now 1. Catches the owner told
// less than the first STOP's loss.
func TestAFailedResumeLeavesTheLossOpen(t *testing.T) {
	head := "Resumed. Held actions may now run."
	k := &fakeKernel{cancelled: 3}
	dir := withKernel(t, k)
	text(t, dir, owner, "STOP")
	k.set(func(k *fakeKernel) { k.lost = true })
	if r, want := resume(t, dir), "RESUME failed to record. Still stopped. STOP cancelled 3 actions; they stay cancelled; once RESUME works, ask again for any you still want."; r != want {
		t.Fatalf("RESUME with its answer lost: %q, want %q", r, want)
	}
	k.set(func(k *fakeKernel) { k.lost, k.cancelled = false, 1 }) // the re-STOP restarted the count
	text(t, dir, owner, "STOP")                                   // a STOP on the stopped kernel trusts nothing
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

// A RESUME whose kernel lift landed before agentosd died, untold, leaves
// the journal stopped and the kernel lifted; the restarted process does
// not take the owner's next STOP as starting the count whole, so its
// RESUME gives the general note, not only the new count (Security on
// #5734). Catches the first STOP's cancels never named.
func TestALiftInterruptedByARestartLeavesTheLossOpen(t *testing.T) {
	ctx := context.Background()
	k := &fakeKernel{cancelled: 3}
	j := &journalStopped{stopped: true} // the journal's STOP held; its RESUME never ran
	b := &bothStops{Engine: j, k: k}
	// The kernel's STOP is in force, then its lift lands and the process dies.
	k.set(func(k *fakeKernel) { k.stopped, k.stops = false, 1 })
	if _, err := b.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	k.set(func(k *fakeKernel) { k.cancelled = 0 }) // this STOP restarted the count
	if n, err := b.StopCancelled(); err == nil {
		t.Fatalf("the STOP after the interrupted lift was trusted: %d", n)
	}
	if r, want := control.CancelledNote(b), " "+control.StopCancelledNote; r != want {
		t.Fatalf("RESUME note %q, want %q", r, want)
	}
}

// journalStopped is the journal's control.Engine, stopped or not.
type journalStopped struct{ stopped bool }

func (j *journalStopped) Stop(context.Context) (control.StopReport, error) {
	j.stopped = true
	return control.StopReport{}, nil
}
func (j *journalStopped) Resume() error          { j.stopped = false; return nil }
func (j *journalStopped) Stopped() bool          { return j.stopped }
func (j *journalStopped) List() []control.Status { return nil }
