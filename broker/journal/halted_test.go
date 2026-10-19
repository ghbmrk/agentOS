package journal

// REQ: OP-6

import (
	"errors"
	"testing"
)

// A STOP whose record fails to write leaves STOP not in force but the
// engine halted: nothing new starts, and the owner's handler can still
// tell the failure from a recorded STOP (SEC-failed-stop-latch, #2458).
func TestOP6FailedStopHaltsWithoutStopping(t *testing.T) {
	cs := &crashStore{MemStore: &MemStore{}, budget: 0}
	e := mustOpen(t, cs, newPolicy(), newService())
	if e.Halted() {
		t.Fatal("halted before any STOP")
	}
	if _, err := e.Stop(ctx); !errors.Is(err, ErrBroken) {
		t.Fatalf("STOP through a failed write: err = %v, want ErrBroken", err)
	}
	if e.Stopped() {
		t.Fatal("a STOP that failed to record reads as recorded")
	}
	if !e.Halted() {
		t.Fatal("a failed STOP left the engine admitting new work")
	}
}

// Halted follows a recorded STOP and RESUME.
func TestOP6HaltedFollowsStopAndResume(t *testing.T) {
	e := mustOpen(t, &MemStore{}, newPolicy(), newService())
	if _, err := e.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if !e.Halted() {
		t.Fatal("not halted under STOP")
	}
	if err := e.Resume(); err != nil {
		t.Fatal(err)
	}
	if e.Halted() {
		t.Fatal("halted after RESUME")
	}
}
