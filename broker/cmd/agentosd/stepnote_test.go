package main

// REQ: REV-1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// The guest plane learns a failed step snapshot's reason only through
// the plane's own marks; a layer too deep to measure, which the manager
// also reports as a disk budget, is too deep (SR2-3s).
func TestSR23sStepErrMarksTheReason(t *testing.T) {
	deep := fmt.Errorf("%w (%w)", vm.ErrQuota, vm.ErrTooDeep)
	for _, tc := range []struct {
		err      error
		deep, no bool
	}{
		{deep, true, false},
		{fmt.Errorf("%w (layer 9 bytes, cap 1)", vm.ErrQuota), false, true},
		{errors.New("pause failed"), false, false},
	} {
		got := stepErr(tc.err)
		if errors.Is(got, guest.ErrStepTooDeep) != tc.deep || errors.Is(got, guest.ErrStepNoRoom) != tc.no || !errors.Is(got, tc.err) {
			t.Errorf("stepErr(%v) = %v", tc.err, got)
		}
	}
	if stepErr(nil) != nil {
		t.Error("a snapshot taken reports an error")
	}
	var n stepNotes
	if n.Note() != "" {
		t.Error("a line before the plane opens")
	}
}

type fakeSteps struct{ line string }

func (f fakeSteps) StepNote() string { return f.line }

// STATUS carries the plane's Rollback line: newStepNotes adds it to the
// notes main hands the daemon, empty until the plane opens (L3 on #179).
func TestSR23sStatusNotesCarryTheLine(t *testing.T) {
	var notes []func() string
	steps := newStepNotes(&notes)
	if len(notes) != 1 || notes[0]() != "" {
		t.Fatalf("notes %d before the plane opens", len(notes))
	}
	line := "Rollback: the agent's files since 08:59 can't be rolled back yet; they're full. It has been told to free space. UNDO still works. Nothing to do unless this lasts."
	steps.open(fakeSteps{line})
	if got := notes[0](); got != line {
		t.Fatalf("STATUS note = %q", got)
	}
}
