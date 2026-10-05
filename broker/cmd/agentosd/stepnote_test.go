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
