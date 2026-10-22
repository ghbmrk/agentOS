package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/guest"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: FORGET-FOLDS-3

// The daemon's own services are a vm.Resetter, as the guest plane is.
var (
	_ vm.Resetter = (*lateServices)(nil)
	_ vm.Resetter = (*guest.Plane)(nil)
)

type resetServices struct {
	recServices
	resets []string
}

func (r *resetServices) Reset(id string) { r.resets = append(r.resets, id) }

// FORGET-FOLDS-3 (CAP-3): the manager's services in the daemon pass
// ForgetSince's reset on to the live guest plane, so its held results go;
// services that hold nothing derived are skipped, and an unset plane is
// not an error.
func TestForgetResetReachesTheLivePlane(t *testing.T) {
	var s lateServices
	s.Reset("agent") // nothing stored yet
	live := &resetServices{}
	s.live.Store(&svc{live})
	s.Reset("agent")
	s.Reset(vm.EvalPrefix + "0a1b")
	if len(live.resets) != 1 || live.resets[0] != "agent" {
		t.Fatalf("live plane reset %q, want only agent", live.resets)
	}
}
