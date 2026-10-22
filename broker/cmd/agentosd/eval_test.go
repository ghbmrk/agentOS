package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: LOOP-5, CHG-1

type recServices struct{ opened []string }

func (r *recServices) Open(id string) (string, error) {
	r.opened = append(r.opened, id)
	return "sock", nil
}
func (r *recServices) Close(string) {}

// A machine named as a replay machine never reaches the live plane with
// its journal, executors and owner (replay R7): agentosd runs none, so it
// gets no services and cannot start.
func TestLOOP5ReplayMachinesNeverReachTheLivePlane(t *testing.T) {
	live := &recServices{}
	var s lateServices
	s.live.Store(&svc{live})
	for _, id := range []string{"agent", vm.EvalPrefix + "0a1b", "agent-fork"} {
		_, err := s.Open(id)
		if replay := id == vm.EvalPrefix+"0a1b"; replay != (err != nil) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if len(live.opened) != 2 || live.opened[0] != "agent" || live.opened[1] != "agent-fork" {
		t.Fatalf("live %q", live.opened)
	}
	if modelroute.EvalPrefix != vm.EvalPrefix {
		t.Fatalf("modelroute.EvalPrefix %q != vm.EvalPrefix %q", modelroute.EvalPrefix, vm.EvalPrefix)
	}
}
