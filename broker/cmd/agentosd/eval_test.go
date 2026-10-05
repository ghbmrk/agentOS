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

// A replay machine reaches only the evaluator's plane, never the live one
// with its journal, executors and owner; with no evaluator it cannot start.
func TestLOOP5ReplayMachinesReachOnlyTheEvaluator(t *testing.T) {
	live, ev := &recServices{}, &recServices{}
	var s lateServices
	if _, err := s.Open(vm.EvalPrefix + "0a1b"); err == nil {
		t.Fatal("replay machine started with no evaluator")
	}
	s.live.Store(&svc{live})
	s.eval.Store(&svc{ev})
	for _, id := range []string{"agent", vm.EvalPrefix + "0a1b", "agent-fork"} {
		if _, err := s.Open(id); err != nil {
			t.Fatal(err)
		}
	}
	if len(live.opened) != 2 || len(ev.opened) != 1 || ev.opened[0] != vm.EvalPrefix+"0a1b" {
		t.Fatalf("live %q, evaluator %q", live.opened, ev.opened)
	}
	if modelroute.EvalPrefix != vm.EvalPrefix {
		t.Fatalf("modelroute.EvalPrefix %q != vm.EvalPrefix %q", modelroute.EvalPrefix, vm.EvalPrefix)
	}
}
