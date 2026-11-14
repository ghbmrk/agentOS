package kernel_test

// REQ: KRN-7, CH-12

// OWN-resume-says-cancelled-fu (#5665): the log counts the steps the STOP
// in force left unsent for good, so RESUME names a loss only when there
// is one.

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// A STOP with nothing unsent counts none; one over a held two-step plan
// counts both; one over a plan whose first step is in flight counts only
// the second, since the first still reconciles (KRN-8). A second STOP
// while stopped adds to the count, a STOP after a RESUME starts it again,
// and a replay of the log folds the same count. Catches a count that says
// a loss with none, misses an unsent step, or counts a sent one.
func TestStopCountsTheStepsItCancels(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Stop(1))
	if n := r.k.State().StopCancelled; n != 0 {
		t.Fatalf("a STOP over nothing counts %d", n)
	}
	must(t, r.k.Resume(2, r.k.State().Stops))

	r.plan("held", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-a"), st(key.Unsubscribe, "list-b"))
	must(t, r.tick(10))
	must(t, r.k.Stop(20))
	if n := r.k.State().StopCancelled; n != 2 {
		t.Fatalf("a STOP over a held two-step plan counts %d, want 2", n)
	}
	must(t, r.k.Stop(30))
	if n := r.k.State().StopCancelled; n != 2 {
		t.Fatalf("a second STOP while stopped left %d, want the first's 2", n)
	}
	must(t, r.k.Resume(40, r.k.State().Stops))
	if n := r.k.State().StopCancelled; n != 2 {
		t.Fatalf("RESUME changed the count to %d", n)
	}

	lost := 1
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" && lost > 0 {
			lost--
			return clerk.FaultLostAck
		}
		return ""
	}
	r.plan("sent", r.ck, st(key.Trash, "m1"), st(key.Organize, "m2"))
	must(t, r.tick(50))
	must(t, r.k.Stop(60))
	if n := r.k.State().StopCancelled; n != 1 {
		t.Fatalf("a STOP over a plan with its first step in flight counts %d, want 1", n)
	}
	must(t, r.k.Resume(70, r.k.State().Stops))
	must(t, r.k.Stop(80))
	if n := r.k.State().StopCancelled; n != 0 {
		t.Fatalf("a STOP after a RESUME over nothing new counts %d", n)
	}
	r.replays()
}
