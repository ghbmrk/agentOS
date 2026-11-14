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
// while stopped adds to the count, any STOP after a lift starts it again,
// and a replay of the log folds the same count. Catches a count that says
// a loss with none (a stale one carried onto a later STOP), misses an unsent step, or counts a sent one.
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
	// Any STOP after a lift starts the count over, one right after it
	// included: the kernel cannot tell agentosd's re-STOP from the owner's
	// next STOP, so it never carries a count onto a STOP that cancelled
	// nothing (L3 on #5734); agentosd covers its re-STOP (bothStops.lossOpen).
	must(t, r.k.Resume(70, r.k.State().Stops))
	must(t, r.k.Stop(71))
	if n, open := r.k.State().StopLoss(); n != 0 || open {
		t.Fatalf("a STOP right after the lift carried %d, open %v; want 0, settled", n, open)
	}
	must(t, r.k.Resume(72, r.k.State().Stops))
	must(t, r.tick(2*kernel.ProbeEvery))
	must(t, r.k.Stop(2*kernel.ProbeEvery+1))
	if n, open := r.k.State().StopLoss(); n != 0 || open {
		t.Fatalf("a STOP after the plans ran counts %d, open %v", n, open)
	}
	r.replays()
}

// A step in flight at the STOP whose clerk never acted is cancelled for
// the STOP later, outside its fold: StopLoss counts it once it is known,
// and reads the loss as open while the step is still unsettled, so RESUME
// never goes silent on it (Security on #5734). The repro: a dropped
// request, STOP, then the probes that find it never acted. Catches a
// count that leaves out a STOP-caused cancel made after the fold.
func TestStopLossCountsAnInFlightStepLaterCancelled(t *testing.T) {
	r := newRig(t)
	drop := 1
	r.mail.Fault = func(op string, _ kernel.Request) string {
		if op == "do" && drop > 0 {
			drop--
			return clerk.FaultDrop
		}
		return ""
	}
	r.plan("p1", r.ck, st(key.Trash, "m1"))
	must(t, r.tick(0))
	must(t, r.k.Stop(1))
	if n, open := r.k.State().StopLoss(); n != 0 || !open {
		t.Fatalf("with the step in flight: %d, open %v; want 0, open", n, open)
	}
	must(t, r.tick(kernel.ProbeEvery))
	must(t, r.tick(2*kernel.ProbeEvery))
	p := r.k.State().Plans["p1"]
	if p.Steps[0].Phase != kernel.PCancelled || p.Cancel != key.RStopped || len(r.mail.Effects()) != 0 {
		t.Fatalf("phase %s, cancel %s, %d effects", p.Steps[0].Phase, p.Cancel, len(r.mail.Effects()))
	}
	if n, open := r.k.State().StopLoss(); n != 1 || open {
		t.Fatalf("after the probes: %d, open %v; want 1, settled", n, open)
	}
	r.replays()
}
