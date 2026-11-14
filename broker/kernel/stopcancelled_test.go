package kernel_test

// REQ: KRN-7, CH-12

// OWN-resume-says-cancelled-fu (#5665): the log counts the steps the STOP
// in force left unsent for good, so RESUME names a loss only when there
// is one.

import (
	"encoding/json"
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
	// nothing (L3 on #5734); agentosd covers its re-STOP (bothStops.whole).
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

// The count's edges (mutgate on #5734): a plan whose current step is not
// its first counts from that step on; an ended plan whose sent step is
// not its first counts the steps after it, and once that step reconciles
// done the loss is settled; a retried step the STOP parks is not lost;
// StopLoss starts from the fold's count. Catches a count off by the
// steps already run, a parked retry counted, a done step read as open, or
// the fold's count dropped.
func TestStopCountsFromThePlansCurrentStep(t *testing.T) {
	// Held, second step current: steps 1 and 2 of 3.
	r := newRig(t)
	r.plan("held", r.derive(key.LimitHold(hour, hour)), st(key.Unsubscribe, "a"), st(key.Unsubscribe, "b"), st(key.Unsubscribe, "c"))
	must(t, r.tick(0))
	must(t, r.tick(hour+1))
	must(t, r.tick(hour+2))
	if p := r.k.State().Plans["held"]; p.Next != 1 || p.Steps[0].Phase != kernel.PDone {
		t.Fatalf("next %d, first step %s; want the second step current", p.Next, p.Steps[0].Phase)
	}
	must(t, r.k.Stop(hour+3))
	if n, open := r.k.State().StopLoss(); n != 2 || open {
		t.Fatalf("a STOP at the second of three held steps: %d, open %v; want 2, settled", n, open)
	}
	r.replays()

	// Ended, second step sent: only the third of 3.
	r = newRig(t)
	lost := 1
	r.mail.Fault = func(op string, req kernel.Request) string {
		if op == "do" && req.Index == 1 && lost > 0 {
			lost--
			return clerk.FaultLostAck
		}
		return ""
	}
	r.plan("sent", r.ck, st(key.Trash, "m1"), st(key.Organize, "m2"), st(key.Organize, "m3"))
	for at := int64(0); r.k.State().Plans["sent"].Next < 1; at++ {
		must(t, r.tick(at))
	}
	must(t, r.tick(10))
	if ph := r.k.State().Plans["sent"].Steps[1].Phase; ph == kernel.PDone {
		t.Fatalf("second step %s, want it unsettled", ph)
	}
	must(t, r.k.Stop(20))
	if n, open := r.k.State().StopLoss(); n != 1 || !open {
		t.Fatalf("a STOP at the second of three, sent: %d, open %v; want 1, open", n, open)
	}
	for at := int64(kernel.ProbeEvery); r.k.State().Plans["sent"].Steps[1].Phase != kernel.PDone && at < 10*int64(kernel.ProbeEvery); at += int64(kernel.ProbeEvery) {
		must(t, r.tick(at))
	}
	if n, open := r.k.State().StopLoss(); n != 1 || open {
		t.Fatalf("after the sent step reconciled done: %d, open %v; want 1, settled", n, open)
	}
	r.replays()

	// A retried step, sendable at the STOP, is parked again, not lost.
	r = newRig(t)
	at := r.park(r.ck)
	must(t, r.k.Retry(at+1, "p1", 0, r.phase("p1").Attempt))
	must(t, r.k.Stop(at+2))
	if ph := r.phase("p1").Phase; ph != kernel.PParked {
		t.Fatalf("the retried step after the STOP: %s, want parked", ph)
	}
	if n := r.k.State().StopCancelled; n != 0 {
		t.Fatalf("a retried step the STOP parks counts %d", n)
	}
	r.replays()
}

// A plan still pending at the STOP counts every step it had (mutgate on
// #5734). The kernel decides a plan at once, so the log is written as a
// forged one would be and replayed. Catches a pending plan left out, or
// read through its absent steps.
func TestStopCountsAPendingPlansSteps(t *testing.T) {
	r := newRig(t)
	pending, err := json.Marshal(r.sign(kernel.Plan{ID: "pending", Key: r.ck,
		Steps: []kernel.PlanStep{st(key.Trash, "m1"), st(key.Trash, "m2")}}))
	must(t, err)
	es := r.k.Log().Entries()
	l := es[len(es)-1]
	for _, e := range []struct{ typ, body string }{{kernel.TPlanSubmit, string(pending)}, {kernel.TStop, "{}"}} {
		l = kernel.Entry{Seq: l.Seq + 1, At: l.At, Type: e.typ, V: 1, Body: json.RawMessage(e.body)}
		es = append(es, l)
	}
	re, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if p := re.Plans["pending"]; p == nil || p.Status != kernel.SCancelled || re.StopCancelled != 2 {
		t.Fatalf("plan %+v, count %d; want it cancelled, 2", p, re.StopCancelled)
	}
}
