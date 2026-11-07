package kernel_test

// REQ: CH-3, KEY-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The kernel stamps each owner event with its rung and hands it to every
// check of a step (D-311): the event that opened the step's task, raised to
// P3 by a code approval of the step. A step whose key asks for more is
// refused at admission, in the kernel's dispatch and by the clerk, and a
// held step that only an approval could lift runs once the approval comes
// and is cancelled if its hold ends without one.
func TestOwnerEventRungMeetsTheKeysRung(t *testing.T) {
	r := newRig(t)
	for _, bad := range []key.Proof{key.PRecovery, 255} {
		if err := r.k.OpenTask(0, "bad", bad); err == nil {
			t.Fatalf("a task opened at %v", bad)
		}
	}
	must(t, r.k.OpenTask(0, "top", key.P4))
	must(t, r.k.OpenTask(0, "t1", key.P1))
	if got := r.k.State().Rung("t1", false); got != key.P1 {
		t.Fatalf("task rung %v, want P1", got)
	}
	if got := r.k.State().Rung("t1", true); got != key.P3 {
		t.Fatalf("a code approval raises to %v, want P3 (CH-10)", got)
	}

	r.plan("low", r.serve("t1", key.LimitRung(key.P1)), st(key.Trash, "m1"))
	r.plan("high", r.serve("t1", key.LimitRung(key.P3)), st(key.Trash, "m2"))
	if p := r.k.State().Plans["high"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("a P1 task's step under a P3 key: %s %s", p.Status, p.Reject)
	}
	must(t, r.tick(1))
	if r.status("low") != kernel.SDone {
		t.Fatalf("a P1 task's step under a P1 key: %s", r.status("low"))
	}

	held := r.serve("t1", key.LimitRung(key.P3), key.LimitHold(hour, hour))
	r.plan("approved", held, st(key.Unsubscribe, "list-a"))
	r.plan("lapsed", held, st(key.Unsubscribe, "list-b"))
	must(t, r.tick(2))
	for _, id := range []string{"approved", "lapsed"} {
		if ph := r.k.State().Plans[id].Steps[0].Phase; ph != kernel.PHeld {
			t.Fatalf("%s: %s, want held for an approval", id, ph)
		}
	}
	// The send-time check (Send, Retry, Rederive) reads the same rung: a
	// step only an approval lifts is refused there until the approval comes.
	for _, id := range []string{"approved", "lapsed"} {
		p := r.k.State().Plans[id]
		if rf := kernel.SendCheck(r.k.State(), p, &p.Steps[0], 0, 2); rf == nil || rf.Code != key.RRung {
			t.Fatalf("%s sent before its approval: %v", id, rf)
		}
	}
	checker := gen(40)
	r.k.PinChecker(checker.pub)
	must(t, r.k.ApproveCode(3, kernel.SignCode(checker.priv, r.codeSteps("approved"))))
	if p := r.k.State().Plans["approved"]; kernel.SendCheck(r.k.State(), p, &p.Steps[0], 0, 3) != nil {
		t.Fatal("the code-approved step is refused at send")
	}
	must(t, r.tick(4))
	if r.status("approved") != kernel.SDone {
		t.Fatalf("the code-approved step: %s", r.status("approved"))
	}
	must(t, r.tick(2+hour))
	if p := r.k.State().Plans["lapsed"]; p.Status != kernel.SCancelled || p.Cancel != key.RRung || p.Steps[0].Attempt != 0 {
		t.Fatalf("a hold that ended unapproved, refused before dispatch: %s %s, attempt %d", p.Status, p.Cancel, p.Steps[0].Attempt)
	}
	if n := len(r.mail.Effects()); n != 2 {
		t.Fatalf("%d effects, want the P1 step and the approved one", n)
	}
	r.replays()
}

// A step under no task reached P0; a task opened on the page at P3 runs a
// P3 key's reversible step with no further approval.
func TestNoTaskIsP0AndAPageTaskIsP3(t *testing.T) {
	r := newRig(t)
	r.plan("bare", r.derive(key.LimitRung(key.P1)), st(key.Trash, "m1"))
	if p := r.k.State().Plans["bare"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("no task under a P1 key: %s %s", p.Status, p.Reject)
	}
	must(t, r.k.OpenTask(0, "page", key.P3))
	r.plan("page", r.serve("page", key.LimitRung(key.P3)), st(key.Trash, "m2"))
	must(t, r.tick(1))
	if r.status("page") != kernel.SDone {
		t.Fatalf("a P3 task's step: %s", r.status("page"))
	}
}
