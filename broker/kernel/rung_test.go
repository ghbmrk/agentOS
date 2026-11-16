package kernel_test

// REQ: CH-3, KEY-2

import (
	"errors"
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
	if got := r.k.State().Rung("t1", key.Key{}, false); got != key.P1 {
		t.Fatalf("task rung %v, want P1", got)
	}
	if got := r.k.State().Rung("t1", key.Key{}, true); got != key.P3 {
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

// A held step waits for its approval until Earliest reaches the hold's end:
// a wide reading does not cut the wait short and cancel it (TIM-1, CH-3).
// REQ: TIM-1, CH-3
func TestTIM1AHeldStepWaitsForItsApprovalUntilEarliest(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", key.P1))
	r.plan("lapsed", r.serve("t1", key.LimitRung(key.P3), key.LimitHold(hour, hour)), st(key.Unsubscribe, "list-b"))
	must(t, r.tick(2))
	wide(r, 2+hour-1)
	must(t, r.tick(0))
	if p := r.k.State().Plans["lapsed"]; p.Status != kernel.SActive || p.Steps[0].Phase != kernel.PHeld {
		t.Fatalf("a hold not yet over by Earliest: %s %s, want held for an approval", p.Status, p.Steps[0].Phase)
	}
}

// standing issues a mail root and its clerk key as standing keys stamped at
// rung, the clerk key asking for P3 (KEY-5's first-approval key), a hold
// before the test so both are live.
func (r *rig) standing(serial string, rung key.Proof) (key.Key, error) {
	r.t.Helper()
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: serial})
	ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40, key.LimitRung(key.P3))
	must(r.t, err)
	return ck, r.k.IssueStanding(-kernel.GrantHold, rung, approve([]key.Key{root, ck}, r.owner, r.spare), root, ck)
}

// A step under a standing key is checked at the rung of the owner event that
// derived the key, recorded on its grant, not P0 (KEY-2 rung clause, KEY-5,
// D-311): with no task, and in a run's task the kernel opens at P0. The same
// key issued as an ordinary grant carries no such rung, and a stamp no
// signature behind the key reaches is refused.
func TestStandingKeyStepRunsAtItsDerivingRung(t *testing.T) {
	r := newRig(t)
	sk, err := r.standing("s1", key.P3)
	must(t, err)
	root := key.Issue(r.owner.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "o1"})
	plain, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 1<<40, key.LimitRung(key.P3))
	must(t, err)
	must(t, r.issue(-kernel.GrantHold, root, plain))
	if got := r.k.State().Rung("", sk, false); got != key.P3 {
		t.Fatalf("a standing key's step at %v, want its deriving P3", got)
	}
	r.plan("later", sk, st(key.Trash, "m1"))
	must(t, r.k.OpenTask(0, "run", key.P0))
	run, err := key.Derive(sk, r.holder.priv, r.holder.pub, key.LimitTask("run"))
	must(t, err)
	r.plan("run", run, st(key.Trash, "m2"))

	r.plan("plain", plain, st(key.Trash, "m3"))
	if p := r.k.State().Plans["plain"]; p.Status != kernel.SRejected || p.Reject != key.RRung {
		t.Fatalf("an ordinary grant's step under a P3 key: %s %s", p.Status, p.Reject)
	}
	must(t, r.tick(1))
	for _, id := range []string{"later", "run"} {
		if r.status(id) != kernel.SDone {
			t.Fatalf("%s under the standing key: %s %s", id, r.status(id), r.k.State().Plans[id].Reject)
		}
	}
	// A renewal of a live grant keeps its stamp: it never raises one.
	if err := r.k.IssueStanding(2, key.P3, approve([]key.Key{root, plain}, r.owner, r.spare), root, plain); err != nil {
		t.Fatal(err)
	}
	if got := r.k.State().Rung("", plain, false); got != key.P0 {
		t.Fatalf("a re-issue stamped an ordinary grant %v", got)
	}

	for _, bad := range []key.Proof{key.PRecovery, 255} {
		if _, err := r.standing("bad", bad); !errors.Is(err, kernel.ErrStandingRung) {
			t.Fatalf("a standing key stamped %v: %v", bad, err)
		}
	}
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	proot := key.Issue(phone.pass, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "p1"})
	if err := r.k.IssueStanding(3, key.P4, approve([]key.Key{proot}, r.owner, r.spare), proot); !errors.Is(err, kernel.ErrStandingRung) {
		t.Fatalf("a phone passkey's root stamped P4: %v", err)
	}
	r.replays()
}

// A metered call is checked at its plan's rung (LOG-7, CH-3): a P3-rung key
// funds no call for a task opened at P1, though its held step was admitted
// on the code approval it waits for, and funds one for a task opened at P3.
func TestSpendRefusesBelowTheKeyRung(t *testing.T) {
	r := newRig(t)
	must(t, r.k.OpenTask(0, "t1", key.P1))
	must(t, r.k.OpenTask(0, "t3", key.P3))
	c := []key.Caveat{key.LimitRung(key.P3), key.LimitHold(hour, hour), key.LimitSpendTask(100)}
	r.plan("low", r.serve("t1", c...), st(key.Unsubscribe, "list-a"))
	r.plan("high", r.serve("t3", c...), st(key.Unsubscribe, "list-b"))
	if r.status("low") != kernel.SActive {
		t.Fatalf("the held step's plan: %s", r.status("low"))
	}
	if rf := r.admit(1, "low", 1); rf == nil || rf.Code != key.RRung {
		t.Fatalf("a P1 task's metered call under a P3 key: %v", rf)
	}
	if rf := r.admit(1, "high", 1); rf != nil {
		t.Fatalf("a P3 task's metered call: %v", rf)
	}
	r.replays()
}
