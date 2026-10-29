package kernel_test

// REQ: CH-4, KRN-2, KEY-4, VRB-1

import (
	"errors"
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// held submits one plan per step under k and ticks once, so each step waits
// in its hold window.
func (r *rig) held(k key.Key, steps map[string]kernel.PlanStep) {
	r.t.Helper()
	for id, s := range steps {
		r.plan(id, k, s)
	}
	must(r.t, r.tick(0))
	for id := range steps {
		if ph := r.k.State().Plans[id].Steps[0].Phase; ph != kernel.PHeld {
			r.t.Fatalf("%s is %s, want held", id, ph)
		}
	}
}

func (r *rig) codeSteps(ids ...string) []kernel.CodeStep {
	var out []kernel.CodeStep
	for _, id := range ids {
		out = append(out, kernel.CodeStepOf(r.k.State().Plans[id].Plan, 0))
	}
	return out
}

// An approval the checker signed on a verified code releases exactly the
// held steps it names, at once and once: a step it does not name still
// waits its window, and a replay, a signature by any other key, or an
// approval over another plan's bytes releases nothing (CH-4, CH-10, KEY-8).
func TestCodeApprovalAdmitsOnlyItsExactSteps(t *testing.T) {
	r := newRig(t)
	checker, other := gen(40), gen(41)
	r.held(r.derive(key.LimitHold(hour, hour)), map[string]kernel.PlanStep{
		"p1": st(key.Unsubscribe, "list-a"), "p2": st(key.Unsubscribe, "list-b")})
	one := r.codeSteps("p1")

	if err := r.k.ApproveCode(10, kernel.SignCode(checker.priv, one)); !errors.Is(err, kernel.ErrNoChecker) {
		t.Fatalf("an approval with no checker pinned: %v", err)
	}
	r.k.PinChecker(checker.pub)
	if err := r.k.ApproveCode(10, kernel.SignCode(other.priv, one)); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("an approval signed by another key: %v", err)
	}
	forged := kernel.SignCode(other.priv, one)
	forged.By = checker.pub
	if err := r.k.ApproveCode(10, forged); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("another key's signature under the checker's name: %v", err)
	}
	swapped := r.codeSteps("p1")
	swapped[0].Hash = r.codeSteps("p2")[0].Hash
	if err := r.k.ApproveCode(10, kernel.SignCode(checker.priv, swapped)); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("an approval over another plan's bytes: %v", err)
	}
	must(t, r.tick(20))
	if len(r.mail.Effects()) != 0 {
		t.Fatal("a refused approval released a step")
	}

	a := kernel.SignCode(checker.priv, one)
	must(t, r.k.ApproveCode(30, a))
	must(t, r.tick(40))
	if got := r.mail.Effects(); len(got) != 1 || r.status("p1") != kernel.SDone || r.status("p2") != kernel.SActive {
		t.Fatalf("the approved step runs at once and the other waits: effects %v, p2 %s", got, r.status("p2"))
	}
	if err := r.k.ApproveCode(50, a); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("a replayed approval: %v", err)
	}
	dup := r.codeSteps("p2", "p2")
	if err := r.k.ApproveCode(50, kernel.SignCode(checker.priv, dup)); !errors.Is(err, kernel.ErrCodeApproval) {
		t.Fatalf("an approval naming one step twice: %v", err)
	}
	must(t, r.tick(hour-1))
	if len(r.mail.Effects()) != 1 {
		t.Fatal("a step no approval named ran inside its window")
	}
	must(t, r.tick(hour))
	if len(r.mail.Effects()) != 2 {
		t.Fatal("the unnamed step did not run after its window")
	}

	re, err := kernel.Replay(r.anchors(), r.k.Log().Entries())
	must(t, err)
	if !reflect.DeepEqual(re, r.k.State()) {
		t.Fatal("replay differs from the live state (KRN-1)")
	}
	if _, err := kernel.Rederive(r.anchors(), r.head.pub, r.k.Log().Entries()); err != nil {
		t.Fatalf("rederive: %v", err)
	}
}

// A code approval never covers a reveal-or-create-secret step, alone or in
// a batch: VRB-1 steps keep their own approval. A batch naming one releases
// none of its steps; the same approval without it is the positive control.
func TestCodeApprovalNeverCoversASecretStep(t *testing.T) {
	r := newRig(t)
	checker := gen(40)
	r.k.PinChecker(checker.pub)
	ck := r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "mail",
		Verbs: []key.Verb{key.Unsubscribe, key.RevealOrCreateSecret}, Serial: "s1"}), 1<<40)
	k, err := key.Derive(ck, r.holder.priv, r.holder.pub, key.LimitHold(hour, hour))
	must(t, err)
	r.held(k, map[string]kernel.PlanStep{"secret": st(key.RevealOrCreateSecret, "acct"), "p2": st(key.Unsubscribe, "list-a")})

	for name, ids := range map[string][]string{"alone": {"secret"}, "in a batch": {"p2", "secret"}} {
		if err := r.k.ApproveCode(10, kernel.SignCode(checker.priv, r.codeSteps(ids...))); !errors.Is(err, kernel.ErrCodeApproval) {
			t.Fatalf("a secret step %s: %v", name, err)
		}
	}
	must(t, r.tick(20))
	if len(r.mail.Effects()) != 0 || r.k.State().Plans["secret"].Steps[0].Phase != kernel.PHeld {
		t.Fatal("an approval naming a secret step released a step")
	}
	must(t, r.k.ApproveCode(30, kernel.SignCode(checker.priv, r.codeSteps("p2"))))
	must(t, r.tick(40))
	if len(r.mail.Effects()) != 1 || r.status("p2") != kernel.SDone {
		t.Fatal("the same approval without the secret step must release it")
	}
	if r.k.State().Plans["secret"].Steps[0].Phase != kernel.PHeld {
		t.Fatal("the secret step left its hold")
	}
}
