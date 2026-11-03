package kernel_test

// REQ: LOG-4, KRN-7, LOG-7

import (
	"crypto/ecdh"
	crand "crypto/rand"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// An erase cancels, in its own entry, every plan not yet ended that a reader
// of the subject submitted after its first read: a spend-held plan, whose
// Extend then releases nothing, and a plan with held steps still to run,
// which never dispatch. A plan the reader submitted before its read, and
// other lineages' plans (agent.x is not agent), run on. A replay folds the
// same state (LOG-4, D-169, KRN-7, #3870). Catches an erase that leaves a
// reader's plan live, matches a lineage without the "/" boundary, or cancels
// by a later entry a crash could lose.
func TestEraseCancelsTheReadersLaterPlans(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.OpenContent(kernel.NewMemKeys(), map[string]kernel.ContentStore{"mail": kernel.NewMemContent()}, 0); err != nil {
		t.Fatal(err)
	}
	sub, err := r.k.OpenSubject(0)
	must(t, err)
	h, err := r.k.Seal(0, sub, "mail", "message", []byte("lunch on Tuesday"))
	must(t, err)
	held := r.derive(key.LimitHold(hour, hour)) // irreversible steps wait an hour
	r.plan("agent/before", held, st(key.Unsubscribe, "m0"))
	if _, err := r.k.ReadFor(1, h, "agent"); err != nil {
		t.Fatal(err)
	}
	r.plan("agent/private/steps", held, st(key.Unsubscribe, "m2"), st(key.Unsubscribe, "m3"))
	r.plan("agent.x/r", held, st(key.Unsubscribe, "m4"))
	r.plan("other/r", held, st(key.Unsubscribe, "m5"))
	must(t, r.tick(2))
	if ph := r.k.State().Plans["agent/private/steps"].Steps[0].Phase; ph != kernel.PHeld {
		t.Fatalf("the reader's step is %s before the erase, want held", ph)
	}
	// After the tick: the rig has no model clerk, so a tick would cancel it.
	modelPlan(r, "agent/spend", modelKey(r, "m1", key.LimitSpendTask(100)))
	env := envelope(r, 500, 800)
	exhaust(r, "agent/spend", 100)
	n := len(r.k.Log().Entries())
	if _, err := r.k.Erase(3, sub); err != nil {
		t.Fatal(err)
	}
	if es := r.k.Log().Entries()[n:]; len(es) == 0 || es[0].Type != kernel.TSubjectErased {
		t.Fatal("the erase is not the next entry")
	}
	for id, want := range map[string]string{"agent/spend": kernel.SCancelled, "agent/private/steps": kernel.SCancelled,
		"agent/before": kernel.SActive, "agent.x/r": kernel.SActive, "other/r": kernel.SActive} {
		p := r.k.State().Plans[id]
		if p.Status != want || want == kernel.SCancelled && p.Cancel != kernel.CErased {
			t.Errorf("%s is %s (%q) after the erase, want %s", id, p.Status, p.Cancel, want)
		}
	}
	var rf *key.Refusal
	if err := r.k.Extend(4, extension(r, env, key.LimitSpendTask(300)), "agent/spend"); !errors.As(err, &rf) || rf.Code != kernel.CNotHeld {
		t.Fatalf("an extension of a cancelled plan: %v", err)
	}
	if a, rf := r.k.AdmitSpend(4, "agent/spend", 1); rf == nil {
		t.Fatalf("a cancelled plan admitted spend: %+v", a)
	}
	must(t, r.tick(3+2*hour))
	for i, s := range r.k.State().Plans["agent/private/steps"].Steps {
		if s.Phase != kernel.PCancelled && s.Phase != kernel.PQueued || s.DispatchSeq != 0 {
			t.Errorf("the reader's step %d ran after the erase: %+v", i, s)
		}
	}
	for _, id := range []string{"agent/before", "agent.x/r", "other/r"} {
		if got := r.status(id); got != kernel.SDone {
			t.Errorf("kept plan %s is %s, want done", id, got)
		}
	}
	r.replays()
}

// The cancel follows the log's order, not its clock: a plan submitted after
// the read under an earlier time is still cancelled, and the reader's plans
// from before its read are kept whatever their time (D-169).
func TestEraseCancelsByLogOrderNotClock(t *testing.T) {
	r := newRig(t)
	if _, err := r.k.OpenContent(kernel.NewMemKeys(), map[string]kernel.ContentStore{"mail": kernel.NewMemContent()}, 0); err != nil {
		t.Fatal(err)
	}
	sub, err := r.k.OpenSubject(0)
	must(t, err)
	h, err := r.k.Seal(0, sub, "mail", "message", []byte("x"))
	must(t, err)
	held := r.derive(key.LimitHold(hour, hour))
	must(t, r.k.Submit(50, r.sign(kernel.Plan{ID: "a/early", Key: held, Steps: []kernel.PlanStep{st(key.Unsubscribe, "m0")}})))
	if _, err := r.k.ReadFor(40, h, "a"); err != nil {
		t.Fatal(err)
	}
	must(t, r.k.Submit(10, r.sign(kernel.Plan{ID: "a/late", Key: held, Steps: []kernel.PlanStep{st(key.Unsubscribe, "m1")}})))
	if _, err := r.k.Erase(60, sub); err != nil {
		t.Fatal(err)
	}
	if r.status("a/early") != kernel.SActive || r.status("a/late") != kernel.SCancelled {
		t.Fatalf("early is %s, late is %s", r.status("a/early"), r.status("a/late"))
	}
	r.replays()
}

// Submit refuses a plan JSON cannot round-trip with JSON's own error, not
// ErrNotText, and logs nothing: an ES256 owner whose RP ID is 100 bytes that
// are not UTF-8 is written as 300 bytes of U+FFFD, past the 253 an RP ID may
// hold, so it does not read back (#4760). Catches Submit dropping or
// renaming asLogged's error.
func TestSubmitReturnsTheEncodingsError(t *testing.T) {
	r := newRig(t)
	ec, err := ecdh.P256().GenerateKey(crand.Reader)
	must(t, err)
	owner, err := key.ES256(strings.Repeat("\xff", 100), ec.PublicKey().Bytes())
	must(t, err)
	k := r.ck
	k.Root.Owner = owner
	n := len(r.k.Log().Entries())
	err = r.k.Submit(0, r.sign(kernel.Plan{ID: "p1", Key: k, Steps: []kernel.PlanStep{st(key.Unsubscribe, "m1")}}))
	if !errors.Is(err, key.ErrMalformed) || errors.Is(err, kernel.ErrNotText) || len(r.k.Log().Entries()) != n {
		t.Fatalf("a plan the log cannot hold: %v, %d entries", err, len(r.k.Log().Entries())-n)
	}
}
