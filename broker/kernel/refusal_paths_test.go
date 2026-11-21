package kernel_test

// REQ: KRN-5, KRN-8, KEY-4, LOG-7

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// onFailing reboots r on a copy of its log whose appends fail once the
// returned store says so.
func onFailing(r *rig, at int64) *failStore {
	r.t.Helper()
	fs := &failStore{MemStore: kernel.MemStore{B: append([]byte(nil), r.store.B...)}}
	l, err := kernel.Open(withStore(r, fs))
	must(r.t, err)
	r.k, err = kernel.Boot(l, r.anchors(), map[string]kernel.Clerk{"mail": r.mail}, at)
	must(r.t, err)
	return fs
}

// A plan whose key no longer verifies when its step comes up, here a bare
// root signed by a phone passkey cut off since, is cancelled for its key
// before anything runs, and the check Rederive repeats says the same (#6023).
func TestAStepWhoseKeyNoLongerVerifiesIsCancelled(t *testing.T) {
	r := newRig(t)
	phone := gen(8)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	root := trashRoot(r, "ph", phone)
	must(t, r.issue(0, root))
	at := kernel.GrantHold + 1
	must(t, r.k.Submit(at, kernel.SignPlan(kernel.Plan{ID: "p1", Key: root, Steps: []kernel.PlanStep{st(key.Trash, "m1")}}, phone.priv)))
	if r.status("p1") != kernel.SActive {
		t.Fatalf("the phone's plan is %s", r.status("p1"))
	}
	must(t, r.k.Unenroll(at+1, key.Unenroll(r.owner.pass, phone.pk)))
	s := r.k.State()
	if rf := kernel.SendCheck(s, s.Plans["p1"], &s.Plans["p1"].Steps[0], 0, at+2); rf == nil || rf.Code() != kernel.CKey {
		t.Fatalf("the send check after the cut-off: %v", rf)
	}
	must(t, r.tick(at+2))
	if p := r.k.State().Plans["p1"]; p.Status != kernel.SCancelled || p.Cancel != kernel.CKey || len(r.mail.Effects()) != 0 {
		t.Fatalf("a plan whose key no longer verifies: %s %s, %d effects", p.Status, p.Cancel, len(r.mail.Effects()))
	}
}

// Two plans with the same irreversible effect, both admitted before either
// runs: the first runs, and the second is cancelled as its duplicate when
// its step comes up (KRN-8).
func TestASecondPlanWithTheSameEffectIsCancelledAsADuplicate(t *testing.T) {
	r := newRig(t)
	r.plan("a", r.ck, st(key.Unsubscribe, "list-a"))
	r.plan("b", r.ck, st(key.Unsubscribe, "list-a"))
	must(t, r.tick(1))
	if p := r.k.State().Plans["b"]; r.status("a") != kernel.SDone || p.Status != kernel.SCancelled || p.Cancel != kernel.CDuplicate || len(r.mail.Effects()) != 1 {
		t.Fatalf("a %s; b %s %s; %d effects", r.status("a"), p.Status, p.Cancel, len(r.mail.Effects()))
	}
}

// A log that cannot take the entry a spend or a pool admission writes
// refuses it as broken, naming the failure, and then refuses every
// admission as broken, before it reads the plan (KRN-5, LOG-7).
func TestAnAdmissionTheLogCannotRecordIsRefused(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	must(t, r.k.Reserve(1, "codex-5h", 100))
	must(t, read(r, 2, "codex-5h", 900, 10_000))
	fs := onFailing(r, 3)
	fs.appendErr = true
	if rf := r.k.AdmitPool(10_000, "codex-5h"); rf == nil || rf.Code() != kernel.CPool || rf.Detail != "codex-5h: disk full" {
		t.Fatalf("a pool reset the log could not take: %v", rf)
	}
	fs = onFailing(r, 3)
	fs.appendErr = true
	if _, rf := r.k.AdmitSpend(3, "t1", 1); rf == nil || rf.Code() != kernel.CBroken || rf.Detail != "disk full" {
		t.Fatalf("a spend the log could not take: %v", rf)
	}
	if _, rf := r.k.AdmitSpend(4, "no-such-plan", 1); rf == nil || rf.Code() != kernel.CBroken || rf.Detail != kernel.ErrBroken.Error() {
		t.Fatalf("a spend on the broken log: %v", rf)
	}
}

// An extension whose chain carries no per-task cap is refused, though its
// grant is live and its root is not the held key's (KEY-4).
func TestAnExtensionWithNoPerTaskCapIsRefused(t *testing.T) {
	r := newRig(t)
	uncapped := modelKey(r, "m2")
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	exhaust(r, "t1", 10)
	if err := r.k.Extend(3, uncapped, "t1"); err == nil || err.Error() != "extension: no per-task cap" {
		t.Fatalf("an uncapped extension: %v", err)
	}
}
