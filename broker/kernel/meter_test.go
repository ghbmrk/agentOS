package kernel_test

// REQ: LOG-7, KEY-2, LOG-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// modelKey issues a root for the model clerk and derives a capped child.
func modelKey(r *rig, serial string, c ...key.Caveat) key.Key {
	root := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: serial})
	must(r.t, r.k.Issue(0, root))
	k, err := key.Derive(root, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return k
}

// modelPlan submits an active plan citing k. Its model calls are charged to k
// with the plan as the task (LOG-7).
func modelPlan(r *rig, id string, k key.Key) {
	r.t.Helper()
	step := key.Step{Verb: key.Read, Clerk: "model", Args: map[string]key.Arg{"query": {Value: "q"}}}
	must(r.t, r.k.Submit(0, kernel.Plan{ID: id, Key: k, Steps: []key.Step{step}}))
	if r.status(id) != kernel.SActive {
		r.t.Fatalf("plan %s is %s", id, r.status(id))
	}
}

func TestMeteredUsageCountsAgainstTaskAndDayCaps(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(100), key.LimitSpendDay(150))
	for _, id := range []string{"t1", "t2", "t3"} {
		modelPlan(r, id, k)
	}
	if rf := r.k.AdmitSpend(1, "t1", "model", 60); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.Meter(1, "t1", "api", 60, "provider"))
	if rf := r.k.AdmitSpend(2, "t1", "model", 41); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("task cap: %v", rf)
	}
	if rf := r.k.AdmitSpend(2, "t2", "model", 91); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("day cap: %v", rf)
	}
	if rf := r.k.AdmitSpend(2, "t2", "model", 90); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.k.AdmitSpend(2, "t2", "mail", 1); rf == nil || rf.Code != key.RClerk {
		t.Fatalf("another clerk's call: %v", rf)
	}
	if rf := r.k.AdmitSpend(1+key.DayMS, "t3", "model", 100); rf != nil {
		t.Fatalf("rolling cap must free after a day: %v", rf)
	}
}

func TestUsageOverAnAdmissionIsStillRecorded(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	must(t, r.k.Meter(1, "t1", "api", 25, "clerk"))
	if rf := r.k.AdmitSpend(2, "t1", "model", 1); rf == nil {
		t.Fatal("recorded overrun must close the cap")
	}
	must(t, r.k.Cancel(3, "t1"))
	must(t, r.k.Meter(4, "t1", "api", 5, "admitted")) // spend that happened is recorded after the plan ended
}

// Spend never refunds: a negative amount is refused at both the check and the record.
func TestNegativeAmountsAreRefused(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	must(t, r.k.Meter(1, "t1", "api", 90, "provider"))
	n := len(r.k.Log().Entries())
	if r.k.Meter(2, "t1", "api", -90, "provider") == nil {
		t.Fatal("a refund must not be metered")
	}
	if len(r.k.Log().Entries()) != n {
		t.Fatal("a refused meter must leave no entry")
	}
	if rf := r.k.AdmitSpend(2, "t1", "model", -1); rf == nil || rf.Code != key.RMalformed {
		t.Fatalf("a negative admission: %v", rf)
	}
	if rf := r.k.AdmitSpend(2, "t1", "model", 11); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the 90 stays spent: %v", rf)
	}
}

// Step-count caps count steps, not metered usage, so a model call is no use.
func TestMeteredUsageDoesNotTripStepCaps(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitUses(1), key.LimitRate(1), key.LimitSpendDay(100)))
	must(t, r.k.Meter(1, "t1", "api", 5, "provider"))
	if rf := r.k.AdmitSpend(2, "t1", "model", 5); rf != nil {
		t.Fatalf("a model call is not a use: %v", rf)
	}
}

func TestSpendNeedsAnActivePlanOfAnIssuedKey(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendDay(100))
	modelPlan(r, "t1", k)
	if rf := r.k.AdmitSpend(1, "nope", "model", 1); rf == nil || rf.Code != kernel.CPlan {
		t.Fatalf("unknown plan: %v", rf)
	}
	if r.k.Meter(1, "nope", "api", 1, "clerk") == nil {
		t.Fatal("an unknown plan must not be metered")
	}
	must(t, r.k.Cancel(2, "t1"))
	if rf := r.k.AdmitSpend(3, "t1", "model", 1); rf == nil || rf.Code != kernel.CPlan {
		t.Fatalf("an ended plan spends nothing: %v", rf)
	}
	foreign := key.Issue(gen(9).priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	step := key.Step{Verb: key.Read, Clerk: "model", Args: map[string]key.Arg{"query": {Value: "q"}}}
	must(t, r.k.Submit(4, kernel.Plan{ID: "t2", Key: foreign, Steps: []key.Step{step}}))
	if rf := r.k.AdmitSpend(5, "t2", "model", 1); rf == nil {
		t.Fatal("a plan on a foreign root must not spend")
	}
	modelPlan(r, "t3", k)
	must(t, r.k.Stop(6))
	if rf := r.k.AdmitSpend(7, "t3", "model", 1); rf == nil || rf.Code != key.RStopped {
		t.Fatalf("stop: %v", rf)
	}
}

func TestMeteredUsageSurvivesReplay(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	must(t, r.k.Meter(1, "t1", "api", 70, "provider"))
	r.boot(2)
	if rf := r.k.AdmitSpend(3, "t1", "model", 31); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("replayed ledger lost the usage: %v", rf)
	}
}
