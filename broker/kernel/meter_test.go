package kernel_test

// REQ: LOG-7, KEY-2, LOG-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// modelKey issues a root for the model clerk and derives a capped child.
func modelKey(r *rig, c ...key.Caveat) key.Key {
	root := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m1"})
	must(r.t, r.k.Issue(0, root))
	k, err := key.Derive(root, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return k
}

func TestMeteredUsageCountsAgainstTaskAndDayCaps(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(100), key.LimitSpendDay(150))
	if rf := r.k.AdmitSpend(1, k, "model", "t1", 60); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.Meter(1, k, "t1", "api", 60, "provider"))
	if rf := r.k.AdmitSpend(2, k, "model", "t1", 41); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("task cap: %v", rf)
	}
	if rf := r.k.AdmitSpend(2, k, "model", "t2", 91); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("day cap: %v", rf)
	}
	if rf := r.k.AdmitSpend(2, k, "model", "t2", 90); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.k.AdmitSpend(2, k, "mail", "t2", 1); rf == nil || rf.Code != key.RClerk {
		t.Fatalf("another clerk's call: %v", rf)
	}
	if rf := r.k.AdmitSpend(1+key.DayMS, k, "model", "t3", 100); rf != nil {
		t.Fatalf("rolling cap must free after a day: %v", rf)
	}
}

func TestUsageOverAnAdmissionIsStillRecorded(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(10))
	must(t, r.k.Meter(1, k, "t1", "api", 25, "clerk"))
	if rf := r.k.AdmitSpend(2, k, "model", "t1", 1); rf == nil {
		t.Fatal("recorded overrun must close the cap")
	}
}

func TestMeteredUsageDoesNotCountAsUses(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitUses(1), key.LimitRate(1), key.LimitSpendDay(100))
	must(t, r.k.Meter(1, k, "t1", "api", 5, "provider"))
	if rf := r.k.AdmitSpend(2, k, "model", "t1", 5); rf != nil {
		t.Fatalf("a model call is not a use: %v", rf)
	}
}

func TestMeterRefusesUnknownRootAndStop(t *testing.T) {
	r := newRig(t)
	other := key.Issue(gen(9).priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	if r.k.Meter(1, other, "t", "api", 1, "clerk") == nil {
		t.Fatal("foreign root must not be metered")
	}
	k := modelKey(r, key.LimitSpendDay(100))
	must(t, r.k.Stop(2))
	if rf := r.k.AdmitSpend(3, k, "model", "t", 1); rf == nil || rf.Code != key.RStopped {
		t.Fatalf("stop: %v", rf)
	}
}

func TestMeteredUsageSurvivesReplay(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(100))
	must(t, r.k.Meter(1, k, "t1", "api", 70, "provider"))
	r.boot(2)
	if rf := r.k.AdmitSpend(3, k, "model", "t1", 31); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("replayed ledger lost the usage: %v", rf)
	}
}
