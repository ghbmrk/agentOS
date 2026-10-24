package kernel_test

// REQ: LOG-7, KEY-2, LOG-1

import (
	"errors"
	"math"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// modelKey issues a root for the model clerk and derives a capped child.
func modelKey(r *rig, serial string, c ...key.Caveat) key.Key {
	ck := r.grant(key.Issue(r.owner.priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: serial}), 1<<40)
	if len(c) == 0 {
		return ck
	}
	k, err := key.Derive(ck, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return k
}

// modelPlan submits an active plan citing k. Its model calls are charged to k
// with the plan as the task (LOG-7).
func modelPlan(r *rig, id string, k key.Key) {
	r.t.Helper()
	step := kernel.PlanStep{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}
	must(r.t, r.k.Submit(0, r.sign(kernel.Plan{ID: id, Key: k, Steps: []kernel.PlanStep{step}})))
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
	if rf := r.admit(1, "t1", 60); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.meter(1, "t1", "api", 60, "provider"))
	if rf := r.admit(2, "t1", 41); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("task cap: %v", rf)
	}
	if rf := r.admit(2, "t2", 91); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("day cap: %v", rf)
	}
	if rf := r.admit(2, "t2", 90); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.admit(1+key.DayMS, "t3", 100); rf != nil {
		t.Fatalf("rolling cap must free after a day: %v", rf)
	}
}

func TestUsageOverAnAdmissionIsStillRecorded(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	a, rf := r.k.AdmitSpend(1, "t1", 5)
	b, rf2 := r.k.AdmitSpend(1, "t1", 5)
	if rf != nil || rf2 != nil {
		t.Fatal(rf, rf2)
	}
	must(t, r.k.Meter(1, a, "api", 25, "clerk"))
	if rf := r.admit(2, "t1", 1); rf == nil {
		t.Fatal("recorded overrun must close the cap")
	}
	must(t, r.k.Cancel(3, "t1"))
	must(t, r.k.Meter(4, b, "api", 5, "admitted")) // spend that happened is recorded after the plan ended
}

// A sum past int64 exceeds every cap, so usage near MaxInt64, metered or
// asked for, never wraps the window's sum back under one (Defect: KEY).
func TestSpendThatOverflowsIsRefused(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	must(t, r.meter(1, "t1", "api", 1, "provider"))
	if rf := r.admit(2, "t1", math.MaxInt64); !spendRefused(rf) {
		t.Fatalf("MaxInt64 after 1 spent: %v", rf)
	}
	modelPlan(r, "t2", modelKey(r, "m2", key.LimitSpendTask(100)))
	must(t, r.meter(3, "t2", "api", math.MaxInt64, "provider"))
	if rf := r.admit(4, "t2", 1); !spendRefused(rf) {
		t.Fatalf("1 after MaxInt64 metered: %v", rf)
	}
	r.replays()
}

func spendRefused(rf *key.Refusal) bool {
	return rf != nil && (rf.Code == key.RSpendTask || rf.Code == key.RSpendDay)
}

// Spend never refunds: a negative amount is refused at both the check and the record.
func TestNegativeAmountsAreRefused(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	must(t, r.meter(1, "t1", "api", 90, "provider"))
	a, rf := r.k.AdmitSpend(2, "t1", 0)
	if rf != nil {
		t.Fatal(rf)
	}
	n := len(r.k.Log().Entries())
	if r.k.Meter(2, a, "api", -90, "provider") == nil {
		t.Fatal("a refund must not be metered")
	}
	if len(r.k.Log().Entries()) != n {
		t.Fatal("a refused meter must leave no entry")
	}
	if rf := r.admit(2, "t1", -1); rf == nil || rf.Code != key.RMalformed {
		t.Fatalf("a negative admission: %v", rf)
	}
	if rf := r.admit(2, "t1", 11); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the 90 stays spent: %v", rf)
	}
}

// Step-count caps count steps, not metered usage, so a model call is no use.
func TestMeteredUsageDoesNotTripStepCaps(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitUses(1), key.LimitRate(1), key.LimitSpendDay(100)))
	must(t, r.meter(1, "t1", "api", 5, "provider"))
	if rf := r.admit(2, "t1", 5); rf != nil {
		t.Fatalf("a model call is not a use: %v", rf)
	}
}

func TestSpendNeedsAnActivePlanOfAnIssuedKey(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendDay(100))
	modelPlan(r, "t1", k)
	if rf := r.admit(1, "nope", 1); rf == nil || rf.Code != kernel.CPlan {
		t.Fatalf("unknown plan: %v", rf)
	}
	if r.meter(1, "nope", "api", 1, "clerk") == nil {
		t.Fatal("an unknown plan must not be metered")
	}
	must(t, r.k.Cancel(2, "t1"))
	if rf := r.admit(3, "t1", 1); rf == nil || rf.Code != kernel.CPlan {
		t.Fatalf("an ended plan spends nothing: %v", rf)
	}
	foreign := key.Issue(gen(9).priv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	step := kernel.PlanStep{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}
	must(t, r.k.Submit(4, r.sign(kernel.Plan{ID: "t2", Key: foreign, Steps: []kernel.PlanStep{step}})))
	if rf := r.admit(5, "t2", 1); rf == nil {
		t.Fatal("a plan on a foreign root must not spend")
	}
	modelPlan(r, "t3", k)
	must(t, r.k.Stop(6))
	if rf := r.admit(7, "t3", 1); rf == nil || rf.Code != key.RStopped {
		t.Fatalf("stop: %v", rf)
	}
}

func TestMeteredUsageSurvivesReplay(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	must(t, r.meter(1, "t1", "api", 70, "provider"))
	r.boot(2)
	if rf := r.admit(3, "t1", 31); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("replayed ledger lost the usage: %v", rf)
	}
}

// Spend is authorized by the funding key's spend caveat, not by the clerk the
// key was issued for: a plan under a mail key makes a capped model call, and a
// key with no spend cap funds nothing.
func TestSpendFollowsTheFundingKeysCaveatWhateverItsClerk(t *testing.T) {
	r := newRig(t)
	step := kernel.PlanStep{Verb: key.Trash, Clerk: "mail", Args: map[string]string{"target": "m1"}}
	must(t, r.k.Submit(0, r.sign(kernel.Plan{ID: "capped", Key: r.derive(key.LimitSpendTask(100)), Steps: []kernel.PlanStep{step}})))
	// Every key off the root has a daily cap (D-146); only the passkey's own
	// one-off under the bare root has none.
	must(t, r.k.Submit(0, kernel.SignPlan(kernel.Plan{ID: "bare", Key: key.Key{Root: r.ck.Root}, Steps: []kernel.PlanStep{step}}, r.owner.priv)))
	if r.status("capped") != kernel.SActive || r.status("bare") != kernel.SActive {
		t.Fatalf("plans: %s %s", r.status("capped"), r.status("bare"))
	}
	if rf := r.admit(1, "capped", 100); rf != nil {
		t.Fatalf("a mail key's spend cap funds a model call: %v", rf)
	}
	if rf := r.admit(1, "capped", 101); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("its cap holds: %v", rf)
	}
	if rf := r.admit(1, "bare", 1); rf == nil || rf.Code != key.RMalformed {
		t.Fatalf("a key with no spend cap funds nothing: %v", rf)
	}
}

// admit is AdmitSpend as a check alone: an admission it makes is settled at
// once with no usage, so it reserves nothing.
func (r *rig) admit(at int64, plan string, amount int64) *key.Refusal {
	r.t.Helper()
	a, rf := r.k.AdmitSpend(at, plan, amount)
	if rf == nil {
		must(r.t, r.k.Meter(at, a, "api", 0, "clerk"))
	}
	return rf
}

// meter records usage of a call admitted at at with no worst case.
func (r *rig) meter(at int64, plan, route string, amount int64, source string) error {
	r.t.Helper()
	a, rf := r.k.AdmitSpend(at, plan, 0)
	if rf != nil {
		return rf
	}
	return r.k.Meter(at, a, route, amount, source)
}

// Calls admitted at once each reserve their worst case, so together they
// never pass a cap, and one refused only for calls in flight is "in-flight",
// which holds nothing; Meter settles a reservation at what was used, once, and
// one never settled stays charged at its worst case, across a restart
// (LOG-7, #2613 item 1).
func TestAdmissionsReserveTheirWorstCase(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(100))
	modelPlan(r, "t1", k)
	modelPlan(r, "t2", k)
	a, rf := r.k.AdmitSpend(1, "t1", 60)
	if rf != nil {
		t.Fatal(rf)
	}
	if _, rf := r.k.AdmitSpend(1, "t1", 41); rf == nil || rf.Code != kernel.CInFlight {
		t.Fatalf("a second call shared the first one's budget: %v", rf)
	}
	if _, rf := r.k.AdmitSpend(1, "t1", 101); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("a call that cannot fit once the first settles: %v", rf)
	}
	day := modelKey(r, "m2", key.LimitSpendDay(100))
	modelPlan(r, "d1", day)
	modelPlan(r, "d2", day)
	if _, rf := r.k.AdmitSpend(1, "d1", 60); rf != nil {
		t.Fatal(rf)
	}
	if _, rf := r.k.AdmitSpend(1, "d2", 41); rf == nil || rf.Code != kernel.CInFlight {
		t.Fatalf("another plan's call shared the day's budget: %v", rf)
	}
	must(t, r.k.Meter(2, a, "api", 20, "provider"))
	if err := r.k.Meter(2, a, "api", 20, "provider"); !errors.Is(err, kernel.ErrNotAdmitted) {
		t.Fatalf("an admission settled twice: %v", err)
	}
	b, rf := r.k.AdmitSpend(3, "t1", 80)
	if rf != nil {
		t.Fatalf("the settled call still holds its worst case: %v", rf)
	}
	c, rf := r.k.AdmitSpend(3, "t2", 10)
	if rf != nil {
		t.Fatal(rf)
	}
	if err := r.k.Meter(3, kernel.Admitted{Plan: "t1", Seq: c.Seq}, "api", 1, "clerk"); !errors.Is(err, kernel.ErrNotAdmitted) {
		t.Fatalf("one plan's admission settled under another: %v", err)
	}
	r.boot(4)
	if _, rf := r.k.AdmitSpend(4, "t1", 1); rf == nil || rf.Code != kernel.CInFlight {
		t.Fatalf("an unsettled admission was lost at restart: %v", rf)
	}
	must(t, r.k.Meter(5, b, "api", 0, "clerk"))
	if _, rf := r.k.AdmitSpend(5, "t1", 80); rf != nil {
		t.Fatalf("after settling: %v", rf)
	}
	r.replays()
}

// A settlement charges the key the call was admitted under, from its
// reservation, not the one funding the plan when it settles: an extension
// granted mid-call carries none of the call admitted before it (LOG-7, #2613
// item 1).
func TestASettlementChargesTheKeyItWasAdmittedUnder(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(100))
	modelPlan(r, "t1", k)
	env := envelope(r, 500, 800)
	a, rf := r.k.AdmitSpend(1, "t1", 40)
	if rf != nil {
		t.Fatal(rf)
	}
	must(t, r.meter(1, "t1", "api", 60, "provider"))
	rf = r.admit(2, "t1", 50)
	if rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the cap is used up: %v", rf)
	}
	must(t, r.k.Hold(2, "t1", rf))
	ext := extension(r, env, key.LimitSpendTask(300))
	must(t, r.k.Extend(3, ext, "t1"))
	must(t, r.k.Meter(4, a, "api", 40, "provider"))
	if n := sum(r.k.State().Ledger().Uses(k.Tip())); n != 100 {
		t.Fatalf("the admitted key carries %d, want 100", n)
	}
	if rf := r.admit(5, "t1", 300); rf != nil {
		t.Fatalf("the extension's whole cap is left: %v", rf)
	}
}

// When open admissions push one cap over and settled usage alone exhausts
// another, the refusal names the exhausted one, which a hold then names
// (LOG-7).
func TestARefusalNamesTheCapSettledUsageExhausts(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(100), key.LimitSpendDay(100))
	modelPlan(r, "t1", k)
	modelPlan(r, "t2", k)
	must(t, r.meter(1, "t2", "api", 50, "provider"))
	if _, rf := r.k.AdmitSpend(1, "t1", 40); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.admit(1, "t1", 70); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("refused %v, want the day cap", rf)
	}
}

func sum(us []key.Use) (n int64) {
	for _, u := range us {
		n += u.Amount
	}
	return n
}
