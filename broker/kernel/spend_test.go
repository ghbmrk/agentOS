package kernel_test

// REQ: LOG-7, RES-5, KEY-3, KEY-4, KEY-6, KRN-7, LOG-1

import (
	"errors"
	"math"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// envelope issues the owner's spend envelope: a model-clerk root whose first
// link sets the per-task and per-day extension ceilings (LOG-7, KEY-4).
func envelope(r *rig, task, day int64) key.Key {
	return r.grant(key.Issue(r.owner.pass, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "env"}), day,
		key.LimitSpendTask(task))
}

func extension(r *rig, env key.Key, c ...key.Caveat) key.Key {
	ext, err := key.Derive(env, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return ext
}

// exhaust spends a plan to its task cap and holds it.
func exhaust(r *rig, plan string, cap int64) {
	must(r.t, r.meter(1, plan, "api", cap, "provider"))
	rf := r.admit(2, plan, 1)
	if rf == nil {
		r.t.Fatal("plan should be exhausted")
	}
	must(r.t, r.k.Hold(2, plan, rf))
}

func TestExhaustedPlanIsHeldUntilExtended(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 100)
	h, ok := r.k.State().SpendHeld["t1"]
	if !ok || h.Code != key.RSpendTask {
		t.Fatalf("plan not held: %+v", h)
	}
	if rf := r.admit(2, "t1", 1); rf == nil || rf.Code != kernel.CHeld {
		t.Fatalf("a held plan admits nothing: %v", rf)
	}
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(300)), "t1"))
	if _, ok := r.k.State().SpendHeld["t1"]; ok {
		t.Fatal("extension must release the hold")
	}
	if rf := r.admit(4, "t1", 300); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.admit(4, "t1", 301); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("extension cap: %v", rf)
	}
}

// The task is the plan: a plan has no other name to spend under, and a second
// plan on the same key has its own task cap but the same day cap.
func TestTaskIsThePlanNotAString(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10), key.LimitSpendDay(15))
	modelPlan(r, "p1", k)
	modelPlan(r, "p2", k)
	exhaust(r, "p1", 10)
	if rf := r.admit(3, "p1", 1); rf == nil {
		t.Fatal("a held plan stays held")
	}
	if rf := r.admit(3, "p2", 5); rf != nil {
		t.Fatalf("another plan has its own task cap: %v", rf)
	}
	if rf := r.admit(3, "p2", 6); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("the day cap is the key's: %v", rf)
	}
}

func TestExtensionsShareTheEnvelopeCeilings(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	for _, id := range []string{"t1", "t2", "t3"} {
		modelPlan(r, id, k)
	}
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(300)), "t1"))
	must(t, r.meter(4, "t1", "api", 300, "provider"))
	rf := r.admit(5, "t1", 1)
	if rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the extension is used up: %v", rf)
	}
	must(t, r.k.Hold(5, "t1", rf))
	// a distinct key: equal caveats derive the same key
	must(t, r.k.Extend(6, extension(r, env, key.LimitSpendTask(350)), "t1"))
	if rf := r.admit(7, "t1", 201); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("two extensions must not pass the per-task ceiling: %v", rf)
	}
	if rf := r.admit(7, "t1", 200); rf != nil {
		t.Fatal(rf)
	}
	exhaust(r, "t2", 10)
	must(t, r.k.Extend(8, extension(r, env, key.LimitSpendTask(360)), "t2"))
	must(t, r.meter(9, "t2", "api", 300, "provider"))
	exhaust(r, "t3", 10)
	must(t, r.k.Extend(10, extension(r, env, key.LimitSpendTask(400)), "t3"))
	if rf := r.admit(11, "t3", 201); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("extensions must not pass the per-day ceiling: %v", rf)
	}
}

func TestExtendRefusals(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", k)
	env := envelope(r, 500, 800)
	if err := r.k.Extend(1, extension(r, env, key.LimitSpendTask(5)), "t1"); err == nil {
		t.Fatal("a plan that is not held cannot be extended")
	}
	exhaust(r, "t1", 10)
	if err := r.k.Extend(3, k, "t1"); err == nil {
		t.Fatal("the exhausted key is not its own extension")
	}
	// a held key cannot release itself, however it is narrowed again
	cited, err := key.Derive(k, r.holder.priv, r.holder.pub, key.LimitSpendTask(5))
	must(t, err)
	if err := r.k.Extend(3, cited, "t1"); err == nil {
		t.Fatal("an extension under the held key's own root releases itself")
	}
	if err := r.k.Extend(3, modelKey(r, "m2", key.LimitSpendDay(5)), "t1"); err == nil {
		t.Fatal("an extension with no per-task cap anywhere in its chain is unbounded")
	}
	other := key.Issue(gen(9).pass, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	if err := r.k.Extend(3, other, "t1"); err == nil {
		t.Fatal("a foreign envelope cannot extend")
	}
	unissued := key.Issue(r.owner.pass, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "never"})
	envNever, err := key.ClerkKey(unissued, r.owner.pass, r.holder.pub, 0, 1000, key.LimitSpendTask(500))
	must(t, err)
	if err := r.k.Extend(3, envNever, "t1"); err == nil {
		t.Fatal("an extension under a root the log never issued cannot fund a plan")
	}
	if _, ok := r.k.State().SpendHeld["t1"]; !ok {
		t.Fatal("refused extensions must leave the hold")
	}
}

func TestHoldOnlyForSpendRefusals(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	if err := r.k.Hold(1, "t1", &key.Refusal{Code: key.RExpired}); err == nil {
		t.Fatal("only an exhausted spend cap holds a plan")
	}
	if err := r.k.Hold(1, "t1", nil); err == nil {
		t.Fatal("a hold needs the refusal that caused it")
	}
	if err := r.k.Hold(1, "nope", &key.Refusal{Code: key.RSpendTask}); err == nil {
		t.Fatal("an unknown plan cannot be held")
	}
}

func TestHoldAndExtensionSurviveReplay(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", k)
	modelPlan(r, "t2", k)
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	exhaust(r, "t2", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(5)), "t2"))
	must(t, r.k.Log().Anchor())
	r.boot(4)
	held := r.k.State().SpendHeld
	if _, ok := held["t1"]; !ok || len(held) != 1 {
		t.Fatalf("replayed holds: %v", held)
	}
	if _, ok := r.k.State().Extended["t2"]; !ok {
		t.Fatal("replayed extension lost")
	}
}

// An extension widens, so it is anchored at once: one whose anchor failed is
// refused and gone after a restart, and the hold is back (KRN-7).
func TestUnanchoredExtensionIsDroppedAndTheHoldReturns(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	must(t, r.k.Log().Anchor())
	if !kernel.Widening(kernel.TSpendExtend) {
		t.Fatal("an extension is a widening")
	}
	r.anchor.down = true
	if err := r.k.Extend(3, extension(r, env, key.LimitSpendTask(5)), "t1"); err == nil {
		t.Fatal("an extension whose anchor failed must be refused")
	}
	r.anchor.down = false
	r.boot(4)
	if _, ok := r.k.State().SpendHeld["t1"]; !ok {
		t.Fatal("an unconfirmed extension must not count after restart")
	}
	if rf := r.admit(5, "t1", 1); rf == nil {
		t.Fatal("the plan must still be held")
	}
	must(t, r.k.Extend(6, extension(r, env, key.LimitSpendTask(5)), "t1"))
	r.boot(7)
	if _, ok := r.k.State().SpendHeld["t1"]; ok {
		t.Fatal("an anchored extension must stand")
	}
}

// Pausing the key a plan cites stops its spend, extended or not (KEY-6).
func TestPausingTheCitedKeyStopsAnExtendedPlan(t *testing.T) {
	r := newRig(t)
	cited := modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", cited)
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(50)), "t1"))
	if rf := r.admit(4, "t1", 1); rf != nil {
		t.Fatalf("the extended plan spends: %v", rf)
	}
	v, err := key.Chain(cited, []key.PublicKey{r.owner.pk})
	if err != nil {
		t.Fatal(err)
	}
	must(t, r.k.Pause(5, v.ID()))
	if rf := r.admit(6, "t1", 1); rf == nil || rf.Code != key.RPaused {
		t.Fatalf("a paused cited key stops its plan's spend: %v", rf)
	}
}

// A rejected plan never ran: nothing is metered or held under a key its
// submitter did not hold, though the key's root was issued.
func TestRejectedPlanMetersNothing(t *testing.T) {
	r := newRig(t)
	step := kernel.PlanStep{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}
	p := kernel.SignPlan(kernel.Plan{ID: "t2", Key: modelKey(r, "m1", key.LimitSpendTask(10)), Steps: []kernel.PlanStep{step}}, gen(9).priv)
	must(t, r.k.Submit(0, p))
	if r.status("t2") != kernel.SRejected {
		t.Fatalf("a stranger's plan is %s", r.status("t2"))
	}
	if err := r.meter(1, "t2", "api", 5, "provider"); err == nil {
		t.Fatal("a rejected plan is metered")
	}
}

func TestPoolRefusesAtTheReserveUntilReset(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "codex-5h", 100))
	must(t, read(r, 2, "codex-5h", 899, 10_000))
	if rf := r.k.AdmitPool(3, "codex-5h"); rf != nil {
		t.Fatal(rf)
	}
	must(t, read(r, 4, "codex-5h", 900, 10_000))
	if rf := r.k.AdmitPool(5, "codex-5h"); rf == nil || rf.Code != kernel.CPool {
		t.Fatalf("pool at the reserve: %v", rf)
	}
	if rf := r.k.AdmitPool(5, "other"); rf != nil {
		t.Fatalf("pools are separate: %v", rf)
	}
	if rf := r.k.AdmitPool(9_999, "codex-5h"); rf == nil {
		t.Fatal("a pool stays closed until its reset time")
	}
	if rf := r.k.AdmitPool(10_000, "codex-5h"); rf != nil {
		t.Fatalf("reset time is the cooldown: %v", rf)
	}
}

// A full window whose reading has no usable reset time, or one already past,
// falls back to the declared window, so it never closes forever. The clerk
// gives the window's own declared length first (plan.Window.Every); the
// kernel's fallback is PoolWindowMS. Another window keeps its own reset.
func TestAFullWindowWithoutResetFallsBackToItsLength(t *testing.T) {
	for name, resetAt := range map[string]int64{"none": 0, "past": 50, "now": 100} {
		r := newRig(t)
		must(t, r.k.ReadPool(100, "p", []kernel.WindowReading{{Window: "5h", Used: 1000, ResetAt: resetAt}, {Window: "7d", Used: 10, ResetAt: 1 << 40}}))
		if w := r.k.State().Pools["p"].Windows; w["5h"].ResetAt != 100+kernel.PoolWindowMS || w["7d"].ResetAt != 1<<40 {
			t.Fatalf("%s: windows %+v", name, w)
		}
		if rf := r.k.AdmitPool(100+kernel.PoolWindowMS-1, "p"); rf == nil {
			t.Fatalf("%s: closed until the window ends", name)
		}
		if rf := r.k.AdmitPool(100+kernel.PoolWindowMS, "p"); rf != nil {
			t.Fatalf("%s: the window is the cooldown: %v", name, rf)
		}
	}
}

// A reading after the reset time reopens the pool first, then narrows again.
func TestReadingAfterTheResetTimeReopensThenReads(t *testing.T) {
	r := newRig(t)
	must(t, read(r, 1, "p", 1000, 10_000))
	must(t, read(r, 10_000, "p", 300, 20_000))
	if !r.k.State().PoolOpen(10_000, "p") {
		t.Fatal("the reset time had passed: the pool is open at 300")
	}
}

// A held key cannot release itself through an extension it was later funded
// by: the key that was funding the plan when it was held is barred too.
func TestAnExtensionCannotReleaseItsOwnHold(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	e1 := extension(r, env, key.LimitSpendTask(20))
	must(t, r.k.Extend(3, e1, "t1"))
	must(t, r.meter(4, "t1", "api", 20, "provider"))
	rf := r.admit(5, "t1", 1)
	if rf == nil {
		t.Fatal("e1 is used up")
	}
	must(t, r.k.Hold(5, "t1", rf))
	if err := r.k.Extend(6, e1, "t1"); err == nil {
		t.Fatal("the extension that funded the plan cannot release it again")
	}
	under, err := key.Derive(e1, r.holder.priv, r.holder.pub, key.LimitSpendTask(5))
	must(t, err)
	if err := r.k.Extend(6, under, "t1"); err == nil {
		t.Fatal("nor can anything derived from it")
	}
	must(t, r.k.Extend(6, extension(r, env, key.LimitSpendTask(20), key.LimitSpendDay(700)), "t1"))
}

// The guards against self-release must hold for keys that still have room:
// a refused cap holds the plan, but the key behind it may be only part used.
func TestHeldKeysWithRoomLeftStillCannotReleaseThePlan(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", k)
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	e1 := extension(r, env, key.LimitSpendTask(100))
	must(t, r.k.Extend(3, e1, "t1"))
	must(t, r.meter(4, "t1", "api", 70, "provider"))
	rf := r.admit(5, "t1", 51)
	if rf == nil {
		t.Fatal("51 more does not fit e1's cap")
	}
	must(t, r.k.Hold(5, "t1", rf))
	if err := r.k.Extend(6, e1, "t1"); err == nil {
		t.Fatal("the key that funded the plan cannot release it, room left or not")
	}
	under, err := key.Derive(e1, r.holder.priv, r.holder.pub, key.LimitSpendTask(90))
	must(t, err)
	if err := r.k.Extend(6, under, "t1"); err == nil {
		t.Fatal("nor can a key derived from it")
	}
	sibling, err := key.ClerkKey(key.Key{Root: k.Root}, r.owner.pass, r.holder.pub, 0, 1000, key.LimitSpendTask(50))
	must(t, err)
	must(t, r.issue(-kernel.GrantHold, sibling)) // granted, so only its root refuses it
	if err := r.k.Extend(6, sibling, "t1"); err == nil {
		t.Fatal("nor can a sibling under the cited key's root")
	}
	if _, ok := r.k.State().SpendHeld["t1"]; !ok {
		t.Fatal("refused extensions must leave the hold")
	}
}

// A pool the reserve alone closed has no reset time to wait for: refusing a
// call on it logs nothing.
func TestPoolClosedByTheReserveAloneLogsNothingWhenRefusing(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 1000))
	n := len(r.k.Log().Entries())
	for i := int64(2); i < 5; i++ {
		if rf := r.k.AdmitPool(i, "p"); rf == nil {
			t.Fatal("a pool whose whole share is the reserve is closed")
		}
	}
	if len(r.k.Log().Entries()) != n {
		t.Fatal("a refusal with no reset time to pass must not log a reset")
	}
}

// An extension needs room for one more under the envelope's ceilings.
func TestExtensionNeedsRoomUnderTheEnvelope(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	env := envelope(r, 15, 800)
	exhaust(r, "t1", 10)
	e1 := extension(r, env, key.LimitSpendTask(15))
	must(t, r.k.Extend(3, e1, "t1"))
	must(t, r.meter(4, "t1", "api", 15, "provider"))
	rf := r.admit(5, "t1", 1)
	must(t, r.k.Hold(5, "t1", rf))
	if err := r.k.Extend(6, extension(r, env, key.LimitSpendTask(15), key.LimitSpendDay(700)), "t1"); err == nil {
		t.Fatal("the envelope's task ceiling is used up: an extension has no room")
	}
}

// Reopening is a widening: it is logged, needs an anchor, and a reading alone
// can only narrow.
func TestPoolReopeningIsALoggedWidening(t *testing.T) {
	r := newRig(t)
	must(t, read(r, 1, "p", 1000, 10_000))
	must(t, read(r, 2, "p", 0, 10_000)) // a reading must not reopen a closed pool
	if rf := r.k.AdmitPool(3, "p"); rf == nil {
		t.Fatal("the pool stays closed")
	}
	must(t, r.k.Log().Anchor())
	if rf := r.k.AdmitPool(10_000, "p"); rf != nil {
		t.Fatal(rf)
	}
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TPoolReset || !kernel.Widening(last.Type) {
		t.Fatalf("reopening must be a logged widening, got %s", last.Type)
	}
	r.boot(10_001)
	if r.k.State().PoolOpen(10_001, "p") {
		t.Fatal("the unanchored reset must not stand after restart")
	}
	if rf := r.k.AdmitPool(10_002, "p"); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.Log().Anchor())
	r.boot(10_003)
	if !r.k.State().PoolOpen(10_003, "p") {
		t.Fatal("an anchored reopening stands")
	}
}

func TestDefaultReserveIsZero(t *testing.T) {
	r := newRig(t)
	must(t, read(r, 1, "p", 999, 10_000))
	if rf := r.k.AdmitPool(2, "p"); rf != nil {
		t.Fatalf("default reserve lets the box use the whole pool: %v", rf)
	}
	must(t, read(r, 3, "p", 1000, 10_000))
	if rf := r.k.AdmitPool(4, "p"); rf == nil {
		t.Fatal("an exhausted pool admits nothing")
	}
}

func TestLoweringTheReserveIsAWidening(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 200))
	must(t, r.k.Reserve(2, "p", 300))
	must(t, r.k.Reserve(3, "p", 100, lower(r, "p", 100, r.owner)))
	es := r.k.Log().Entries()
	n := len(es)
	if kernel.Widening(es[n-3].Type) || kernel.Widening(es[n-2].Type) {
		t.Fatal("raising a reserve narrows: a text is enough (KEY-6)")
	}
	if !kernel.Widening(es[n-1].Type) {
		t.Fatal("lowering a reserve widens: it needs the passkey (KEY-4)")
	}
	if err := r.k.Reserve(4, "p", 1001); err == nil {
		t.Fatal("a reserve is a share of the pool")
	}
	if err := read(r, 4, "p", -1, 0); err == nil {
		t.Fatal("utilization is a share of the pool")
	}
}

func TestPoolStateSurvivesReplay(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, read(r, 2, "p", 950, 10_000))
	must(t, r.k.ReadPool(2, "q", []kernel.WindowReading{{Window: "5h", Used: 100, ResetAt: 5_000}, {Window: "7d", Used: 950, ResetAt: 50_000}}))
	must(t, r.k.Reserve(3, "q", 50))
	before := r.k.State().Pools["q"]
	r.boot(4)
	if rf := r.k.AdmitPool(4, "p"); rf == nil {
		t.Fatal("replayed pool lost its reading")
	}
	after := r.k.State().Pools["q"]
	if len(after.Windows) != 2 || after.Windows["5h"] != before.Windows["5h"] || after.Windows["7d"] != before.Windows["7d"] ||
		after.Reserve != 50 || after.Changes != before.Changes {
		t.Fatalf("replay rebuilt %+v, want %+v", after, before)
	}
	if rf := r.k.AdmitPool(5_000, "q"); rf == nil {
		t.Fatal("the week is still at the reserve after a replay")
	}
}

// A lowered reserve anchors at once: with the anchor down it is refused, no
// spend is admitted on the broken log, and after a restart the reserve is
// back where it was (KRN-5, KRN-7, #2613 items 8, 9).
func TestAnUnanchoredReserveDropBreaksTheLogAndAdmitsNoSpend(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(10)))
	must(t, r.k.Reserve(1, "p", 300))
	must(t, r.k.Log().Anchor())
	r.anchor.down = true
	if err := r.k.Reserve(2, "p", 100, lower(r, "p", 100, r.owner)); err == nil {
		t.Fatal("a lowered reserve whose anchor failed must be refused")
	}
	if rf := r.admit(3, "t1", 1); rf == nil || rf.Code != kernel.CBroken {
		t.Fatalf("a call admitted on a broken log: %v", rf)
	}
	if rf := r.k.AdmitPool(3, "p"); rf == nil || rf.Code != kernel.CBroken {
		t.Fatalf("a pool admitted on a broken log: %v", rf)
	}
	r.anchor.down = false
	r.boot(4)
	if got := r.k.State().Pools["p"].Reserve; got != 300 {
		t.Fatalf("reserve after restart %d, want 300", got)
	}
	if rf := r.admit(5, "t1", 1); rf != nil {
		t.Fatalf("a reopened log admits spend: %v", rf)
	}
}

// An extended plan stops spending once its envelope is revoked, and an
// extension of a plan whose cited key is paused is refused at once (KEY-6,
// #2613 items 9, 12).
func TestARevokedEnvelopeFundsNothingAndAPausedKeysPlanIsNotExtended(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", k)
	modelPlan(r, "t2", k)
	env := envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(100)), "t1"))
	must(t, r.k.Revoke(4, key.Key{Root: env.Root}.Tip()))
	if rf := r.admit(5, "t1", 1); rf == nil || rf.Code != key.RRevoked {
		t.Fatalf("a revoked envelope still funds the plan: %v", rf)
	}
	r = newRig(t)
	k = modelKey(r, "m1", key.LimitSpendTask(10))
	modelPlan(r, "t1", k)
	env = envelope(r, 500, 800)
	exhaust(r, "t1", 10)
	must(t, r.k.Pause(3, k.Tip()))
	if err := r.k.Extend(4, extension(r, env, key.LimitSpendTask(100)), "t1"); err == nil {
		t.Fatal("a plan whose cited key is paused was extended")
	}
	if _, ok := r.k.State().Extended["t1"]; ok {
		t.Fatal("the refused extension was logged")
	}
}

// read is a one-window reading of pool: the 5-hour window.
func read(r *rig, at int64, pool string, used, resetAt int64) error {
	return r.k.ReadPool(at, pool, []kernel.WindowReading{{Window: "5h", Used: used, ResetAt: resetAt}})
}

// lower is by's signature over lowering pool's live reserve to to, as the
// pool's next reserve change.
func lower(r *rig, pool string, to int64, by pair) key.Cosign {
	p := r.k.State().Pools[pool]
	return key.Approve(by.pass, kernel.ReserveHash(p.Changes, pool, p.Reserve, to))
}

func entries(r *rig) int { return len(r.k.Log().Entries()) }

// A 5-hour reset leaves a pool closed while its week is at the reserve: the
// plan work the owner kept back stays kept (RES-5).
func TestEachWindowNarrowsAndResetsOnItsOwn(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, r.k.ReadPool(2, "p", []kernel.WindowReading{{Window: "5h", Used: 950, ResetAt: 1_000}, {Window: "7d", Used: 920, ResetAt: 100_000}}))
	if rf := r.k.AdmitPool(500, "p"); rf == nil {
		t.Fatal("both windows are at the reserve")
	}
	if rf := r.k.AdmitPool(1_000, "p"); rf == nil || rf.Code != kernel.CPool {
		t.Fatalf("the 5-hour window reset, but the week is still at the reserve: %v", rf)
	}
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TPoolReset || string(last.Body) != `{"pool":"p","window":"5h"}` {
		t.Fatalf("the 5-hour window's reset is logged on its own: %s %s", last.Type, last.Body)
	}
	if w := r.k.State().Pools["p"].Windows; w["5h"].Used != 0 || w["7d"].Used != 920 {
		t.Fatalf("windows after the 5-hour reset: %+v", w)
	}
	must(t, r.k.ReadPool(1_001, "p", []kernel.WindowReading{{Window: "7d", Used: 0, ResetAt: 200_000}}))
	if rf := r.k.AdmitPool(1_002, "p"); rf == nil {
		t.Fatal("a reading cannot reopen the week before its reset time")
	}
	if w := r.k.State().Pools["p"].Windows["7d"]; w.Used != 920 || w.ResetAt != 200_000 {
		t.Fatalf("a reading of a window at the reserve can only narrow: %+v", w)
	}
	must(t, r.k.ReadPool(1_003, "p", []kernel.WindowReading{{Window: "7d", Used: 990, ResetAt: 50_000}}))
	if w := r.k.State().Pools["p"].Windows["7d"]; w.Used != 990 || w.ResetAt != 200_000 {
		t.Fatalf("nor bring its reset time forward: %+v", w)
	}
	if rf := r.k.AdmitPool(200_000, "p"); rf != nil {
		t.Fatalf("the week's reset reopens the pool: %v", rf)
	}
}

func TestAReadingWithoutAWindowKeepsItsLastFigure(t *testing.T) {
	r := newRig(t)
	must(t, r.k.ReadPool(1, "p", []kernel.WindowReading{{Window: "5h", Used: 300, ResetAt: 10_000}, {Window: "7d", Used: 900, ResetAt: 90_000}}))
	must(t, read(r, 2, "p", 400, 10_000))
	if w := r.k.State().Pools["p"].Windows; w["5h"].Used != 400 || w["7d"].Used != 900 || w["7d"].ResetAt != 90_000 {
		t.Fatalf("windows %+v", w)
	}
	must(t, r.k.ReadPool(3, "p", []kernel.WindowReading{{Window: "7d", Used: 1000, ResetAt: 90_000}}))
	must(t, read(r, 4, "p", 10, 10_000))
	if rf := r.k.AdmitPool(5, "p"); rf == nil {
		t.Fatal("a reading of the 5-hour window alone leaves the spent week spent")
	}
	for name, ws := range map[string][]kernel.WindowReading{
		"no window":  nil,
		"twice":      {{Window: "5h", Used: 1}, {Window: "5h", Used: 2}},
		"unnamed":    {{Used: 1}},
		"over whole": {{Window: "5h", Used: 1001}},
		"negative":   {{Window: "5h", Used: -1}},
	} {
		n := entries(r)
		if err := r.k.ReadPool(6, "p", ws); err == nil || entries(r) != n {
			t.Fatalf("%s: a malformed reading is refused and logs nothing", name)
		}
	}
}

// REQ: KEY-6
func TestRaisingTheReserveNeedsNoSignature(t *testing.T) {
	r := newRig(t)
	must(t, read(r, 1, "p", 750, 1<<40))
	must(t, r.k.Reserve(2, "p", 300))
	if rf := r.k.AdmitPool(2, "p"); rf == nil {
		t.Fatal("a raise is live at once")
	}
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TReserveUp || kernel.Widening(last.Type) {
		t.Fatalf("a raise is a narrowing entry: %s", last.Type)
	}
	if got := r.k.State().Pools["p"]; got.Reserve != 300 || got.Lowering != nil || got.Changes != 1 {
		t.Fatalf("pool %+v", got)
	}
}

// REQ: KEY-4, KEY-6
func TestLoweringTheReserveNeedsALivePasskey(t *testing.T) {
	r := newRig(t)
	phone, cut, stranger := gen(8), gen(9), gen(10)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, cut.pk)))
	must(t, r.k.Unenroll(0, key.Unenroll(r.owner.pass, cut.pk)))
	must(t, r.k.Reserve(1, "p", 300))
	n := r.k.State().Pools["p"].Changes
	for name, cos := range map[string][]key.Cosign{
		"no cosign":         nil,
		"another pool":      {key.Approve(phone.pass, kernel.ReserveHash(n, "q", 300, 200))},
		"another value":     {key.Approve(phone.pass, kernel.ReserveHash(n, "p", 300, 100))},
		"another from":      {key.Approve(phone.pass, kernel.ReserveHash(n, "p", 400, 200))},
		"older change":      {key.Approve(phone.pass, kernel.ReserveHash(n-1, "p", 300, 200))},
		"line domain":       {key.Approve(phone.pass, kernel.LineHash(n, 200))},
		"cut-off passkey":   {lower(r, "p", 200, cut)},
		"stranger":          {lower(r, "p", 200, stranger)},
		"forged by a phone": {{By: phone.pk, Sig: stranger.pass.Sign(key.CosignMsg(kernel.ReserveHash(n, "p", 300, 200)))}},
	} {
		before := entries(r)
		if err := r.k.Reserve(2, "p", 200, cos...); !errors.Is(err, kernel.ErrReserveSig) {
			t.Fatalf("%s: %v, want ErrReserveSig", name, err)
		}
		if entries(r) != before {
			t.Fatalf("%s: a refused lowering logs nothing", name)
		}
	}
	sig := lower(r, "p", 200, phone)
	must(t, r.k.Reserve(2, "p", 200, sig))
	es := r.k.Log().Entries()
	if last := es[len(es)-1]; last.Type != kernel.TReserveDown || !kernel.Widening(last.Type) {
		t.Fatalf("a lowering is a widening entry: %s", last.Type)
	}
	must(t, r.k.Reserve(3, "p", 300)) // cancel it
	if err := r.k.Reserve(4, "p", 200, sig); !errors.Is(err, kernel.ErrReserveSig) {
		t.Fatalf("an old signature replays: %v", err)
	}
}

// REQ: KEY-4, KRN-7
func TestALoweringIsNotLiveInsideTheHold(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 300))
	must(t, read(r, 1, "p", 800, 1<<40))
	must(t, r.k.Reserve(2, "p", 0, lower(r, "p", 0, r.owner)))
	live := 2 + kernel.GrantHold
	want := []kernel.PendingReserve{{Pool: "p", From: 300, To: 0, Live: live}}
	for _, boot := range []bool{false, true} {
		if boot {
			r.boot(3)
		}
		if got := r.k.State().PendingReserves(3); len(got) != 1 || got[0] != want[0] {
			t.Fatalf("boot %v: pending %+v, want %+v", boot, got, want)
		}
		if rf := r.k.AdmitPool(live-1, "p"); rf == nil {
			t.Fatalf("boot %v: admission reads the old reserve inside the hold", boot)
		}
	}
	if rf := r.k.AdmitPool(live, "p"); rf != nil {
		t.Fatalf("the lowering is live at the end of its hold: %v", rf)
	}
	if got := r.k.State().PendingReserves(live); len(got) != 0 {
		t.Fatalf("a live lowering is not pending: %+v", got)
	}
}

// REQ: KEY-4
func TestACancelledLoweringNeverGoesLive(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 300))
	must(t, read(r, 1, "p", 800, 1<<40))
	must(t, r.k.Reserve(2, "p", 0, lower(r, "p", 0, r.owner)))
	must(t, r.k.Reserve(5, "p", 300)) // back to the current reserve: the page's Cancel
	for _, boot := range []bool{false, true} {
		if boot {
			r.boot(6)
		}
		if got := r.k.State().PendingReserves(6); len(got) != 0 {
			t.Fatalf("boot %v: a cancelled lowering is pending: %+v", boot, got)
		}
		if rf := r.k.AdmitPool(2+kernel.GrantHold, "p"); rf == nil {
			t.Fatalf("boot %v: a cancelled lowering went live", boot)
		}
		if got := r.k.State().Pools["p"]; got.Reserve != 300 || got.Lowering != nil {
			t.Fatalf("boot %v: pool %+v", boot, got)
		}
	}
}

// REQ: KEY-4
func TestALaterLoweringRestartsTheHold(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 300))
	must(t, read(r, 1, "p", 750, 1<<40))
	must(t, r.k.Reserve(2, "p", 200, lower(r, "p", 200, r.owner)))
	must(t, r.k.Reserve(1_000, "p", 100, lower(r, "p", 100, r.owner)))
	if got := r.k.State().PendingReserves(1_001); len(got) != 1 || got[0].To != 100 || got[0].From != 300 || got[0].Live != 1_000+kernel.GrantHold {
		t.Fatalf("pending %+v", got)
	}
	if rf := r.k.AdmitPool(2+kernel.GrantHold, "p"); rf == nil {
		t.Fatal("the replaced lowering never goes live")
	}
	if rf := r.k.AdmitPool(1_000+kernel.GrantHold, "p"); rf != nil {
		t.Fatalf("the later lowering goes live at the end of its own hold: %v", rf)
	}
}

// The box's usable share is 1000 minus the reserve: a lowering that takes it
// past the owner's line is big (KEY-4, D-146).
// REQ: KEY-4
func TestABigLoweringNeedsTwoPasskeysOneAnAnchor(t *testing.T) {
	r := newRig(t)
	phone, phone2 := gen(8), gen(9)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.pk)))
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone2.pk)))
	must(t, r.k.Reserve(1, "p", 600))
	for name, by := range map[string][]pair{"phone alone": {phone}, "anchor alone": {r.owner}, "two phones": {phone, phone2}, "one phone twice": {phone, phone}} {
		var cos []key.Cosign
		for _, p := range by {
			cos = append(cos, lower(r, "p", 0, p))
		}
		before := entries(r)
		if err := r.k.Reserve(2, "p", 0, cos...); !errors.Is(err, kernel.ErrNeedsCosign) {
			t.Fatalf("%s: 600 to 0 takes 400 to 1000: %v, want ErrNeedsCosign", name, err)
		}
		if entries(r) != before {
			t.Fatalf("%s: a refused lowering logs nothing", name)
		}
	}
	must(t, r.k.Reserve(2, "p", 0, lower(r, "p", 0, phone), lower(r, "p", 0, r.owner)))
	if got := r.k.State().PendingReserves(3); len(got) != 1 || got[0].Live != 2+kernel.GrantHold {
		t.Fatalf("a big lowering still waits the hold: %+v", got)
	}
	must(t, r.k.Reserve(4, "q", 300))
	must(t, r.k.Reserve(5, "q", 0, lower(r, "q", 0, phone))) // 700 to 1000: one passkey
	must(t, r.k.Reserve(8, "a", 600))
	if err := r.k.Reserve(9, "a", 100, lower(r, "a", 100, phone)); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("600 to 100 takes 400 to 900: %v, want ErrNeedsCosign", err)
	}
	must(t, r.k.Reserve(10, "b", 500))
	must(t, r.k.Reserve(11, "b", 400, lower(r, "b", 400, phone))) // 500 to 600: one passkey
	must(t, r.k.Reserve(12, "c", 600))
	must(t, r.k.Reserve(13, "c", 590, lower(r, "c", 590, phone))) // 400 to 410: one passkey
	must(t, r.k.Reserve(6, "w", 1000))
	if err := r.k.Reserve(7, "w", 990, lower(r, "w", 990, phone)); !errors.Is(err, kernel.ErrNeedsCosign) {
		t.Fatalf("any lowering from 1000 is big: %v", err)
	}
}

// REQ: LOG-7, ONB-9
func TestSpentSumsRoutesSinceAndPrunesPastTwoDays(t *testing.T) {
	r := newRig(t)
	modelPlan(r, "t1", modelKey(r, "m1"))
	day := key.DayMS
	must(t, r.meter(1, "t1", "api", 10, "provider"))
	must(t, r.meter(day, "t1", "plan", 5, "provider"))
	must(t, r.meter(day+1, "t1", "api", 3, "clerk"))
	if got := r.k.State().Spent(day); got["api"] != 3 || got["plan"] != 5 || len(got) != 2 {
		t.Fatalf("spent since a day: %v", got)
	}
	if got := r.k.State().Spent(0); got["api"] != 13 {
		t.Fatalf("spent in the last two days: %v", got)
	}
	must(t, r.meter(2*day+1, "t1", "plan", 1, "provider"))
	if got := r.k.State().Spent(0); got["api"] != 13 {
		t.Fatalf("spend exactly two days old is kept: %v", got)
	}
	must(t, r.meter(2*day+10, "t1", "api", 7, "provider"))
	for _, boot := range []bool{false, true} {
		if boot {
			r.boot(2*day + 11)
		}
		if got := r.k.State().Spent(0); got["api"] != 10 || got["plan"] != 6 {
			t.Fatalf("boot %v: spend older than two days is pruned: %v", boot, got)
		}
	}
}

// A lowering written past the kernel with no valid signature changes nothing
// on replay, so an audit trusts no writer for it (KRN-1, KRN-7).
// REQ: KRN-1, KEY-4
func TestAnUnsignedLoweringInTheLogIsNotFolded(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 300))
	for to, cos := range map[int64][]key.Cosign{0: nil, 1: {lower(r, "q", 1, r.owner)}, 300: {lower(r, "p", 300, r.owner)}} {
		body := map[string]any{"pool": "p", "reserve": to, "cosigns": cos}
		_, err := r.k.Log().Append(2, kernel.TReserveDown, 2, body)
		must(t, err)
	}
	must(t, r.k.Log().Anchor())
	r.boot(3)
	if got := r.k.State().Pools["p"]; got.Reserve != 300 || got.Lowering != nil || got.Changes != 1 {
		t.Fatalf("an unsigned lowering was folded: %+v", got)
	}
}

// Two windows due at once both reset, each logged (RES-5, KRN-7).
func TestWindowsDueTogetherEachReset(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, r.k.ReadPool(2, "p", []kernel.WindowReading{{Window: "5h", Used: 950, ResetAt: 1_000}, {Window: "7d", Used: 950, ResetAt: 1_000}}))
	if !r.k.State().WindowDue(1_000, "p", "7d") || r.k.State().WindowDue(999, "p", "7d") {
		t.Fatal("a window is due from its reset time")
	}
	if rf := r.k.AdmitPool(1_000, "p"); rf != nil {
		t.Fatalf("both windows reset: %v", rf)
	}
	es := r.k.Log().Entries()
	if a, b := es[len(es)-2], es[len(es)-1]; a.Type != kernel.TPoolReset || b.Type != kernel.TPoolReset {
		t.Fatalf("each reset is logged: %s %s", a.Type, b.Type)
	}
}

// A full window written past the kernel with no reset time is never due: an
// entry the kernel did not normalize reopens nothing (KRN-1, KRN-7).
func TestAFullWindowInTheLogWithNoResetTimeIsNeverDue(t *testing.T) {
	r := newRig(t)
	body := map[string]any{"pool": "p", "windows": []map[string]any{{"window": "5h", "used": 1000, "reset_at": 0}}}
	_, err := r.k.Log().Append(1, kernel.TPoolRead, 2, body)
	must(t, err)
	must(t, r.k.Log().Anchor())
	r.boot(2)
	if r.k.State().WindowDue(1<<40, "p", "5h") || r.k.State().PoolOpen(1<<40, "p") {
		t.Fatal("a full window with no reset time is due")
	}
}

// A model.used logged at a time near the int64 floor replays without a
// panic and keeps no spend (L3 delta on d1e27c8c).
func TestSpendAtTheInt64FloorReplays(t *testing.T) {
	r := newRig(t)
	body := map[string]any{"task": "t1", "route": "api", "amount": 3, "source": "provider"}
	_, err := r.k.Log().Append(math.MinInt64+5, kernel.TModelUsed, 1, body)
	must(t, err)
	must(t, r.k.Log().Anchor())
	r.boot(2)
	if got := r.k.State().Spent(math.MinInt64); len(got) != 0 {
		t.Fatalf("spent %v", got)
	}
}
