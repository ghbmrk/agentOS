package kernel_test

// REQ: LOG-7, RES-5, KEY-3, KEY-4, KEY-6, KRN-7, LOG-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// envelope issues the owner's spend envelope: a model-clerk root whose first
// link sets the per-task and per-day extension ceilings (LOG-7, KEY-4).
func envelope(r *rig, task, day int64) key.Key {
	root := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "env"})
	must(r.t, r.k.Issue(0, root))
	env, err := key.Derive(root, r.holder.priv, r.holder.pub, key.LimitSpendTask(task), key.LimitSpendDay(day))
	must(r.t, err)
	return env
}

func extension(r *rig, env key.Key, c ...key.Caveat) key.Key {
	ext, err := key.Derive(env, r.holder.priv, r.holder.pub, c...)
	must(r.t, err)
	return ext
}

// exhaust spends a plan to its task cap and holds it.
func exhaust(r *rig, plan string, cap int64) {
	must(r.t, r.k.Meter(1, plan, "api", cap, "provider"))
	rf := r.k.AdmitSpend(2, plan, 1)
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
	if rf := r.k.AdmitSpend(2, "t1", 1); rf == nil || rf.Code != kernel.CHeld {
		t.Fatalf("a held plan admits nothing: %v", rf)
	}
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(300)), "t1"))
	if _, ok := r.k.State().SpendHeld["t1"]; ok {
		t.Fatal("extension must release the hold")
	}
	if rf := r.k.AdmitSpend(4, "t1", 300); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.k.AdmitSpend(4, "t1", 301); rf == nil || rf.Code != key.RSpendTask {
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
	if rf := r.k.AdmitSpend(3, "p1", 1); rf == nil {
		t.Fatal("a held plan stays held")
	}
	if rf := r.k.AdmitSpend(3, "p2", 5); rf != nil {
		t.Fatalf("another plan has its own task cap: %v", rf)
	}
	if rf := r.k.AdmitSpend(3, "p2", 6); rf == nil || rf.Code != key.RSpendDay {
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
	must(t, r.k.Meter(4, "t1", "api", 300, "provider"))
	rf := r.k.AdmitSpend(5, "t1", 1)
	if rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("the extension is used up: %v", rf)
	}
	must(t, r.k.Hold(5, "t1", rf))
	// a distinct key: equal caveats derive the same key
	must(t, r.k.Extend(6, extension(r, env, key.LimitSpendTask(350)), "t1"))
	if rf := r.k.AdmitSpend(7, "t1", 201); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("two extensions must not pass the per-task ceiling: %v", rf)
	}
	if rf := r.k.AdmitSpend(7, "t1", 200); rf != nil {
		t.Fatal(rf)
	}
	exhaust(r, "t2", 10)
	must(t, r.k.Extend(8, extension(r, env, key.LimitSpendTask(360)), "t2"))
	must(t, r.k.Meter(9, "t2", "api", 300, "provider"))
	exhaust(r, "t3", 10)
	must(t, r.k.Extend(10, extension(r, env, key.LimitSpendTask(400)), "t3"))
	if rf := r.k.AdmitSpend(11, "t3", 201); rf == nil || rf.Code != key.RSpendDay {
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
	other := key.Issue(gen(9).priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	if err := r.k.Extend(3, other, "t1"); err == nil {
		t.Fatal("a foreign envelope cannot extend")
	}
	unissued := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "never"})
	envNever, err := key.Derive(unissued, r.holder.priv, r.holder.pub, key.LimitSpendTask(500))
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
	if rf := r.k.AdmitSpend(5, "t1", 1); rf == nil {
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
	if rf := r.k.AdmitSpend(4, "t1", 1); rf != nil {
		t.Fatalf("the extended plan spends: %v", rf)
	}
	v, err := key.Chain(cited, r.owner.pub)
	if err != nil {
		t.Fatal(err)
	}
	must(t, r.k.Pause(5, v.ID()))
	if rf := r.k.AdmitSpend(6, "t1", 1); rf == nil || rf.Code != key.RPaused {
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
	if err := r.k.Meter(1, "t2", "api", 5, "provider"); err == nil {
		t.Fatal("a rejected plan is metered")
	}
}

func TestPoolRefusesAtTheReserveUntilReset(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "codex-5h", 100))
	must(t, r.k.ReadPool(2, "codex-5h", 899, 10_000))
	if rf := r.k.AdmitPool(3, "codex-5h"); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.ReadPool(4, "codex-5h", 900, 10_000))
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

// A full pool whose reading has no usable reset time, or one already past,
// falls back to the pool's declared window, so it never closes forever.
func TestPoolWithoutUsableResetTimeFallsBackToTheWindow(t *testing.T) {
	for name, resetAt := range map[string]int64{"none": 0, "past": 50} {
		r := newRig(t)
		must(t, r.k.ReadPool(100, "p", 1000, resetAt))
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
	must(t, r.k.ReadPool(1, "p", 1000, 10_000))
	must(t, r.k.ReadPool(10_000, "p", 300, 20_000))
	if !r.k.State().PoolOpen("p") {
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
	must(t, r.k.Meter(4, "t1", "api", 20, "provider"))
	rf := r.k.AdmitSpend(5, "t1", 1)
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
	must(t, r.k.Meter(4, "t1", "api", 70, "provider"))
	rf := r.k.AdmitSpend(5, "t1", 51)
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
	sibling, err := key.Derive(key.Key{Root: k.Root}, r.holder.priv, r.holder.pub, key.LimitSpendTask(50))
	must(t, err)
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
	must(t, r.k.Meter(4, "t1", "api", 15, "provider"))
	rf := r.k.AdmitSpend(5, "t1", 1)
	must(t, r.k.Hold(5, "t1", rf))
	if err := r.k.Extend(6, extension(r, env, key.LimitSpendTask(15), key.LimitSpendDay(700)), "t1"); err == nil {
		t.Fatal("the envelope's task ceiling is used up: an extension has no room")
	}
}

// Reopening is a widening: it is logged, needs an anchor, and a reading alone
// can only narrow.
func TestPoolReopeningIsALoggedWidening(t *testing.T) {
	r := newRig(t)
	must(t, r.k.ReadPool(1, "p", 1000, 10_000))
	if err := r.k.ReadPool(2, "p", 0, 10_000); err == nil {
		t.Fatal("a reading must not reopen a closed pool")
	}
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
	if r.k.State().PoolOpen("p") {
		t.Fatal("the unanchored reset must not stand after restart")
	}
	if rf := r.k.AdmitPool(10_002, "p"); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.Log().Anchor())
	r.boot(10_003)
	if !r.k.State().PoolOpen("p") {
		t.Fatal("an anchored reopening stands")
	}
}

func TestDefaultReserveIsZero(t *testing.T) {
	r := newRig(t)
	must(t, r.k.ReadPool(1, "p", 999, 10_000))
	if rf := r.k.AdmitPool(2, "p"); rf != nil {
		t.Fatalf("default reserve lets the box use the whole pool: %v", rf)
	}
	must(t, r.k.ReadPool(3, "p", 1000, 10_000))
	if rf := r.k.AdmitPool(4, "p"); rf == nil {
		t.Fatal("an exhausted pool admits nothing")
	}
}

func TestLoweringTheReserveIsAWidening(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 200))
	must(t, r.k.Reserve(2, "p", 300))
	must(t, r.k.Reserve(3, "p", 100))
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
	if err := r.k.ReadPool(4, "p", -1, 0); err == nil {
		t.Fatal("utilization is a share of the pool")
	}
}

func TestPoolStateSurvivesReplay(t *testing.T) {
	r := newRig(t)
	must(t, r.k.Reserve(1, "p", 100))
	must(t, r.k.ReadPool(2, "p", 950, 10_000))
	r.boot(3)
	if rf := r.k.AdmitPool(4, "p"); rf == nil {
		t.Fatal("replayed pool lost its reading")
	}
}
