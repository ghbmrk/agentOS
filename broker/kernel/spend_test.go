package kernel_test

// REQ: LOG-7, RES-5, KEY-3, KEY-4, KEY-6, LOG-1

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

// exhaust spends a key to its task cap and holds the task.
func exhaust(r *rig, k key.Key, task string, cap int64) {
	must(r.t, r.k.Meter(1, k, task, "api", cap, "provider"))
	rf := r.k.AdmitSpend(2, k, "model", task, 1)
	if rf == nil {
		r.t.Fatal("key should be exhausted")
	}
	must(r.t, r.k.Hold(2, k, task, rf))
}

func TestExhaustedTaskIsHeldUntilExtended(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(100))
	env := envelope(r, 500, 800)
	exhaust(r, k, "t1", 100)
	h, ok := r.k.State().SpendHeld["t1"]
	if !ok || h.Code != key.RSpendTask || h.Clerk != "model" {
		t.Fatalf("task not held: %+v", h)
	}
	ext := extension(r, env, key.LimitSpendTask(300))
	must(t, r.k.Extend(3, ext, "t1"))
	if _, ok := r.k.State().SpendHeld["t1"]; ok {
		t.Fatal("extension must release the hold")
	}
	if rf := r.k.AdmitSpend(4, ext, "model", "t1", 300); rf != nil {
		t.Fatal(rf)
	}
	if rf := r.k.AdmitSpend(4, ext, "model", "t1", 301); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("extension cap: %v", rf)
	}
}

func TestExtensionsShareTheEnvelopeCeilings(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(10))
	env := envelope(r, 500, 800)
	exhaust(r, k, "t1", 10)
	e1 := extension(r, env, key.LimitSpendTask(300))
	must(t, r.k.Extend(3, e1, "t1"))
	must(t, r.k.Meter(4, e1, "t1", "api", 300, "provider"))
	e2 := extension(r, env, key.LimitSpendTask(350)) // a distinct key: equal caveats derive the same key
	if rf := r.k.AdmitSpend(5, e2, "model", "t1", 201); rf == nil || rf.Code != key.RSpendTask {
		t.Fatalf("two extensions must not pass the per-task ceiling: %v", rf)
	}
	if rf := r.k.AdmitSpend(5, e2, "model", "t1", 200); rf != nil {
		t.Fatal(rf)
	}
	must(t, r.k.Meter(5, e2, "t2", "api", 300, "provider"))
	e3 := extension(r, env, key.LimitSpendTask(360))
	if rf := r.k.AdmitSpend(6, e3, "model", "t3", 201); rf == nil || rf.Code != key.RSpendDay {
		t.Fatalf("extensions must not pass the per-day ceiling: %v", rf)
	}
}

func TestExtendRefusals(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(10))
	env := envelope(r, 500, 800)
	if err := r.k.Extend(1, extension(r, env, key.LimitSpendTask(5)), "t1"); err == nil {
		t.Fatal("a task that is not held cannot be extended")
	}
	exhaust(r, k, "t1", 10)
	if err := r.k.Extend(3, k, "t1"); err == nil {
		t.Fatal("the exhausted key is not its own extension")
	}
	if err := r.k.Extend(3, modelKey(r, key.LimitSpendDay(5)), "t1"); err == nil {
		t.Fatal("an extension with no per-task cap anywhere in its chain is unbounded")
	}
	other := key.Issue(gen(9).priv, key.Root{Holder: r.holder.pub, Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "x"})
	if err := r.k.Extend(3, other, "t1"); err == nil {
		t.Fatal("a foreign envelope cannot extend")
	}
	mailRoot := key.Issue(r.owner.priv, key.Root{Holder: r.holder.pub, Clerk: "mail", Verbs: []key.Verb{key.Read}, Serial: "m"})
	must(t, r.k.Issue(0, mailRoot))
	mail, err := key.Derive(mailRoot, r.holder.priv, r.holder.pub, key.LimitSpendTask(5))
	must(t, err)
	if err := r.k.Extend(3, mail, "t1"); err == nil {
		t.Fatal("another clerk's key cannot extend a model hold")
	}
	if _, ok := r.k.State().SpendHeld["t1"]; !ok {
		t.Fatal("refused extensions must leave the hold")
	}
}

func TestHoldOnlyForSpendRefusals(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(10))
	if err := r.k.Hold(1, k, "t1", &key.Refusal{Code: key.RExpired}); err == nil {
		t.Fatal("only an exhausted spend cap holds a task")
	}
	if err := r.k.Hold(1, k, "t1", nil); err == nil {
		t.Fatal("a hold needs the refusal that caused it")
	}
}

func TestHoldAndExtensionSurviveReplay(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, key.LimitSpendTask(10))
	env := envelope(r, 500, 800)
	exhaust(r, k, "t1", 10)
	exhaust(r, k, "t2", 10)
	must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(5)), "t2"))
	r.boot(4)
	held := r.k.State().SpendHeld
	if _, ok := held["t1"]; !ok || len(held) != 1 {
		t.Fatalf("replayed holds: %v", held)
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
	if rf := r.k.AdmitPool(10_000, "codex-5h"); rf != nil {
		t.Fatalf("reset time is the cooldown: %v", rf)
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
