package kernel_test

// REQ: KRN-6, LOG-7

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// An owner call decides on its keys as the log will hold them. A key whose
// link is not valid UTF-8 verifies in-process, but the log's JSON rewrites
// the link and its signature then fails, so Issue and Extend refuse it and
// log nothing: the live decision and the folded one agree (KRN-6). Catches
// a call that returns success while its entry folds to nothing (#4322).
func TestOwnerCallsDecideOnTheLoggedKey(t *testing.T) {
	t.Run("Issue", func(t *testing.T) {
		r := newRig(t)
		root := key.Issue(r.owner.pass, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "u"})
		ck, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 10, key.LimitLabels("l\xff"))
		must(t, err)
		rewritten(t, ck)
		n := len(r.k.Log().Entries())
		if err := r.issue(1, root, ck); err == nil {
			t.Fatal("a grant the log cannot hold as signed was issued")
		}
		if got := len(r.k.Log().Entries()); got != n {
			t.Fatalf("a refused Issue logged %d entries", got-n)
		}
		if _, ok := r.k.State().Grants[ck.Tip()]; ok {
			t.Fatal("the refused clerk key is granted")
		}
		// the same batch in valid UTF-8 is issued
		ok, err := key.ClerkKey(root, r.owner.pass, r.holder.pub, 0, 10, key.LimitLabels("l"))
		must(t, err)
		must(t, r.issue(1, root, ok))
		r.replays()
	})
	t.Run("Extend", func(t *testing.T) {
		r := newRig(t)
		modelPlan(r, "t1", modelKey(r, "m1", key.LimitSpendTask(100)))
		env := envelope(r, 500, 800)
		exhaust(r, "t1", 100)
		ext := extension(r, env, key.LimitSpendTask(300), key.LimitLabels("l\xff"))
		rewritten(t, ext)
		n := len(r.k.Log().Entries())
		var rf *key.Refusal
		if err := r.k.Extend(3, ext, "t1"); !errors.As(err, &rf) || rf.Code != kernel.CKey {
			t.Fatalf("an extension the log cannot hold as signed: %v", err)
		}
		if got := len(r.k.Log().Entries()); got != n {
			t.Fatalf("a refused Extend logged %d entries", got-n)
		}
		if _, held := r.k.State().SpendHeld["t1"]; !held {
			t.Fatal("a refused extension released the hold")
		}
		must(t, r.k.Extend(3, extension(r, env, key.LimitSpendTask(300), key.LimitLabels("l")), "t1"))
		if rf := r.admit(4, "t1", 1); rf != nil {
			t.Fatalf("the valid extension funds nothing: %v", rf)
		}
		r.replays()
	})
}

// rewritten checks that the log's JSON changes k, so the test exercises a
// key whose logged form differs from the one given.
func rewritten(t *testing.T, k key.Key) {
	t.Helper()
	var logged key.Key
	b, err := json.Marshal(k)
	must(t, err)
	must(t, json.Unmarshal(b, &logged))
	if logged.Tip() == k.Tip() {
		t.Fatal("the log's JSON should rewrite the key's link")
	}
}

// A spend.held entry folds only for an active plan, as funding admits only
// one (Hold refuses the rest): a hold logged past the kernel for a pending
// or ended plan takes no hold, so no later Extend or honey-key trip acts on
// a hold with no scope (LOG-7, KRN-6). Catches the fold taking a hold the
// live call would refuse (#4321).
func TestSpendHeldFoldsOnlyForAnActivePlan(t *testing.T) {
	r := newRig(t)
	k := modelKey(r, "m1", key.LimitSpendTask(100))
	modelPlan(r, "live", k)
	modelPlan(r, "ended", k)
	must(t, r.k.Cancel(1, "ended"))
	if err := r.k.Hold(2, "ended", &key.Refusal{Code: key.RSpendTask}); err == nil {
		t.Fatal("Hold took an ended plan")
	}
	pending, err := json.Marshal(r.sign(kernel.Plan{ID: "pending", Key: k,
		Steps: []kernel.PlanStep{{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}))
	must(t, err)
	es := r.k.Log().Entries()
	l := es[len(es)-1]
	add := func(typ string, body string) {
		l = kernel.Entry{Seq: l.Seq + 1, At: l.At, Type: typ, V: 1, Body: json.RawMessage(body)}
		es = append(es, l)
	}
	add(kernel.TPlanSubmit, string(pending))
	for _, p := range []string{"pending", "ended", "live", "unknown"} {
		add(kernel.TSpendHeld, `{"plan":"`+p+`","code":"spend-task"}`)
	}
	re, err := kernel.Replay(r.anchors(), es)
	must(t, err)
	if re.Plans["pending"] == nil || re.Plans["pending"].Status != kernel.SPending {
		t.Fatal("the forged plan should fold as pending")
	}
	var held []string
	for p := range re.SpendHeld {
		held = append(held, p)
	}
	if !slices.Equal(held, []string{"live"}) {
		t.Fatalf("holds folded for %v, want only the active plan", held)
	}
}
