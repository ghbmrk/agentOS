package grants

// REQ: CAP-3, OP-5

import (
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// W3-forget: the owner's forget of a task is asked of the owner with the
// box's own line for it, looked up by goal, and runs only on YES. Only the
// broker's forget origin may submit one, and the journal carries only the
// goal ID: the task's text comes from ForgetItem at ask time.
func TestAForgetIsAskedWithTheBoxsLineAndRunsOnlyOnYes(t *testing.T) {
	ex := &recordExec{}
	tasks := map[string][2]string{"g1": {`"book a table for fri…"`, "undoes 2 things I learned"}}
	r := newRigExecs(t, func(c *Config) {
		c.ForgetItem = func(goal string) (string, string, bool) {
			t, ok := tasks[goal]
			return t[0], t[1], ok
		}
	}, map[string]journal.Executor{ForgetExecutor: ex})
	forget := func(id, origin, goal string) journal.Intent {
		return journal.Intent{ID: ForgetID(id, goal), Origin: origin, Account: journal.BrokerAccount,
			Action: journal.ActionLearnForget, Executor: ForgetExecutor}
	}
	for _, origin := range []string{"guest:agent.x", OriginOwner, OriginLoop2, OriginRecall, "local"} {
		if st := r.submit(forget("f-"+origin, origin, "g1")); st.State != journal.Denied {
			t.Fatalf("forget from %s: %s", origin, st.State)
		}
	}
	if st := r.submit(forget("f-none", OriginForget, "g9")); st.State != journal.Denied {
		t.Fatalf("forget of an unknown task: %s", st.State)
	}
	if st := r.submit(forget("f-1", OriginForget, "g1")); st.State != journal.Pending {
		t.Fatalf("forget not asked: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Facts.Verb != "forget" || !items[0].Facts.NoRecipient ||
		items[0].Object != `"book a table for fri…"` || items[0].Detail != "undoes 2 things I learned" || items[0].Recipient != "" {
		t.Fatalf("approval line: %+v", items)
	}
	if len(ex.ran) != 0 {
		t.Fatal("ran before the owner answered")
	}
	r.decide(true, "owner")
	if len(ex.ran) != 1 || r.state(ForgetID("f-1", "g1")).State != journal.Succeeded {
		t.Fatalf("after YES: ran %v, %s", ex.ran, r.state(ForgetID("f-1", "g1")).State)
	}
	if st := r.submit(forget("f-2", OriginForget, "g1")); st.State != journal.Pending {
		t.Fatal(st.State)
	}
	r.g.Flush()
	r.decide(false, "owner")
	if len(ex.ran) != 1 || r.state(ForgetID("f-2", "g1")).State != journal.Denied {
		t.Fatalf("after NO: ran %v, %s", ex.ran, r.state(ForgetID("f-2", "g1")).State)
	}
}

// W3-forget-b2b: taking back the agent's work since a forgotten task is
// the same request's item 2, on the same tier and verb, with the box's
// own line for it; only the broker's forget origin may submit it.
func TestAForgetsAgentTakeBackIsItem2OfTheSameRequest(t *testing.T) {
	ex := &recordExec{}
	r := newRigExecs(t, func(c *Config) {
		c.ForgetItem = func(goal string) (string, string, bool) { return `"pay the gas bill"`, "", goal == "g1" }
		c.ForgetAgentItem = func(goal string) (string, string, bool) {
			return "your agent's work since today 13:02", "", goal == "g1"
		}
	}, map[string]journal.Executor{ForgetExecutor: ex})
	agent := func(nonce, origin, goal string) journal.Intent {
		return journal.Intent{ID: ForgetAgentID(nonce, goal), Origin: origin, Account: journal.BrokerAccount,
			Action: journal.ActionLearnForget, Executor: ForgetExecutor}
	}
	if ForgetGoal(ForgetAgentID("n", "g1")) != "" || ForgetAgentGoal(ForgetID("n", "g1")) != "" || ForgetAgentGoal(ForgetAgentID("n", "g1")) != "g1" {
		t.Fatal("item 1 and item 2 IDs must not parse as each other")
	}
	if ForgetSibling(ForgetAgentID("n", "g1")) != ForgetID("n", "g1") || ForgetSibling(ForgetID("n", "g1")) != ForgetAgentID("n", "g1") {
		t.Fatal("siblings")
	}
	for _, origin := range []string{"guest:agent.x", OriginOwner, OriginRecall} {
		if st := r.submit(agent("a-"+origin, origin, "g1")); st.State != journal.Denied {
			t.Fatalf("take-back from %s: %s", origin, st.State)
		}
	}
	if st := r.submit(agent("a-none", OriginForget, "g9")); st.State != journal.Denied {
		t.Fatalf("take-back for an unknown task: %s", st.State)
	}
	in1 := journal.Intent{ID: ForgetID("n1", "g1"), Origin: OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: ForgetExecutor}
	if st := r.submit(in1); st.State != journal.Pending {
		t.Fatal(st.State)
	}
	if st := r.submit(agent("n1", OriginForget, "g1")); st.State != journal.Pending {
		t.Fatalf("take-back not asked: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 2 || items[0].Ref != in1.ID || items[1].Ref != ForgetAgentID("n1", "g1") ||
		items[1].Object != "your agent's work since today 13:02" || items[1].Facts != items[0].Facts {
		t.Fatalf("one request, forget then take-back: %+v", items)
	}
}

// #327 L3 B-1 (OP-3 at re-issue, CAP-3): item 2's detail, the actions so
// far, is the one fixed when it was asked, carried in the intent; the live
// count moving (the agent acting while the owner reads, or not known after
// a restart) neither changes the line nor closes item 2 at re-issue,
// which would leave item 1 asked alone.
func TestAForgetsTakeBackDetailIsFixedWhenAsked(t *testing.T) {
	live := "1 action so far stays done"
	ex := &recordExec{}
	r := newRigExecs(t, func(c *Config) {
		c.ForgetItem = func(goal string) (string, string, bool) { return `"pay the gas bill"`, "", goal == "g1" }
		c.ForgetAgentItem = func(goal string) (string, string, bool) {
			return "your agent's work since today 13:02", live, goal == "g1"
		}
	}, map[string]journal.Executor{ForgetExecutor: ex})
	in1 := journal.Intent{ID: ForgetID("n1", "g1"), Origin: OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: ForgetExecutor}
	in2 := journal.Intent{ID: ForgetAgentID("n1", "g1"), Origin: OriginForget, Account: journal.BrokerAccount,
		Action: journal.ActionLearnForget, Executor: ForgetExecutor,
		Params: map[string]any{"agent": true, "actions": 2}}
	for _, in := range []journal.Intent{in1, in2} {
		if st := r.submit(in); st.State != journal.Pending {
			t.Fatalf("%s: %s %q", in.ID, st.State, st.Permission.Reason)
		}
	}
	r.g.Flush()
	req, items := r.own.last(t)
	if len(items) != 2 || items[1].Detail != "2 actions so far stay done" {
		t.Fatalf("item 2's line: %+v", items)
	}
	asked := r.now()
	var boot []owner.Carried
	for _, it := range items {
		boot = append(boot, owner.Carried{Ref: it.Ref, Request: req, Asked: asked, Expires: asked.Add(15 * time.Minute), Sum: owner.ItemSum(it)})
	}
	live = "no actions yet" // the count after a restart, recall not open yet
	r.advance(time.Minute)
	r.boot = boot
	r.open()
	r.g.Tick()
	r.g.Flush()
	for _, id := range []string{in1.ID, in2.ID} {
		if st := r.state(id); st.State != journal.Pending {
			t.Fatalf("%s at re-issue: %s %q", id, st.State, st.Permission.Reason)
		}
	}
}
