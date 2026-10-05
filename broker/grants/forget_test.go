package grants

// REQ: CAP-3, OP-5

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
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
