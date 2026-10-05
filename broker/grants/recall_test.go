package grants

// REQ: CAP-3, OP-5

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

type recordExec struct{ ran []string }

func (e *recordExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	e.ran = append(e.ran, in.ID)
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (e *recordExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied}
}

// recalltool W10: the broker's recall rollback is asked of the owner with
// the broker's line and runs only on YES; no other origin can submit one.
func TestRecallRollbackRunsOnlyOnTheOwnersYes(t *testing.T) {
	ex := &recordExec{}
	r := newRigExecs(t, nil, map[string]journal.Executor{RecallExecutor: ex})
	rollback := func(id, origin string) journal.Intent {
		return journal.Intent{ID: id, Origin: origin, Account: journal.BrokerAccount,
			Action: journal.ActionRecallRollback, Executor: RecallExecutor,
			Params: map[string]any{"lineage": "agent.x", "since": "2026-10-05T09:00:00Z",
				"object": "a mail you deleted from agent", "detail": "back to 08:12 Oct 5; 2 actions stay done"}}
	}
	for _, origin := range []string{"guest:agent.x", OriginOwner, "local"} {
		if st := r.submit(rollback("rb-"+origin, origin)); st.State != journal.Denied {
			t.Fatalf("rollback from %s: %s", origin, st.State)
		}
	}
	if st := r.submit(rollback("rb-1", OriginRecall)); st.State != journal.Pending {
		t.Fatalf("broker rollback not asked: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Facts.Verb != "forget" || items[0].Object != "a mail you deleted from agent" ||
		items[0].Detail == "" || items[0].Recipient != "" {
		t.Fatalf("approval line: %+v", items)
	}
	if len(ex.ran) != 0 {
		t.Fatal("ran before the owner answered")
	}
	r.decide(true, "owner")
	if len(ex.ran) != 1 || r.state("rb-1").State != journal.Succeeded {
		t.Fatalf("after YES: ran %v, %s", ex.ran, r.state("rb-1").State)
	}
	if st := r.submit(rollback("rb-2", OriginRecall)); st.State != journal.Pending {
		t.Fatal(st.State)
	}
	r.g.Flush()
	r.decide(false, "owner")
	if len(ex.ran) != 1 || r.state("rb-2").State != journal.Denied {
		t.Fatalf("after NO: ran %v, %s", ex.ran, r.state("rb-2").State)
	}
	// recalltool tells the owner's NO from no answer by this reason.
	if why := r.state("rb-2").Permission.Reason; why != "not approved: owner" {
		t.Fatalf("NO recorded as %q", why)
	}
}

// recalltool W10, #59 security C2: a lineage that still holds a record
// the owner deleted gets no pre-allowance; the same send is asked.
func TestContainedLineageGetsNoPreAllowance(t *testing.T) {
	held := map[string]bool{"agent": true}
	r := newRig(t, func(c *Config) { c.Contained = func(l string) bool { return held[l] } })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 1, PerDay: 3, HoldDays: 7}})
	r.ver.set("inv-1042", sam())
	p := map[string]any{"template": "invoice", "record": "inv-1042"}
	if st := r.effect("agent/held", "invoice.send", p, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("contained lineage: %s %q", st.State, st.Permission.Reason)
	}
	delete(held, "agent")
	if st := r.effect("agent/free", "invoice.send", p, "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("after release: %s %q", st.State, st.Permission.Reason)
	}
}

// recalltool W10 (#59 L3): a rollback question superseded by an earlier
// one is withdrawn: closed as superseded, and a later YES runs nothing.
// Nothing else can be withdrawn.
func TestRecallRollbackCanBeWithdrawn(t *testing.T) {
	ex := &recordExec{}
	r := newRigExecs(t, nil, map[string]journal.Executor{RecallExecutor: ex})
	in := journal.Intent{ID: "rb", Origin: OriginRecall, Account: journal.BrokerAccount,
		Action: journal.ActionRecallRollback, Executor: RecallExecutor,
		Params: map[string]any{"lineage": "agent.x", "since": "2026-10-05T09:00:00Z",
			"object": "a mail you deleted from agent", "detail": "back to 08:12 Oct 5; 2 actions stay done"}}
	if st := r.submit(in); st.State != journal.Pending {
		t.Fatal(st.State)
	}
	r.g.Flush()
	if err := r.g.Withdraw("rb"); err != nil {
		t.Fatal(err)
	}
	if st := r.state("rb"); st.State != journal.Denied || st.Permission.Reason != "not approved: superseded" {
		t.Fatalf("withdrawn: %s %q", st.State, st.Permission.Reason)
	}
	r.decide(true, "owner")
	if len(ex.ran) != 0 {
		t.Fatal("a withdrawn rollback ran")
	}
	other := in
	other.ID, other.Origin = "o", "guest:agent.x"
	r.submit(other)
	if err := r.g.Withdraw("o"); err == nil {
		t.Fatal("withdrew an intent that is not a recall rollback")
	}
}
