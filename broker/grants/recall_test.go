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
				"object": "agent work since 09:00 Oct 5", "detail": "2 actions since it read a mail you deleted"}}
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
	if len(items) != 1 || items[0].Facts.Verb != "undo" || items[0].Object != "agent work since 09:00 Oct 5" ||
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
}
