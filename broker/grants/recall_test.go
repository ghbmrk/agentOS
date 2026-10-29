package grants

// REQ: CAP-3, OP-5

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/reversible"
)

type recordExec struct{ ran []string }

func (e *recordExec) Execute(_ context.Context, in journal.Intent, _ int) journal.Outcome {
	e.ran = append(e.ran, in.ID)
	return journal.Outcome{Result: journal.ResultSucceeded}
}

func (e *recordExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultNotApplied}
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

// LOG-4, D-169 (#3704): an agent that read content the owner had the box
// forget goes back, and what it asked for since that still waits, for the
// owner or in its undo window, is closed: a held one's staged copy goes,
// and a later YES or release runs nothing. Its asks from before the read,
// and other agents', are kept.
func TestVoidSinceClosesWhatAReaderQueued(t *testing.T) {
	r := newRig(t, withForms(map[string]reversible.Form{"invoice.send": {Stage: "draft.save", Inverse: "draft.discard"}}))
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	send := func(id string) {
		r.effect(id, "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
		r.g.Flush()
	}
	send("agent/before")
	r.submit(journal.Intent{ID: "other/s1", Origin: "guest:other", Account: "mail", Action: "invoice.send",
		Params: map[string]any{"record": "inv-1042"}, Recipients: []string{"sam@example.com"}, Executor: "mail", Machine: "other", Label: "private"})
	r.g.Flush()
	r.advance(time.Minute)
	read := r.now()
	send("agent/held")
	r.approveHeld()
	send("agent/asked")
	voided, err := r.g.VoidSince("agent", read)
	if err != nil || !slices.Equal(voided, []string{"agent/held", "agent/asked"}) {
		t.Fatalf("voided %v %v", voided, err)
	}
	for _, id := range voided {
		if st := r.state(id); st.State != journal.Denied || st.Permission.Reason != "not approved: "+string(Forgotten) {
			t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
		}
	}
	if st := r.state(reversible.InverseID("agent/held", 1)); st.State != journal.Succeeded {
		t.Fatalf("staged copy left: %s", st.State)
	}
	r.decide(true, "owner")
	r.advance(reversible.DefaultWindow)
	r.g.Tick()
	r.g.Wait()
	if r.exec.runs("agent/held")+r.exec.runs("agent/asked") != 0 {
		t.Fatal("a voided intent ran")
	}
	for _, id := range []string{"agent/before", "other/s1"} {
		if st := r.state(id); st.State != journal.Pending {
			t.Fatalf("%s: %s", id, st.State)
		}
	}
}
