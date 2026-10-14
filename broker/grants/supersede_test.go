package grants

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2

// B6 at the gate: the send of invoice 1042 to sam is proved not done
// after a restart and its resend refused (the approval lived in memory),
// so RETRY offers it. Before the owner answers, the agent resubmits the
// same send, the owner approves that and it goes. The send is then no
// longer offered, and the owner's approval of the RETRY line already
// shown is refused and spent: invoice 1042 goes once.
func TestOP2NotDoneSendIsNotResentAfterAResubmissionWent(t *testing.T) {
	ctx := context.Background()
	r := killedSend(t, true)
	ns := r.eng.NotResent()
	if len(ns) != 1 || ns[0].Intent.ID != "agent/s1" {
		t.Fatalf("not resent %+v", ns)
	}
	l := r.g.RetryItem(ctx, ns[0], "an email")

	if st := r.effect("agent/s2", "invoice.send", map[string]any{"record": "inv-1042", "template": "invoice"}, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("resubmit: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	req, _ := r.own.last(t)
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
	deadline := time.Now().Add(5 * time.Second)
	for r.state("agent/s2").State != journal.Succeeded {
		if time.Now().After(deadline) {
			t.Fatalf("s2: %+v", r.state("agent/s2"))
		}
		time.Sleep(time.Millisecond)
	}
	if ns := r.eng.NotResent(); len(ns) != 0 {
		t.Fatalf("still offered after the resubmission went: %+v", ns)
	}
	_, err := r.g.Resend(ctx, "agent/s1", ns[0].Attempt, l, false)
	var se *journal.SupersededError
	if !errors.As(err, &se) || se.By != "agent/s2" || !errors.Is(err, journal.ErrState) {
		t.Fatalf("resend: %v", err)
	}
	if r.exec.runs("agent/s1") != 0 || r.exec.runs("agent/s2") != 1 {
		t.Fatalf("invoice 1042 sent: s1 %d, s2 %d", r.exec.runs("agent/s1"), r.exec.runs("agent/s2"))
	}
	r.g.mu.Lock()
	_, left := r.g.decided["agent/s1"]
	r.g.mu.Unlock()
	if left {
		t.Fatal("the refused resend's approval was not spent")
	}
}
