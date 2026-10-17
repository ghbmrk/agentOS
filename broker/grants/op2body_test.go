package grants

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP-2, ADP-9, ADP-11, OP2-IB-1

// OP2-IB-1 (#1677, Security R25 and L21 on #1433): SPEC OP-2 defines an
// identical repeat as the same record to the same recipients by the same
// action, with no body. A send of the same record within 24 hours of one
// known to have gone is asked marked already sent, and when, even when
// its body is reworded. (A body is carried only under an auto-reply rule,
// so a pre-allowance without one asks this send anyway: the mark is what
// tells the owner it is a repeat.)
func TestARewordedSendOfTheSameRecordIsMarkedSent(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	const to = "sam@example.com"
	params := func(body string) map[string]any {
		p := invoice("inv-1042")
		p[ParamBody] = body
		return p
	}
	r.effect("agent/s1", "invoice.send", params("Invoice 1042 attached."), to)
	r.g.Flush()
	r.decide(true, "owner")
	st := r.state("agent/s1")
	if st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	went := st.Attempts[0].Dispatched
	if st := r.effect("agent/s2", "invoice.send", params("Please find invoice 1042 attached."), to); st.State != journal.Pending {
		t.Fatalf("s2: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || items[0].Ref != "agent/s2" || !items[0].Sent.Equal(went) {
		t.Fatalf("s2 asked %+v, want it marked sent at %v", items, went)
	}
}

// OP2-IB-1 under an auto-reply rule (ADP-11): a reply to the same message
// that says something new, within 24 hours of a reply known to have gone,
// is asked, not queued to go unseen.
func TestARewordedAutoReplyToTheSameMessageIsAsked(t *testing.T) {
	r, reply, went := sentReply(t)
	q := len(r.own.queued)
	if st := reply("reply-1/r2", "thr-1", "And the second file."); st.State != journal.Pending || len(r.own.queued) != q {
		t.Fatalf("r2: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || items[0].Ref != "reply-1/r2" || !items[0].Sent.Equal(went) {
		t.Fatalf("r2 asked %+v, want it marked sent at %v", items, went)
	}
}
