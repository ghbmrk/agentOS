package grants

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: OP2-ER-1, OP2-ER-2, OP-2, CH-10

// #1433 R26/U26: an erased send keeps its recipients (CAP-3), so it is a
// repeat only of a send to the same recipients. Another record to another
// person under the pre-allowance goes unasked after an erase.
func TestAnErasedSendToOtherRecipientsIsNotARepeat(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	x := sam()
	x.Record = "inv-2000"
	r.ver.set("inv-2000", x)
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	if er, _, err := r.eng.Erase([]string{"agent/s1"}); err != nil || len(er) != 1 {
		t.Fatalf("erase: %v %v", er, err)
	}
	q := len(r.own.queued)
	if st := r.effect("agent/s2", "invoice.send", invoice("inv-2000"), "lee@example.com"); st.State != journal.Succeeded || len(r.own.queued) != q {
		t.Fatalf("s2 to lee: %s %q, asked %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
	// Case is folded, as sendID compares recipients: the same person is
	// still asked.
	it := askedRepeat(t, r, "agent/s3", "inv-2000", "SAM@example.com")
	if it.Sent.IsZero() || !it.SentErased {
		t.Fatalf("s3 to SAM: %+v, want it marked as maybe repeating the erased send", it)
	}
}

// OP2-ER-2: when every known success behind the mark was erased, the ask
// says so (SentErased), since "already sent" names a record and
// recipient the broker can no longer check. A kept match says "already
// sent", erased one or not beside it.
func TestAnErasedOnlyRepeatIsMarkedErased(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	const to = "sam@example.com"
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), to); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	went := r.state("agent/s1").Attempts[0].Dispatched
	if er, _, err := r.eng.Erase([]string{"agent/s1"}); err != nil || len(er) != 1 {
		t.Fatalf("erase: %v %v", er, err)
	}
	it := askedRepeat(t, r, "agent/s2", "inv-1042", to)
	if !it.Sent.Equal(went) || !it.SentErased {
		t.Fatalf("erased only: %+v, want Sent %v and SentErased", it, went)
	}
	r.decide(true, "owner")
	if st := r.state("agent/s2"); st.State != journal.Succeeded {
		t.Fatalf("s2 approved: %s", st.State)
	}
	// s2 is kept: the next repeat was already sent.
	it = askedRepeat(t, r, "agent/s3", "inv-1042", to)
	if it.Sent.IsZero() || it.SentErased {
		t.Fatalf("kept match: %+v, want Sent without SentErased", it)
	}
}

// REQ: OP2-ER-1
// An erased send whose intent named its recipient twice still matches a
// later send to that one person: the mail adapter sent it once (#2178).
func TestAnErasedSendWithARepeatedRecipientIsStillARepeat(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"}, AmountCap: 100000, PerRecord: 20, PerDay: 50, HoldDays: 7}})
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com", "SAM@example.com")
	r.g.Flush()
	r.decide(true, "owner")
	if st, _ := r.eng.Get("agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s", st.State)
	}
	r.eng.Erase([]string{"agent/s1"})
	if st := r.effect("agent/s2", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State == journal.Succeeded {
		t.Fatal("s2 went unasked after an erased send to the same person")
	}
}
