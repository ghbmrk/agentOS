package grants

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2, CH-10, ADP-9

// toVerifier reads a record as fakeVerifier does, with the recipients
// the intent names (as a mail account's verifier reads a draft's), so
// the same record can go to different recipients.
type toVerifier struct{ *fakeVerifier }

func (v toVerifier) Verify(ctx context.Context, in journal.Intent) (Verified, error) {
	x, err := v.fakeVerifier.Verify(ctx, in)
	if err != nil {
		return x, err
	}
	x.Recipients = append([]string(nil), in.Recipients...)
	x.Item.Recipient = strings.Join(in.Recipients, ", ")
	return x, nil
}

// repeatRig pre-allows sending invoices (ADP-9), with rec's verified
// record, to any recipient the intent names.
func repeatRig(t *testing.T, rec string, x Verified) *rig {
	t.Helper()
	r := newRig(t, func(c *Config) { c.Verifiers["mail"] = toVerifier{c.Verifiers["mail"].(*fakeVerifier)} })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 100000, PerRecord: 20, PerDay: 50, HoldDays: 7}})
	x.Record = rec
	r.ver.set(rec, x)
	return r
}

func invoice(rec string) map[string]any { return map[string]any{"record": rec, "template": "invoice"} }

// askedRepeat submits id, which must wait for the owner, and returns the
// line the owner was asked.
func askedRepeat(t *testing.T, r *rig, id, rec, to string) owner.Item {
	t.Helper()
	if st := r.effect(id, "invoice.send", invoice(rec), to); st.State != journal.Pending {
		t.Fatalf("%s: %s %q, want it asked", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Ref != id {
		t.Fatalf("%s: asked %+v", id, items)
	}
	return items[0]
}

// Confirm repeats (Mark, D-116, 2026-10-14): a pre-allowed send that
// repeats one known to have gone in the last 24 hours (same record, same
// recipients, same action) is asked of the owner instead of sent unseen.
// The ask says it was already sent and when, at the tier its facts give;
// declined or never answered it does not go, approved it goes. A repeat
// more than 24 hours after the success, or to other recipients, is not
// asked.
func TestConfirmRepeatsAPreAllowedSend(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	const to = "sam@example.com"
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), to); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	// Past the window, the same send goes unasked.
	r.advance(24*time.Hour + time.Minute)
	if st := r.effect("agent/s2", "invoice.send", invoice("inv-1042"), to); st.State != journal.Succeeded {
		t.Fatalf("s2 a day later: %s %q", st.State, st.Permission.Reason)
	}
	s2 := r.state("agent/s2").Attempts[0].Dispatched
	// Within it, it is asked, marked with when the send went.
	r.advance(24*time.Hour - time.Minute)
	it := askedRepeat(t, r, "agent/s3", "inv-1042", to)
	if !it.Sent.Equal(s2) || !it.Retried.IsZero() {
		t.Fatalf("s3's ask %+v, want it marked sent at %v", it, s2)
	}
	// $120 to a contact the owner made, under the owner's $500 limit:
	// low risk, a texted code (CH-10), not raised.
	if it.Facts.Kind == owner.MoneyRetry || r.own.Tier(it.Facts) != owner.Low {
		t.Fatalf("s3's tier: kind %v, tier %v", it.Facts.Kind, r.own.Tier(it.Facts))
	}
	r.decide(false, "owner")
	if st := r.state("agent/s3"); st.State != journal.Denied || r.exec.runs("agent/s3") != 0 {
		t.Fatalf("declined repeat: %s, ran %d", st.State, r.exec.runs("agent/s3"))
	}
	askedRepeat(t, r, "agent/s4", "inv-1042", to)
	r.decide(false, "expired")
	if st := r.state("agent/s4"); st.State != journal.Denied || r.exec.runs("agent/s4") != 0 {
		t.Fatalf("unanswered repeat: %s, ran %d", st.State, r.exec.runs("agent/s4"))
	}
	askedRepeat(t, r, "agent/s5", "inv-1042", to)
	r.decide(true, "owner")
	if st := r.state("agent/s5"); st.State != journal.Succeeded || r.exec.runs("agent/s5") != 1 {
		t.Fatalf("confirmed repeat: %s, ran %d", st.State, r.exec.runs("agent/s5"))
	}
	// With two sends in the window that went, the ask names the first.
	if it := askedRepeat(t, r, "agent/s8", "inv-1042", to); !it.Sent.Equal(s2) {
		t.Fatalf("s8's ask %+v, want it marked sent at %v (s2, the first in the window)", it, s2)
	}
	r.decide(false, "owner")
	// The same record to another recipient is another send.
	if st := r.effect("agent/s6", "invoice.send", invoice("inv-1042"), "bob@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s6 to bob: %s %q", st.State, st.Permission.Reason)
	}
	// Another record to the same recipient is too.
	x := sam()
	x.Record = "inv-1043"
	r.ver.set("inv-1043", x)
	if st := r.effect("agent/s7", "invoice.send", invoice("inv-1043"), to); st.State != journal.Succeeded {
		t.Fatalf("s7: %s %q", st.State, st.Permission.Reason)
	}
	for _, id := range []string{"agent/s1", "agent/s2", "agent/s5", "agent/s6", "agent/s7"} {
		if n := r.exec.runs(id); n != 1 {
			t.Fatalf("%s ran %d times", id, n)
		}
	}
}

// A repeat of money above the owner-set limit takes the code generator,
// as CH-10 gives it; it is not raised past that.
func TestConfirmRepeatsMoneyAboveTheLimitTakesTheCodeGenerator(t *testing.T) {
	x := sam()
	x.Item.Amount, x.Item.Facts.Amount = "$600.00", 60000
	r := repeatRig(t, "inv-big", x)
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-big"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	it := askedRepeat(t, r, "agent/s2", "inv-big", "sam@example.com")
	if it.Sent.IsZero() || it.Facts.Kind == owner.MoneyRetry || r.own.Tier(it.Facts) != owner.High {
		t.Fatalf("s2's ask %+v, tier %v", it, r.own.Tier(it.Facts))
	}
}

// An identical auto-reply in the same thread is a repeat too (ADP-11):
// asked, not queued. A reply to another message that says something new
// is not (another reply to the same message is, whatever its body:
// TestARewordedAutoReplyToTheSameMessageIsAsked).
func TestConfirmRepeatsAPreAllowedIdenticalReply(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Isolated = func(m string) bool { return m == "reply-1" } })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	for _, rec := range []string{"thr-1", "thr-2"} {
		r.ver.set(rec, Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
			Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
			Recipients: []string{"sam@example.com"}, Record: rec, ThreadVerified: true})
	}
	reply := func(id, rec, body string) journal.Status {
		return r.submit(journal.Intent{ID: id, Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
			Params: map[string]any{"record": rec, "body": body}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	}
	reply("reply-1/r1", "thr-1", "Thanks, got it.")
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("reply-1/r1"); st.State != journal.Succeeded {
		t.Fatalf("r1: %s", st.State)
	}
	went := r.state("reply-1/r1").Attempts[0].Dispatched
	queued := len(r.own.queued)
	if st := reply("reply-1/r2", "thr-1", "Thanks, got it."); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" || len(r.own.queued) != queued {
		t.Fatalf("identical reply: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-queued)
	}
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || items[0].Ref != "reply-1/r2" || !items[0].Sent.Equal(went) {
		t.Fatalf("identical reply asked %+v", items)
	}
	if st := reply("reply-1/r3", "thr-2", "And the second file, thanks."); st.State != journal.Pending || len(r.own.queued) != queued+1 {
		t.Fatalf("new reply: %s %q", st.State, st.Permission.Reason)
	}
}

// A send that may have gone (unknown after a restart) marks a request
// for the same send "may go twice", with when it was first tried, and
// raises money to the code generator; a pre-allowed one is asked too.
func TestARepeatOfASendThatMayHaveGoneIsMarkedAndAsked(t *testing.T) {
	r := killedSend(t, false)
	st := r.state("agent/s1")
	if st.State != journal.OutcomeUnknown {
		t.Fatalf("s1: %+v", st)
	}
	first := st.Attempts[0].Dispatched
	r.advance(2 * time.Hour)
	it := askedRepeat(t, r, "agent/s2", "inv-1042", "sam@example.com")
	if !it.Retried.Equal(first) || !it.Sent.IsZero() || it.Facts.Kind != owner.MoneyRetry || r.own.Tier(it.Facts) != owner.High {
		t.Fatalf("s2's ask %+v, want it marked tried at %v and high", it, first)
	}
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 20, PerDay: 50, HoldDays: 7}})
	if it := askedRepeat(t, r, "agent/s3", "inv-1042", "sam@example.com"); !it.Retried.Equal(first) {
		t.Fatalf("pre-allowed s3's ask %+v", it)
	}
	if r.exec.runs("agent/s2") != 0 || r.exec.runs("agent/s3") != 0 {
		t.Fatal("a repeat went unasked")
	}
}

// A restart re-issues a repeat's ask with its mark.
func TestARepeatsAskKeepsItsMarkOverARestart(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	went := r.state("agent/s1").Attempts[0].Dispatched
	it := askedRepeat(t, r, "agent/s2", "inv-1042", "sam@example.com")
	req, _ := r.own.last(t)
	r.boot = []owner.Carried{{Ref: "agent/s2", Request: req, Asked: r.now(), Expires: r.now().Add(10 * time.Minute), Sum: owner.ItemSum(it)}}
	r.open()
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || items[0].Ref != "agent/s2" || !items[0].Sent.Equal(went) {
		t.Fatalf("re-issued %+v", items)
	}
}
