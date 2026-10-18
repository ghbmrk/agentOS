package grants

import (
	"context"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-2, OP-3, CH-10, ADP-9, ADP-11, CAP-3

// replyRig is an ADP-11 reply rule on a composer machine, with thr-1 and
// thr-2 verified replies to sam in one thread (thread), and thr-9 in
// another; reply submits one and lets the undo window decide nothing.
func replyRig(t *testing.T) (*rig, func(id, rec, body string) journal.Status) {
	t.Helper()
	r := newRig(t, func(c *Config) { c.Isolated = func(m string) bool { return m == "reply-1" } })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	for rec, thread := range map[string][]string{
		"thr-1": {"thr-1", "root"},
		"thr-2": {"thr-2", "root", "thr-1"},
		"thr-9": {"thr-9", "other-root"},
	} {
		r.ver.set(rec, Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
			Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
			Recipients: []string{"sam@example.com"}, Record: rec, ThreadVerified: true, Thread: thread})
	}
	reply := func(id, rec, body string) journal.Status {
		return r.submit(journal.Intent{ID: id, Origin: "guest:reply-1", Machine: "reply-1", Account: "mail", Action: "message.send",
			Params: map[string]any{"record": rec, "body": body}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	}
	return r, reply
}

// sentReply leaves reply-1/r1, "Thanks, got it." on thr-1, sent by its
// undo window passing, and returns when it went.
func sentReply(t *testing.T) (*rig, func(id, rec, body string) journal.Status, time.Time) {
	t.Helper()
	r, reply := replyRig(t)
	reply("reply-1/r1", "thr-1", "Thanks, got it.")
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	st := r.state("reply-1/r1")
	if st.State != journal.Succeeded {
		t.Fatalf("r1: %s", st.State)
	}
	return r, reply, st.Attempts[0].Dispatched
}

// Security B10 on #1433 (probe TestZZSec8TwoQueuedIdenticalAutoReplies):
// two identical auto-replies queued a minute apart, before either went.
// The first goes when its undo window passes; the second's window passing
// is no confirmation of a repeat (D-116), so it does not go: the owner is
// asked, told it was already sent.
func TestAnAutoReplysUndoWindowNeverConfirmsARepeat(t *testing.T) {
	r, reply := replyRig(t)
	reply("reply-1/r1", "thr-1", "Thanks, got it.")
	r.advance(time.Minute)
	if st := reply("reply-1/r2", "thr-1", "Thanks, got it."); st.State != journal.Pending || len(r.own.queued) != 2 {
		t.Fatalf("r2: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued))
	}
	r.advance(9*time.Minute + 30*time.Second)
	r.g.Tick()
	r.g.Wait()
	st := r.state("reply-1/r1")
	if st.State != journal.Succeeded {
		t.Fatalf("r1: %s", st.State)
	}
	went := st.Attempts[0].Dispatched
	asked := r.own.count()
	r.advance(time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("reply-1/r2"); st.State != journal.Pending || r.exec.runs("reply-1/r2") != 0 {
		t.Fatalf("r2 after its undo window: %s %q, ran %d", st.State, st.Permission.Reason, r.exec.runs("reply-1/r2"))
	}
	r.g.Flush()
	if r.own.count() != asked+1 {
		t.Fatalf("owner requests %d, want one more than %d", r.own.count(), asked)
	}
	_, items := r.own.last(t)
	if len(items) != 1 || items[0].Ref != "reply-1/r2" || !items[0].Sent.Equal(went) {
		t.Fatalf("r2 asked %+v, want it marked sent at %v", items, went)
	}
	// Confirmed, it goes.
	r.decide(true, "owner")
	if st := r.state("reply-1/r2"); st.State != journal.Succeeded || r.exec.runs("reply-1/r2") != 1 {
		t.Fatalf("confirmed r2: %s, ran %d", st.State, r.exec.runs("reply-1/r2"))
	}
}

// Security B10 on #1433 (probe TestZZSec8StaleApproval): s1 and s2, the
// same send, are each asked before either went, so neither ask is
// marked. The owner approves s1, which goes, then s2's unmarked ask. That
// approval did not see the repeat: s2 does not go, and the owner is asked
// again, told it was already sent. The same holds for a request whose
// record param differs but verifies to the same record.
func TestAnApprovalGivenBeforeTheSendWentDoesNotConfirmItsRepeat(t *testing.T) {
	for _, rec2 := range []string{"inv-1042", "INV-1042"} {
		t.Run(rec2, func(t *testing.T) {
			r := newRig(t, nil)
			r.grant(mailGrant())
			r.ver.set("inv-1042", sam())
			r.ver.set("INV-1042", sam())
			if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State != journal.Pending {
				t.Fatal(st.State)
			}
			r.g.Flush()
			req1, _ := r.own.last(t)
			if st := r.effect("agent/s2", "invoice.send", invoice(rec2), "sam@example.com"); st.State != journal.Pending {
				t.Fatal(st.State)
			}
			r.g.Flush()
			req2, items2 := r.own.last(t)
			if !items2[0].Sent.IsZero() || !items2[0].Retried.IsZero() {
				t.Fatalf("s2's first ask %+v, want it unmarked", items2[0])
			}
			r.g.Decide(owner.Decision{Request: req1, Item: 1, Ref: "agent/s1", Approved: true, Why: "owner"})
			r.g.Wait()
			st1 := r.state("agent/s1")
			if st1.State != journal.Succeeded {
				t.Fatalf("s1: %s", st1.State)
			}
			r.g.Decide(owner.Decision{Request: req2, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
			r.g.Wait()
			if st := r.state("agent/s2"); st.State != journal.Pending || r.exec.runs("agent/s2") != 0 {
				t.Fatalf("s2 on its stale approval: %s %q, ran %d", st.State, st.Permission.Reason, r.exec.runs("agent/s2"))
			}
			r.g.Flush()
			req3, items := r.own.last(t)
			if req3 == req2 || len(items) != 1 || items[0].Ref != "agent/s2" || !items[0].Sent.Equal(st1.Attempts[0].Dispatched) {
				t.Fatalf("s2 asked again %+v, want it marked sent at %v", items, st1.Attempts[0].Dispatched)
			}
		})
	}
}

// Security B10 on #1433 (probe TestZZSec8StaleApprovalWhileRivalInFlight):
// s2's ask was shown, unmarked and low, before s1 was dispatched; the
// owner approves it on a texted code while s1 is in flight. That approval
// did not see that the send may go twice, or the code generator a
// payment then takes: s2 does not go, and is asked again, marked and
// raised to MoneyRetry.
func TestAnApprovalGivenBeforeTheRivalStartedIsAskedAgainMarked(t *testing.T) {
	for _, rec2 := range []string{"inv-1042", "INV-1042"} {
		t.Run(rec2, func(t *testing.T) {
			r := newRig(t, nil)
			r.grant(mailGrant())
			r.ver.set("inv-1042", sam())
			r.ver.set("INV-1042", sam())
			hold := make(chan struct{})
			r.exec.mu.Lock()
			r.exec.block = map[string]chan struct{}{"agent/s1": hold}
			r.exec.mu.Unlock()
			r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com")
			r.g.Flush()
			req1, _ := r.own.last(t)
			r.effect("agent/s2", "invoice.send", invoice(rec2), "sam@example.com")
			r.g.Flush()
			req2, items2 := r.own.last(t)
			if items2[0].Facts.Kind == owner.MoneyRetry || r.own.Tier(items2[0].Facts) != owner.Low {
				t.Fatalf("s2's first ask %+v, want it low", items2[0])
			}
			r.g.Decide(owner.Decision{Request: req1, Item: 1, Ref: "agent/s1", Approved: true, Why: "owner"})
			for st := r.state("agent/s1"); len(st.Attempts) == 0; st = r.state("agent/s1") {
				time.Sleep(time.Millisecond)
			}
			tried := r.state("agent/s1").Attempts[0].Dispatched
			r.g.Decide(owner.Decision{Request: req2, Item: 1, Ref: "agent/s2", Approved: true, Why: "owner"})
			// s1's settle is still running; wait for s2's ask instead.
			var items []owner.Item
			for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
				r.g.Flush()
				var req string
				if req, items = r.own.last(t); req != req2 {
					break
				}
			}
			if st := r.state("agent/s2"); st.State != journal.Pending || r.exec.runs("agent/s2") != 0 {
				t.Fatalf("s2 while s1 is in flight: %s %q, ran %d", st.State, st.Permission.Reason, r.exec.runs("agent/s2"))
			}
			if len(items) != 1 || items[0].Ref != "agent/s2" || !items[0].Retried.Equal(tried) ||
				items[0].Facts.Kind != owner.MoneyRetry || r.own.Tier(items[0].Facts) != owner.High {
				t.Fatalf("s2 asked again %+v, want it marked tried at %v and high", items, tried)
			}
			close(hold)
			r.g.Wait()
			if r.exec.runs("agent/s2") != 0 {
				t.Fatal("s2 went")
			}
		})
	}
}

// Security B10 on #1433, the recheck itself: s2 is approved on a line
// marked "may go twice" while s1 is in flight, and STOP holds it. s1 then
// goes. s2's approval covered a send that may have gone, not one known
// to have gone, so its dispatch after RESUME is refused, never sent.
func TestTheDispatchRecheckRefusesAnApprovalThatDidNotSeeTheSendGo(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.ver.set("INV-1042", sam())
	hold := make(chan struct{})
	r.exec.mu.Lock()
	r.exec.block = map[string]chan struct{}{"agent/s1": hold}
	r.exec.mu.Unlock()
	r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com")
	r.g.Flush()
	approveLast(t, r)
	for st := r.state("agent/s1"); len(st.Attempts) == 0; st = r.state("agent/s1") {
		time.Sleep(time.Millisecond)
	}
	it := askedRepeat(t, r, "agent/s2", "INV-1042", "sam@example.com")
	if it.Retried.IsZero() {
		t.Fatalf("s2's ask %+v, want it marked may go twice", it)
	}
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	approveLast(t, r)
	st := r.state("agent/s2")
	for end := time.Now().Add(10 * time.Second); st.State == journal.Pending && time.Now().Before(end); st = r.state("agent/s2") {
		time.Sleep(time.Millisecond)
	}
	if st.State != journal.Authorized {
		t.Fatalf("s2 under STOP: %s %q", st.State, st.Permission.Reason)
	}
	close(hold)
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s", st.State)
	}
	if err := r.eng.Resume(); err != nil {
		t.Fatal(err)
	}
	st, err := r.g.Dispatch(context.Background(), "agent/s2")
	if err == nil || st.State != journal.Denied || st.Permission.Reason != RepeatSinceApproval || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("s2 after s1 went: %s %q %v, ran %d", st.State, st.Permission.Reason, err, r.exec.runs("agent/s2"))
	}
}

// Security B11 on #1433 (probe TestZZSec8LateKnownSuccess): s1's outcome
// is unknown, and a check proves it went 30 hours after it was
// dispatched. The 24 hours run from when the success became known, so an
// identical pre-allowed send right after is asked, and its line still
// says when s1 was sent.
func TestARepeatRightAfterALateProofIsAsked(t *testing.T) {
	r := killedSend(t, false)
	sent := r.state("agent/s1").Attempts[0].Dispatched
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 20, PerDay: 50, HoldDays: 7}})
	r.advance(30 * time.Hour)
	if _, err := r.eng.Resolve("agent/s1", 1, journal.Outcome{Result: journal.ResultSucceeded, Evidence: "found in Sent"}, "check"); err != nil {
		t.Fatal(err)
	}
	if st := r.state("agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s", st.State)
	}
	it := askedRepeat(t, r, "agent/s2", "inv-1042", "sam@example.com")
	if !it.Sent.Equal(sent) || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("s2's ask %+v, ran %d; want it marked sent at %v", it, r.exec.runs("agent/s2"), sent)
	}
	r.decide(false, "owner")
	// 24 hours after the proof, it is a new send.
	r.advance(24*time.Hour + time.Minute)
	if st := r.effect("agent/s3", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s3 a day after the proof: %s %q", st.State, st.Permission.Reason)
	}
}

// Potency P12 / UX U20 on #1433: a send that may have gone (parked
// unknown, or in flight), resubmitted with a different body, may still
// go twice: it is marked so and a payment is raised to the code
// generator. Only the known-success side compares the body.
func TestAResubmissionWithANewBodyOfASendThatMayHaveGoneIsMarked(t *testing.T) {
	reworded := map[string]any{"record": "inv-1042", "template": "invoice", "body": "Resending, sorry"}
	check := func(t *testing.T, r *rig, first time.Time) {
		t.Helper()
		if st := r.effect("agent/s2", "invoice.send", reworded, "sam@example.com"); st.State != journal.Pending {
			t.Fatalf("s2: %s %q", st.State, st.Permission.Reason)
		}
		r.g.Flush()
		_, items := r.own.last(t)
		if len(items) != 1 || !items[0].Retried.Equal(first) || items[0].Facts.Kind != owner.MoneyRetry || r.own.Tier(items[0].Facts) != owner.High {
			t.Fatalf("s2's ask %+v, want it marked tried at %v and high", items, first)
		}
	}
	t.Run("parked", func(t *testing.T) {
		r := killedSend(t, false)
		st := r.state("agent/s1")
		if st.State != journal.OutcomeUnknown {
			t.Fatalf("s1: %s", st.State)
		}
		r.advance(time.Hour)
		check(t, r, st.Attempts[0].Dispatched)
	})
	t.Run("in flight", func(t *testing.T) {
		r := newRig(t, nil)
		r.grant(mailGrant())
		r.ver.set("inv-1042", sam())
		hold := make(chan struct{})
		defer close(hold)
		r.exec.mu.Lock()
		r.exec.block = map[string]chan struct{}{"agent/s1": hold}
		r.exec.mu.Unlock()
		r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com")
		r.g.Flush()
		approveLast(t, r)
		var st journal.Status
		for st = r.state("agent/s1"); len(st.Attempts) == 0; st = r.state("agent/s1") {
			time.Sleep(time.Millisecond)
		}
		check(t, r, st.Attempts[0].Dispatched)
	})
}

// Security R20 on #1433 (probe TestZZSec8NearIdenticalBody): bodies are
// compared with whitespace trimmed and folded, line endings included, so
// a regenerated reply that differs only in spacing is a repeat and is
// asked. Case is not folded: "thanks" is other text than "Thanks", which
// matters only in reply to another message of the thread; another reply
// to the same message is a repeat whatever its body (#1677).
func TestABodyThatDiffersOnlyInWhitespaceIsARepeat(t *testing.T) {
	for _, body := range []string{"Thanks, got it.\n", " Thanks, got it.", "Thanks,  got it.", "Thanks,\r\ngot it.", "\tThanks, got\tit. \n"} {
		r, reply, went := sentReply(t)
		q := len(r.own.queued)
		if st := reply("reply-1/r2", "thr-1", body); st.State != journal.Pending || len(r.own.queued) != q {
			t.Fatalf("body %q: %s %q, queued %d", body, st.State, st.Permission.Reason, len(r.own.queued)-q)
		}
		r.g.Flush()
		if _, items := r.own.last(t); len(items) != 1 || !items[0].Sent.Equal(went) {
			t.Fatalf("body %q: asked %+v", body, items)
		}
	}
	r, reply, _ := sentReply(t)
	q := len(r.own.queued)
	if st := reply("reply-1/r2", "thr-2", "thanks, got it."); st.State != journal.Pending || len(r.own.queued) != q+1 {
		t.Fatalf("other case: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
}

// Security R21 on #1433 (probe TestZZSec8OtherRecordSameContent): the same
// body to the same recipients in reply to another message of the same
// thread (the agent's own Sent copy of its first reply, say) is a repeat
// (the coordinator's conservative reading, D-116). In another thread it
// is a new send.
func TestTheSameBodyInReplyToAnotherMessageOfTheThreadIsARepeat(t *testing.T) {
	r, reply, went := sentReply(t)
	q := len(r.own.queued)
	if st := reply("reply-1/r2", "thr-2", "Thanks, got it."); st.State != journal.Pending || len(r.own.queued) != q {
		t.Fatalf("same thread: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || !items[0].Sent.Equal(went) {
		t.Fatalf("same thread: asked %+v", items)
	}
	r.decide(false, "owner")
	if st := reply("reply-1/r3", "thr-9", "Thanks, got it."); st.State != journal.Pending || len(r.own.queued) != q+1 {
		t.Fatalf("other thread: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
	// Something new in the same thread is a new send.
	if st := reply("reply-1/r4", "thr-2", "And the second file."); st.State != journal.Pending || len(r.own.queued) != q+2 {
		t.Fatalf("new text: %s %q, queued %d", st.State, st.Permission.Reason, len(r.own.queued)-q)
	}
}

// Security R23 on #1433: a send erased after it went (CAP-3, a recall
// reset) no longer names its record, so it cannot be told apart from the
// same send: a pre-allowed send within 24 hours of it is asked, not sent
// unseen (D-116).
func TestASendErasedAfterItWentStillCountsAsSent(t *testing.T) {
	r := repeatRig(t, "inv-1042", sam())
	if st := r.effect("agent/s1", "invoice.send", invoice("inv-1042"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("s1: %s %q", st.State, st.Permission.Reason)
	}
	went := r.state("agent/s1").Attempts[0].Dispatched
	if er, _, err := r.eng.Erase([]string{"agent/s1"}); err != nil || len(er) != 1 {
		t.Fatalf("erase: %v %v", er, err)
	}
	it := askedRepeat(t, r, "agent/s2", "inv-1042", "sam@example.com")
	if !it.Sent.Equal(went) || r.exec.runs("agent/s2") != 0 {
		t.Fatalf("s2's ask %+v, want it marked sent at %v", it, went)
	}
}

// approveLast approves every item of the owner's last request without
// waiting for the gate's settling, which a blocked send would hold up.
func approveLast(t *testing.T, r *rig) {
	t.Helper()
	req, items := r.own.last(t)
	for i, it := range items {
		r.g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: true, Why: "owner"})
	}
}
