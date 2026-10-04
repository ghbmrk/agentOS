package grants

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: REV-2, CH-10, ADP-1

// TestIrreversibleEffectsWaitForTheOwner: reads and drafts under a grant
// run at once; a send is journaled, asked of the owner, and runs once on
// approval. An operation the grant does not declare does not exist, and
// an account no grant connects is refused.
func TestIrreversibleEffectsWaitForTheOwner(t *testing.T) {
	r := newRig(t, nil)
	if _, ok := r.g.Route("mail"); ok {
		t.Fatal("an account routes before any grant connects it")
	}
	r.grant(mailGrant())
	if ex, ok := r.g.Route("mail"); !ok || ex != "mail" {
		t.Fatalf("route %q %v", ex, ok)
	}

	if st := r.effect("agent/l1", "message.list", nil); st.State != journal.Succeeded {
		t.Fatalf("read: %s %q", st.State, st.Permission.Reason)
	}
	if st := r.effect("agent/d1", "draft.save", map[string]any{"body": "hi"}); st.State != journal.Succeeded {
		t.Fatalf("draft: %s", st.State)
	}
	r.ver.set("inv-1042", sam())
	send := map[string]any{"record": "inv-1042", "template": "invoice"}
	st := r.effect("agent/s1", "invoice.send", send, "sam@example.com")
	if st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("send ran or was not held: %s %q", st.State, st.Permission.Reason)
	}
	// A retry asks nothing twice.
	if st := r.effect("agent/s1", "invoice.send", send, "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("retry: %s", st.State)
	}
	r.g.Flush()
	req, items := r.own.last(t)
	if len(items) != 1 || r.own.count() != 2 { // the grant, then the send
		t.Fatalf("requests %d, items %+v", r.own.count(), items)
	}
	// The line comes from the source and the grant's verb, never the agent.
	it := items[0]
	if it.Ref != "agent/s1" || it.Facts.Verb != "send" || it.Object != "invoice 1042" || it.Amount != "$120.00" || r.own.Tier(it.Facts) != owner.Low {
		t.Fatalf("item %+v", it)
	}
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s1", Approved: true, Why: "owner"})
	r.g.Wait()
	if st := r.state("agent/s1"); st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("approved send: %s, ran %d", st.State, r.exec.runs("agent/s1"))
	}
	// A late duplicate decision changes nothing.
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/s1", Approved: true})
	r.g.Wait()
	if r.exec.runs("agent/s1") != 1 {
		t.Fatal("a duplicate decision ran the effect again")
	}

	if st := r.effect("agent/x1", "account.delete", nil); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "not declared") {
		t.Fatalf("undeclared operation: %s %q", st.State, st.Permission.Reason)
	}
	in := journal.Intent{ID: "agent/b1", Origin: "guest:agent", Account: "bank", Action: "pay", Executor: "mail"}
	if st := r.submit(in); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "no grant") {
		t.Fatalf("ungranted account: %s %q", st.State, st.Permission.Reason)
	}
}

// REQ: CH-10, CRED-6

// TestUnverifiedAndSecretItemsAreHighRisk: without a verifier the line
// shows the operation and the recipients that will be used, marked
// unverified, at the high tier. Secret verbs are high by kind.
func TestUnverifiedAndSecretItemsAreHighRisk(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.effect("agent/s1", "message.send", map[string]any{"body": "hello"}, "eve@example.net")
	r.effect("agent/k1", "key.create", nil)
	r.g.Flush()
	_, items := r.own.last(t)
	if len(items) != 2 {
		t.Fatalf("items %+v", items)
	}
	for _, it := range items {
		if r.own.Tier(it.Facts) != owner.High {
			t.Fatalf("%s is not high risk: %+v", it.Ref, it.Facts)
		}
	}
	if items[0].Recipient != "eve@example.net" || !strings.Contains(items[0].Object, "unverified") {
		t.Fatalf("unverified line %+v", items[0])
	}
	if items[1].Facts.Kind != owner.SecretReveal {
		t.Fatalf("secret kind %+v", items[1].Facts)
	}
}

// REQ: CH-10, CH-13

// TestBatchesSplitByTierAndDenialsClose: items asked within one tick share
// a request per tier; a denied or expired item is denied and never runs.
func TestBatchesSplitByTierAndDenialsClose(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1", sam())
	r.ver.set("inv-2", sam())
	big := sam()
	big.Record, big.Item.Facts.Amount = "inv-3", 90000
	r.ver.set("inv-3", big)
	before := r.own.count()
	for i, rec := range []string{"inv-1", "inv-2", "inv-3"} {
		r.effect("agent/s"+string(rune('1'+i)), "invoice.send", map[string]any{"record": rec}, "sam@example.com")
	}
	r.g.Flush()
	if got := r.own.count() - before; got != 2 {
		t.Fatalf("%d requests, want one low and one high", got)
	}
	low := r.own.reqs[r.own.order[before]]
	high := r.own.reqs[r.own.order[before+1]]
	if len(low) != 2 || len(high) != 1 || high[0].Ref != "agent/s3" {
		t.Fatalf("low %+v high %+v", low, high)
	}
	r.g.Decide(owner.Decision{Request: r.own.order[before], Item: 1, Ref: "agent/s1", Why: "owner"})
	r.g.Decide(owner.Decision{Request: r.own.order[before], Item: 2, Ref: "agent/s2", Why: "expired"})
	r.g.Wait()
	for _, id := range []string{"agent/s1", "agent/s2"} {
		st := r.state(id)
		if st.State != journal.Denied || r.exec.runs(id) != 0 {
			t.Fatalf("%s: %s, ran %d", id, st.State, r.exec.runs(id))
		}
	}
	if st := r.state("agent/s2"); !strings.Contains(st.Permission.Reason, "expired") {
		t.Fatalf("reason %q", st.Permission.Reason)
	}
	// A decision naming another request does not settle the item.
	r.g.Decide(owner.Decision{Request: "Z9", Item: 1, Ref: "agent/s3", Approved: true})
	r.g.Wait()
	if st := r.state("agent/s3"); st.State != journal.Pending {
		t.Fatalf("stray decision settled s3: %s", st.State)
	}
}

// REQ: OP-3

// TestRecheckBeforeDispatch: an approval does not outlive the grant, the
// approved details, or DefaultFresh.
func TestRecheckBeforeDispatch(t *testing.T) {
	r := newRig(t, nil)
	gid := r.grant(mailGrant())
	ctx := context.Background()
	approveHeld := func(id, rec string) {
		t.Helper()
		r.ver.set(rec, func() Verified { v := sam(); v.Record = rec; return v }())
		r.effect(id, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
		r.g.Flush()
		r.decide(true, "owner")
		if st := r.state(id); st.State != journal.Authorized {
			t.Fatalf("%s should be authorized and held by STOP: %s", id, st.State)
		}
	}
	if _, err := r.eng.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	approveHeld("agent/a", "inv-a")
	approveHeld("agent/b", "inv-b")
	approveHeld("agent/c", "inv-c")
	r.eng.Resume()

	// The recipient on the source record changed after approval.
	moved := sam()
	moved.Record, moved.Item.Recipient = "inv-a", "mallory@example.net"
	r.ver.set("inv-a", moved)
	if st, _ := r.g.Dispatch(ctx, "agent/a"); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "changed") {
		t.Fatalf("changed details: %s %q", st.State, st.Permission.Reason)
	}
	// Stale approval.
	r.advance(DefaultFresh + time.Minute)
	if st, _ := r.g.Dispatch(ctx, "agent/b"); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "older") {
		t.Fatalf("stale approval: %s %q", st.State, st.Permission.Reason)
	}
	// Revoked grant.
	if got := r.g.Narrow("REVOKE", gid); !strings.HasPrefix(got, "Revoked") {
		t.Fatal(got)
	}
	if st, _ := r.g.Dispatch(ctx, "agent/c"); st.State != journal.Denied || r.exec.runs("agent/c") != 0 {
		t.Fatalf("revoked grant: %s", st.State)
	}
}

// REQ: OP-4, CH-13

// TestRestartClosesIntentsWaitingOnTheOwner: no approval request survives a
// restart, so every intent left pending is denied with the reason, and a
// decision the owner channel's Boot reports is harmless.
func TestRestartClosesIntentsWaitingOnTheOwner(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()

	r.open() // restart
	st := r.state("agent/s1")
	if st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "restarted") || r.exec.runs("agent/s1") != 0 {
		t.Fatalf("after restart: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Decide(owner.Decision{Request: "R2", Item: 1, Ref: "agent/s1", Why: "restart"})
	r.g.Wait()
	if _, ok := r.g.Route("mail"); !ok {
		t.Fatal("the grant did not survive the restart")
	}
}

// REQ: ADP-11

// TestContextScopedReplies: a reply composed in an isolated machine under a
// reply rule is queued with an undo window and released after it; UNDO
// denies it; a reply that matches the commitment filter becomes a request;
// a reply from the main agent is asked as usual.
func TestContextScopedReplies(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Isolated = func(o string) bool { return strings.HasPrefix(o, "guest:reply-") } })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	thread := Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
		Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
		Recipients: []string{"sam@example.com"}, Record: "thr-1", ThreadVerified: true}
	r.ver.set("thr-1", thread)
	reply := func(id, origin string) journal.Status {
		return r.submit(journal.Intent{ID: id, Origin: origin, Account: "mail", Action: "message.send",
			Params: map[string]any{"record": "thr-1", "body": "Thanks, got it."}, Recipients: []string{"sam@example.com"}, Executor: "mail"})
	}

	st := reply("reply-1/r1", "guest:reply-1")
	if st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "auto-reply queued") || len(r.own.queued) != 1 {
		t.Fatalf("not queued: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Tick()
	if r.exec.runs("reply-1/r1") != 0 {
		t.Fatal("sent inside the undo window")
	}
	r.advance(11 * time.Minute)
	r.g.Tick()
	r.g.Wait()
	if st := r.state("reply-1/r1"); st.State != journal.Succeeded {
		t.Fatalf("released reply: %s %q", st.State, st.Permission.Reason)
	}

	reply("reply-1/r2", "guest:reply-1")
	q := r.own.due[len(r.own.due)-1]
	r.g.Decide(owner.Decision{Request: q.ID, Item: 1, Ref: "reply-1/r2", Why: "undo"})
	r.g.Wait()
	if st := r.state("reply-1/r2"); st.State != journal.Denied || r.exec.runs("reply-1/r2") != 0 {
		t.Fatalf("undone reply: %s", st.State)
	}

	r.own.commit = true
	if st := reply("reply-1/r3", "guest:reply-1"); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" {
		t.Fatalf("committing reply: %s %q", st.State, st.Permission.Reason)
	}
	r.decide(true, "owner")
	if st := r.state("reply-1/r3"); st.State != journal.Succeeded {
		t.Fatalf("approved committing reply: %s", st.State)
	}
	r.own.commit = false

	n := len(r.own.queued)
	reply("agent/r4", "guest:agent")
	if len(r.own.queued) != n {
		t.Fatal("a reply from a non-isolated machine was auto-queued")
	}
}

// REQ: CH-10

// TestOwnerUnreachableLeavesItPending: if the owner cannot be texted, the
// intent stays pending with the reason and a retry asks again.
func TestOwnerUnreachableLeavesItPending(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.own.down = true
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	if st := r.state("agent/s1"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "could not ask the owner") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	r.own.down = false
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state("agent/s1"); st.State != journal.Succeeded {
		t.Fatalf("after retry: %s", st.State)
	}
}
