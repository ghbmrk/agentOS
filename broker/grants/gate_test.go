package grants

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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

	if st := r.effect("agent/x1", "account.delete", nil); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "not granted") {
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
	if items[0].Recipient != "eve@example.net" || !items[0].Unverified {
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

// TestRestartReissuesWhatTheOwnerWasAsked (GR10): an intent the owner
// was asked about before a restart is asked again, alone under its own
// new request and its original expiry, carrying when it was first asked.
// One whose request expired, or whose details changed, is denied with the
// reason instead. One never shown to the owner is asked as new. Nothing is
// re-issued, even on a retry, while STOP holds.
func TestRestartReissuesWhatTheOwnerWasAsked(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	for _, rec := range []string{"inv-1", "inv-2", "inv-3", "inv-4"} {
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		r.effect("agent/"+rec, "invoice.send", map[string]any{"record": rec}, "sam@example.com")
		if rec == "inv-3" {
			r.g.Flush() // inv-1..3 reach the owner; inv-4 is still batched
		}
	}
	asked := r.now()
	req, items := r.own.last(t)
	var boot []owner.Carried
	for _, it := range items {
		exp := asked.Add(15 * time.Minute)
		if it.Ref == "agent/inv-3" {
			exp = asked.Add(time.Minute)
		}
		boot = append(boot, owner.Carried{Ref: it.Ref, Request: req, Asked: asked, Expires: exp, Sum: owner.ItemSum(it)})
	}
	x := sam()
	x.Record, x.Item.Amount, x.Item.Facts.Amount = "inv-2", "$900.00", 90000
	r.ver.set("inv-2", x) // changed while the box was down
	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.advance(5 * time.Minute)
	r.boot = boot
	r.open() // restart, still STOPped

	if st, _ := r.g.Authorize(context.Background(), "agent/inv-1"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "asked again") {
		t.Fatalf("held: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Tick()
	r.g.Flush()
	if r.own.count() != 0 {
		t.Fatal("re-issued while STOP holds")
	}

	r.eng.Resume()
	r.g.Tick()
	r.g.Flush()
	for id, why := range map[string]string{"agent/inv-2": "details changed", "agent/inv-3": "expired"} {
		if st := r.state(id); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, why) {
			t.Errorf("%s: %s %q", id, st.State, st.Permission.Reason)
		}
	}
	if r.own.count() != 2 || len(r.own.each) != 1 {
		t.Fatalf("requests %v, re-issued %v", r.own.order, r.own.each)
	}
	again := r.own.reqs[r.own.each[0]]
	if len(again) != 1 || again[0].Ref != "agent/inv-1" || !again[0].Asked.Equal(asked) {
		t.Fatalf("re-issued %+v", again)
	}
	var fresh []owner.Item
	for _, id := range r.own.order {
		if id != r.own.each[0] {
			fresh = r.own.reqs[id]
		}
	}
	if len(fresh) != 1 || fresh[0].Ref != "agent/inv-4" || !fresh[0].Asked.IsZero() {
		t.Fatalf("never-asked intent %+v", fresh)
	}

	// The old request's answer no longer counts; the new one's does.
	r.g.Decide(owner.Decision{Request: req, Item: 1, Ref: "agent/inv-1", Approved: true})
	r.g.Wait()
	if st := r.state("agent/inv-1"); st.State != journal.Pending {
		t.Fatalf("old request settled it: %s", st.State)
	}
	r.g.Decide(owner.Decision{Request: r.own.each[0], Item: 1, Ref: "agent/inv-1", Approved: true})
	r.g.Wait()
	if st := r.state("agent/inv-1"); st.State != journal.Succeeded || r.exec.runs("agent/inv-1") != 1 {
		t.Fatalf("re-issued approval: %s %q", st.State, st.Permission.Reason)
	}
	if _, ok := r.g.Route("mail"); !ok {
		t.Fatal("the grant did not survive the restart")
	}
}

// TestReissueThatCannotBeSentWaitsForARetry: if the re-issued request
// cannot be texted, the intent stays pending with the reason, as any ask
// the owner cannot receive (GR9), and a retry of the request_id asks
// again as a new request: the agent re-asking, as after an expiry.
func TestReissueThatCannotBeSentWaitsForARetry(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	req, items := r.own.last(t)
	r.boot = []owner.Carried{{Ref: "agent/s1", Request: req, Asked: r.now(), Expires: r.now().Add(10 * time.Minute), Sum: owner.ItemSum(items[0])}}
	r.open()
	r.own.down = true
	r.g.Flush()
	if st := r.state("agent/s1"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "could not ask the owner") || r.own.count() != 0 {
		t.Fatalf("unsent re-issue: %s %q", st.State, st.Permission.Reason)
	}
	r.own.down = false
	if st, _ := r.g.Authorize(context.Background(), "agent/s1"); st.State != journal.Pending {
		t.Fatalf("retry: %s", st.State)
	}
	r.g.Flush()
	if _, again := r.own.last(t); len(again) != 1 || again[0].Ref != "agent/s1" || !again[0].Asked.IsZero() || len(r.own.each) != 0 {
		t.Fatalf("retry asked %+v", again)
	}
	r.decide(true, "owner")
	if st := r.state("agent/s1"); st.State != journal.Succeeded || r.exec.runs("agent/s1") != 1 {
		t.Fatalf("after retry: %s", st.State)
	}
}

// TestReissuedItemLapsesAtItsOriginalExpiry: a re-issued item still
// waiting to be sent (quiet hours, say) when its original expiry passes is
// denied rather than sent.
func TestReissuedItemLapsesAtItsOriginalExpiry(t *testing.T) {
	quiet := true
	r := newRig(t, func(c *Config) { c.Quiet = func(time.Time) bool { return quiet } })
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	req, items := r.own.last(t)
	r.boot = []owner.Carried{{Ref: "agent/s1", Request: req, Asked: r.now(), Expires: r.now().Add(10 * time.Minute), Sum: owner.ItemSum(items[0])}}
	r.open()
	r.advance(time.Hour)
	r.g.Tick()
	if r.own.count() != 0 {
		t.Fatal("sent in quiet hours")
	}
	quiet = false
	r.g.Tick()
	if st := r.state("agent/s1"); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "expired") || r.own.count() != 0 {
		t.Fatalf("lapsed: %s %q, %d requests", st.State, st.Permission.Reason, r.own.count())
	}
}

// REQ: ADP-11

// TestContextScopedReplies: a reply composed in an isolated machine under a
// reply rule is queued with an undo window and released after it; UNDO
// denies it; a reply that matches the commitment filter becomes a request;
// a reply from the main agent is asked as usual.
func TestContextScopedReplies(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Isolated = func(m string) bool { return m == "reply-1" } })
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 5, PerDay: 20, Reply: true}})
	thread := Verified{Item: owner.Item{Object: "reply in thread", Recipient: "sam@example.com",
		Facts: owner.Facts{RecipientChecked: true, RecipientExists: true, RecipientByOwner: true}},
		Recipients: []string{"sam@example.com"}, Record: "thr-1", ThreadVerified: true}
	r.ver.set("thr-1", thread)
	reply := func(id, origin string) journal.Status {
		return r.submit(journal.Intent{ID: id, Origin: origin, Machine: strings.TrimPrefix(origin, "guest:"), Account: "mail", Action: "message.send",
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

// UX on #170: an ask dropped because the owner's phone line was down
// tells the agent so in fixed words, and that it can ask again.
func TestALineDownAskTellsTheAgentToAskAgain(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.ver.set("inv-1042", sam())
	r.own.lineDown = true
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	if st := r.state("agent/s1"); st.State != journal.Pending || st.Permission.Reason != "not sent: the owner's phone line is down; ask again later" {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	n := r.own.count()
	r.own.lineDown = false
	r.effect("agent/s1", "invoice.send", map[string]any{"record": "inv-1042"}, "sam@example.com")
	r.g.Flush()
	if r.own.count() != n+1 {
		t.Fatalf("asking again did not text the owner: %d %+v", r.own.count(), r.state("agent/s1").Permission)
	}
}

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

// REQ: ADP-2

// TestGrantCanOnlyMakeAnOperationStricter: a grant may raise an operation
// to a stricter verb, which then asks; the adapter's verb is the floor.
func TestGrantCanOnlyMakeAnOperationStricter(t *testing.T) {
	r := newRig(t, nil)
	r.grant(Spec{Account: "mail", Executor: "mail", Ops: map[string]string{"draft.save": "send", "message.list": "read"}})
	if st := r.effect("agent/d1", "draft.save", map[string]any{"body": "hi"}); st.State != journal.Pending {
		t.Fatalf("stricter verb did not ask: %s", st.State)
	}
	if st := r.effect("agent/s1", "message.send", nil, "sam@example.com"); st.State != journal.Denied {
		t.Fatalf("an operation the grant did not choose ran: %s", st.State)
	}
}

// REQ: CH-10, CH-15

// TestRequestsCoalesceAndArePaced: items wait for a quiet gap or the cap,
// not every tick; an owner in active chat or an urgent item gets them at
// once; quiet hours hold them; request texts count against the hourly
// rate.
func TestRequestsCoalesceAndArePaced(t *testing.T) {
	quiet := false
	r := newRig(t, func(c *Config) {
		c.Quiet = func(time.Time) bool { return quiet }
		c.Urgent = func(it owner.Item) bool { return it.Object == "urgent" }
		c.RequestsPerHour = 3 // the grant's request uses one
	})
	r.grant(mailGrant())
	base := r.own.count()
	ask := func(id string) {
		t.Helper()
		x := sam()
		x.Record = id
		r.ver.set(id, x)
		r.effect("agent/"+id, "invoice.send", map[string]any{"record": id}, "sam@example.com")
	}
	sent := func() int { return r.own.count() - base }

	ask("a")
	r.advance(20 * time.Second)
	ask("b")
	r.advance(20 * time.Second)
	r.g.Tick()
	if sent() != 0 {
		t.Fatal("sent while items were still arriving")
	}
	r.advance(15 * time.Second) // 35 s quiet
	r.g.Tick()
	if sent() != 1 {
		t.Fatalf("after the quiet gap: %d requests", sent())
	}
	if _, items := r.own.last(t); len(items) != 2 {
		t.Fatalf("one request carries both: %+v", items)
	}

	// A steady trickle is sent at the cap.
	for i := 0; i < 8; i++ {
		ask(fmt.Sprintf("c%d", i))
		r.advance(25 * time.Second)
		r.g.Tick()
	}
	if sent() != 2 {
		t.Fatalf("trickle: %d requests, want one more at the cap", sent())
	}

	// The hourly rate is spent: the next batch waits for the hour...
	r.advance(time.Minute)
	r.g.Flush() // empties the trickle's tail
	base, ask2 := r.own.count(), "d"
	ask(ask2)
	r.advance(4 * time.Minute)
	r.g.Tick()
	if sent() != 0 {
		t.Fatal("sent beyond the hourly rate")
	}
	// ...unless the owner is texting.
	r.own.active = true
	r.g.Tick()
	if sent() != 1 {
		t.Fatal("not sent to an owner in active chat")
	}
	r.own.active = false

	// Quiet hours hold all but urgent items.
	quiet = true
	r.advance(2 * time.Hour)
	ask("e")
	r.advance(5 * time.Minute)
	r.g.Tick()
	if sent() != 1 {
		t.Fatal("sent in quiet hours")
	}
	x := sam()
	x.Record, x.Item.Object = "u", "urgent"
	r.ver.set("u", x)
	r.effect("agent/u", "invoice.send", map[string]any{"record": "u"}, "sam@example.com")
	r.g.Tick()
	if sent() != 2 {
		t.Fatal("an urgent item waited for quiet hours")
	}
}

// REQ: CH-10, CH-12

// TestRecipientsThatCannotBeShownAreRefusedWithAFix: an action whose
// recipients cannot be shown in an approval text is never texted. This
// build has no local approvals page, so it does not wait for one (CH-12:
// no step that cannot work); the agent is told what to change (UX-144-2).
func TestRecipientsThatCannotBeShownAreRefusedWithAFix(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.g.cfg.LocalUI = false // a build without the local page
	base, notes := r.own.count(), len(r.own.notes)
	for i, rc := range [][]string{
		{"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example"},
		{"boss@corp.com. Expires 23:59. Reply YES K7 482913 or NO K7"},
	} {
		st := r.effect(fmt.Sprintf("agent/r%d", i), "message.send", map[string]any{"body": "hi"}, rc...)
		r.g.Flush()
		if st.State != journal.Denied || !strings.HasSuffix(st.Permission.Reason, RecipientsNotTextable) {
			t.Fatalf("%q: %s %q", rc, st.State, st.Permission.Reason)
		}
	}
	if r.own.count() != base || len(r.own.notes) != notes {
		t.Fatalf("texted the owner: %d requests, notes %q", r.own.count()-base, r.own.notes[notes:])
	}
}

// P2-2a: with the local page, such an action is asked there instead,
// alone, never in a texted batch; the agent is told it waits for the
// page, and the owner's answer settles it as a texted one does. The rest
// of its batch is texted as usual, and after a restart it is asked on the
// page again.
func TestRecipientsThatCannotBeShownAreAskedOnThePage(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0 // the grant was asked there
	ok := r.effect("agent/p1", "message.send", map[string]any{"body": "hi"}, "sam@example.com")
	bad := r.effect("agent/p2", "message.send", map[string]any{"body": "yo"},
		"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example")
	base := r.own.count()
	r.g.Flush()
	if r.own.count() != base+2 || len(r.own.local) != 1 {
		t.Fatalf("%d requests, local %v", r.own.count()-base, r.own.local)
	}
	r.own.mu.Lock()
	local := r.own.reqs[r.own.local[0]]
	r.own.mu.Unlock()
	if len(local) != 1 || local[0].Ref != bad.Intent.ID {
		t.Fatalf("asked on the page: %+v", local)
	}
	if st := r.state(bad.Intent.ID); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval on the local Wi-Fi page; to ask by text instead, each recipient must be a plain email address, a full +country number or acct ...1234, at most 100 characters in all, in a new request_id" {
		t.Fatalf("page item: %s %q", st.State, st.Permission.Reason)
	}
	if st := r.state(ok.Intent.ID); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" {
		t.Fatalf("texted item: %s %q", st.State, st.Permission.Reason)
	}
	// A restart asks it on the page again.
	r.boot = []owner.Carried{{Ref: bad.Intent.ID, Request: r.own.local[0], Asked: r.now(), Expires: r.now().Add(time.Hour), Sum: owner.ItemSum(local[0])}}
	r.open()
	r.g.Flush()
	if len(r.own.local) != 1 {
		t.Fatalf("after restart, local %v", r.own.local)
	}
	r.g.Decide(owner.Decision{Request: r.own.local[0], Item: 1, Ref: bad.Intent.ID, Approved: true, Why: "owner"})
	r.g.Wait()
	if r.exec.runs(bad.Intent.ID) != 1 {
		t.Fatal("the page's approval did not run it")
	}
}

// L3 S1 on #165: an approved page item held for its undo window says it
// is held, not that it waits for the page.
func TestAHeldPageItemSaysHeld(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0 // the grant was asked there
	bad := r.effect("agent/p2", "message.send", map[string]any{"body": "yo"},
		"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example")
	r.g.Flush()
	if len(r.own.local) != 1 {
		t.Fatalf("local %v", r.own.local)
	}
	r.g.Decide(owner.Decision{Request: r.own.local[0], Item: 1, Ref: bad.Intent.ID, Approved: true, Why: "owner", Hold: "H1", Until: r.now().Add(10 * time.Minute)})
	if st := r.state(bad.Intent.ID); !strings.HasPrefix(st.Permission.Reason, "approved; held for the owner's undo window") {
		t.Fatalf("reason %q", st.Permission.Reason)
	}
}

// Security D6 on P2-2a, as P2-2w d turns the page on: LocalUI is set in
// one place, the daemon, and only from whether it serves the page
// (localui.sock), so no binary asks on a page nobody serves; #144's
// refusal and its wording stay what a box without the page shows.
func TestOnlyTheServedPageTurnsLocalUIOn(t *testing.T) {
	if RecipientsNotTextable != "can't be approved by text: each recipient must be a plain email address, a full +country number or acct ...1234, at most 100 characters in all; ask again with a new request_id" {
		t.Fatalf("wording changed: %q", RecipientsNotTextable)
	}
	const want = "gcfg.LocalUI = cfg.PageSocket != nil"
	// Every package but grants itself (L3 F2 on #322): a setter in any
	// other main or library package fails too.
	for _, dir := range []string{".."} {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() && p == filepath.Join("..", "grants") {
				return fs.SkipDir
			}
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return err
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(string(b), "\n") {
				if strings.Contains(line, "LocalUI") && !strings.HasPrefix(strings.TrimSpace(line), "//") &&
					(p != filepath.Join("..", "daemon", "daemon.go") || strings.TrimSpace(line) != want) {
					t.Errorf("%s: %s", p, strings.TrimSpace(line))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// UX-144-1: an item that cannot be texted (here one asked under an
// earlier build's rules and carried over a restart) fails alone; the rest
// of its batch is still asked.
func TestAnUntextableItemDoesNotFailItsBatch(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.g.cfg.LocalUI = false // a build without the local page
	ok := r.effect("agent/b1", "message.send", map[string]any{"body": "hi"}, "sam@example.com")
	bad := r.effect("agent/b2", "message.send", map[string]any{"body": "yo"}, "dad@example.com")
	r.g.mu.Lock()
	r.g.waiting[bad.Intent.ID].item.Recipient = "Dad Smith"
	r.g.mu.Unlock()
	base := r.own.count()
	r.g.Flush()
	if r.own.count() != base+1 {
		t.Fatalf("%d requests", r.own.count()-base)
	}
	if st := r.state(ok.Intent.ID); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" {
		t.Fatalf("textable item: %s %q", st.State, st.Permission.Reason)
	}
	if st := r.state(bad.Intent.ID); st.State != journal.Denied || !strings.HasSuffix(st.Permission.Reason, RecipientsNotTextable) {
		t.Fatalf("untextable item: %s %q", st.State, st.Permission.Reason)
	}
}

// Potency R2 on P2-2a: page requests from one flush go to the owner
// channel together, so their notices share texts.
func TestPageRequestsInOneFlushAreAskedTogether(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Verifiers = nil })
	r.grant(mailGrant())
	r.own.local, r.own.localCalls = nil, 0 // the grant was asked there
	many := []string{"mom@example.com", "dad@example.com", "sis@example.com", "bro@example.com", "gran@example.com", "x@attacker.example"}
	a := r.effect("agent/q1", "message.send", map[string]any{"body": "hi"}, many...)
	b := r.effect("agent/q2", "message.send", map[string]any{"body": "yo"}, many...)
	r.g.Flush()
	r.own.mu.Lock()
	calls, local := r.own.localCalls, append([]string(nil), r.own.local...)
	r.own.mu.Unlock()
	if calls != 1 || len(local) != 2 {
		t.Fatalf("%d calls, local %v", calls, local)
	}
	for _, id := range []string{a.Intent.ID, b.Intent.ID} {
		if st := r.state(id); st.State != journal.Pending || !strings.HasPrefix(st.Permission.Reason, "waiting for the owner's approval on the local Wi-Fi page;") {
			t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
		}
	}
	// If the channel cannot ask, the agent is told so, not to wait.
	r.own.down = true
	c := r.effect("agent/q3", "message.send", map[string]any{"body": "hey"}, many...)
	r.g.Flush()
	if st := r.state(c.Intent.ID); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "could not ask the owner") {
		t.Fatalf("unasked: %s %q", st.State, st.Permission.Reason)
	}
}
