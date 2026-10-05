package mail_test

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

// ownerFake is the owner channel as the gate uses it. Auto-replies go
// through the real ADP-11 commitment filter (owner.Commitments, Mark's D2
// patterns), as owner.Channel.QueueAutoReply does.
type ownerFake struct {
	mu     sync.Mutex
	reqs   map[string][]owner.Item
	order  []string
	queued []owner.AutoReply
	now    func() time.Time
}

func (o *ownerFake) Request(items []owner.Item, _ time.Duration) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	id := fmt.Sprintf("R%d", len(o.order)+1)
	o.reqs[id] = append([]owner.Item(nil), items...)
	o.order = append(o.order, id)
	return id, nil
}

func (o *ownerFake) RequestEach(items []owner.Item, _ []time.Duration) ([]string, error) {
	var ids []string
	for _, it := range items {
		id, _ := o.Request([]owner.Item{it}, 0)
		ids = append(ids, id)
	}
	return ids, nil
}

func (o *ownerFake) Tier(f owner.Facts) owner.Tier {
	return owner.Classify(f, owner.Limits{AmountLimit: 50000}, o.now())
}
func (o *ownerFake) Active(time.Duration) bool { return true }
func (o *ownerFake) QueueAutoReply(ar owner.AutoReply) (owner.QueueResult, error) {
	if m := (owner.Commitments{}).Match(ar.Body); m != "" {
		id, err := o.Request([]owner.Item{{Ref: ar.Ref, Object: "reply (" + m + ")", Facts: ar.Facts}}, 0)
		return owner.QueueResult{Request: id, Matched: m}, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.queued = append(o.queued, ar)
	return owner.QueueResult{Queued: &owner.Queued{ID: "Q", SendAt: o.now().Add(10 * time.Minute), Reply: ar}}, nil
}
func (o *ownerFake) DueAutoReplies() []owner.Queued { return nil }
func (o *ownerFake) Inform(string) error            { return nil }

func (o *ownerFake) last() (string, []owner.Item) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.order) == 0 {
		return "", nil
	}
	id := o.order[len(o.order)-1]
	return id, o.reqs[id]
}

// gated is the adapter behind the real grants gate and journal engine.
type gated struct {
	*h
	g   *grants.Gate
	eng *journal.Engine
	own *ownerFake
}

func newGated(t *testing.T, edit func(*mail.Config)) *gated {
	t.Helper()
	var eng *journal.Engine
	x := newH(t, func(c *mail.Config) {
		c.Authorized = func(action string, since time.Time) []journal.Intent {
			return eng.AuthorizedSince("mail", action, since)
		}
		c.Contacts = func(a string) bool { return a == "sam@example.com" || a == "bob@example.com" }
		if edit != nil {
			edit(c)
		}
	})
	g := grants.New(grants.Config{Declared: map[string]map[string]string{"mail": mail.Declared()},
		Verifiers: map[string]grants.Verifier{"mail": x.a}, LocalUI: true, Now: func() time.Time { return x.now },
		Isolated: func(m string) bool { return m == "composer" }})
	own := &ownerFake{reqs: map[string][]owner.Item{}, now: func() time.Time { return x.now }}
	var err error
	eng, err = journal.Open(&journal.MemStore{}, g, map[string]journal.Executor{"mail": x.a, grants.ExecutorName: g},
		func(s string) string { return s }, journal.WithClock(func() time.Time { return x.now }))
	if err != nil {
		t.Fatal(err)
	}
	g.Attach(eng, own)
	r := &gated{h: x, g: g, eng: eng, own: own}
	r.grant(grants.Spec{Account: "mail", Executor: "mail", Ops: mail.Declared()})
	return r
}

func (r *gated) submit(in journal.Intent) journal.Status {
	r.t.Helper()
	st, err := r.g.Submit(in)
	if err != nil {
		r.t.Fatal(err)
	}
	if st.State == journal.Pending {
		st, _ = r.g.Authorize(ctx, in.ID)
	}
	if st.State == journal.Authorized {
		st, _ = r.g.Dispatch(ctx, in.ID)
	}
	return st
}

func (r *gated) decideAll(yes bool) {
	r.g.Flush()
	req, items := r.own.last()
	for i, it := range items {
		r.g.Decide(owner.Decision{Request: req, Item: i + 1, Ref: it.Ref, Approved: yes, Why: "owner"})
	}
	r.g.Wait()
}

// grant connects the account the way the owner does: code, then the
// local page.
func (r *gated) grant(s grants.Spec) {
	r.t.Helper()
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	id := fmt.Sprintf("local/grant/%d", len(r.eng.List()))
	st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: map[string]any{"grant": m}, Executor: grants.ExecutorName})
	if st.State != journal.Pending {
		r.t.Fatalf("grant: %s %q", st.State, st.Permission.Reason)
	}
	r.decideAll(true)
	if err := r.g.ConfirmLocal(id); err != nil {
		r.t.Fatal(err)
	}
	r.g.Wait()
}

func (r *gated) effect(action string, params map[string]any, recips ...string) (journal.Intent, journal.Status) {
	in := r.intent(action, params, recips...)
	in.Machine, in.Label = "agent", "private"
	return in, r.submit(in)
}

// REQ: ADP-2, REV-2, ADP-11

// TestGateRunsOrganizeAndAsksWhatTheGuardsFlag: through the real gate,
// archiving a newsletter runs unasked; archiving a security alert is
// asked as change-account with the source's line; a reply is asked with
// the thread's verified recipients and runs on YES.
func TestGateRunsOrganizeAndAsksWhatTheGuardsFlag(t *testing.T) {
	r := newGated(t, nil)
	id := r.news(1)
	if _, st := r.effect(mail.OpArchive, rec(id)); st.State != journal.Succeeded {
		t.Fatalf("archive: %s %q", st.State, st.Permission.Reason)
	}
	if folder, _, _ := r.srv.Find(id); folder != "Archive" {
		t.Fatalf("archived to %s", folder)
	}
	r.deliver("INBOX", msg{id: "<alert@x.example>", from: "someone@x.example", to: me, subject: "Unusual sign-in", body: "x"})
	if _, st := r.effect(mail.OpArchive, rec("<alert@x.example>")); st.State != journal.Pending {
		t.Fatalf("alert archive: %s", st.State)
	}
	r.g.Flush()
	_, items := r.own.last()
	if len(items) != 1 || items[0].Facts.Verb != "change-account" || items[0].Object != `archive "Unusual sign-in" from someone@x.example` || items[0].Unverified {
		t.Fatalf("asked %+v", items)
	}
	r.decideAll(true)
	if folder, _, _ := r.srv.Find("<alert@x.example>"); folder != "Archive" {
		t.Fatal("approved alert archive did not run")
	}
	// Trash is never a target, whatever the agent asks.
	if _, st := r.effect(mail.OpMove, map[string]any{"record": id, "to": "Trash"}); st.State != journal.Denied {
		t.Fatalf("move to trash: %s", st.State)
	}
	thread(r.h)
	if _, st := r.effect(mail.OpReply, reply("<t3@example.com>", "Sounds good."), "sam@example.com", "bob@example.com"); st.State != journal.Pending {
		t.Fatalf("reply: %s", st.State)
	}
	r.g.Flush()
	_, items = r.own.last()
	if items[0].Recipient != "bob@example.com, sam@example.com" || items[0].Facts.Verb != "send" || items[0].Unverified {
		t.Fatalf("reply line %+v", items[0])
	}
	r.decideAll(true)
	if len(r.srv.Submitted()) != 1 {
		t.Fatal("approved reply not sent")
	}
}

// TestReplyRuleQueuesOnlyCommitmentFreeReplies: under an ADP-11 reply
// rule, a composer's reply in a verified thread is queued with an undo
// window; one naming a date or a commitment phrase (D2) becomes a normal
// approval request; a cold thread, or one where a third party copied
// someone in, never matches the rule.
func TestReplyRuleQueuesOnlyCommitmentFreeReplies(t *testing.T) {
	r := newGated(t, nil)
	r.grant(grants.Spec{Account: "mail", Rule: &grants.Rule{Action: mail.OpReply, Reply: true, PerRecord: 3, PerDay: 10}})
	thread(r.h)
	composer := func(body string) journal.Status {
		in := r.intent(mail.OpReply, reply("<t2@example.com>", body), "sam@example.com")
		in.Machine, in.Label = "composer", "private"
		return r.submit(in)
	}
	if st := composer("Sounds good, thanks!"); st.State != journal.Pending || len(r.own.queued) != 1 {
		t.Fatalf("plain reply: %s, queued %d", st.State, len(r.own.queued))
	}
	// Queued for the undo window: nothing reaches SMTP until the gate
	// releases it after the window (grants GR11), so an UNDO in the
	// window means it is never submitted.
	r.g.Tick()
	if len(r.srv.Submitted()) != 0 {
		t.Fatal("a queued auto-reply was submitted inside its undo window")
	}
	before := len(r.own.order)
	for _, body := range []string{"I confirm.", "See you Tuesday.", "We agree to the terms."} {
		composer(body)
	}
	if len(r.own.queued) != 1 || len(r.own.order) != before+3 {
		t.Fatalf("commitments queued: %d queued, %d requests", len(r.own.queued), len(r.own.order)-before)
	}
	r.deliver("INBOX", msg{id: "<cold@x.example>", from: "stranger@x.example", to: me, subject: "Hi", body: "hello"})
	in := r.intent(mail.OpReply, reply("<cold@x.example>", "Thanks!"), "stranger@x.example")
	in.Machine = "composer"
	r.submit(in)
	if len(r.own.queued) != 1 {
		t.Fatal("a cold thread opened an auto-reply")
	}
	in = r.intent(mail.OpReply, reply("<t3@example.com>", "Thanks!"), "sam@example.com", "bob@example.com")
	in.Machine = "composer"
	r.submit(in)
	r.g.Tick()
	if len(r.own.queued) != 1 || len(r.srv.Submitted()) != 0 {
		t.Fatal("a third party's Cc opened an auto-reply")
	}
}
