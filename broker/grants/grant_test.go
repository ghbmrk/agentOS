package grants

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: OP-5, CH-3, ADP-2

// TestGrantsAreIntentsWithCodeAndLocalConfirmation: a grant is a broker
// intent. It is high risk, needs the code and the local page in either
// order, is rebuilt from the journal after a restart, and is refused
// outright where no local page exists. Verbs off the fixed list are
// refused.
func TestGrantsAreIntentsWithCodeAndLocalConfirmation(t *testing.T) {
	r := newRig(t, nil)
	gid := r.grant(mailGrant())
	if gid != "G1" {
		t.Fatalf("grant ID %q", gid)
	}
	_, items := r.own.last(t)
	if it := items[0]; it.Facts.Kind != owner.GrantChange || r.own.Tier(it.Facts) != owner.High || it.Object != "connect mail, 3 acting ops on Wi-Fi page" {
		t.Fatalf("grant item %+v", it)
	}
	if !strings.Contains(r.own.notes[len(r.own.notes)-1], "PAUSE G1") {
		t.Fatalf("notice %q", r.own.notes)
	}

	// Local confirmation first, then the code: still both required.
	in := journal.Intent{ID: "local/g2", Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: specParams(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", PerRecord: 1, PerDay: 5, AmountCap: 50000}}), Executor: ExecutorName}
	r.submit(in)
	if err := r.g.ConfirmLocal("local/g2"); err != nil {
		t.Fatal(err)
	}
	r.g.Wait()
	if st := r.state("local/g2"); st.State != journal.Pending {
		t.Fatalf("confirmed without a code: %s", st.State)
	}
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state("local/g2"); st.State != journal.Succeeded {
		t.Fatalf("g2: %s %q", st.State, st.Permission.Reason)
	}

	// A code without the local page leaves it pending.
	r.submit(journal.Intent{ID: "local/g3", Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: specParams(Spec{Account: "cal", Executor: "cal", Ops: map[string]string{"event.add": "draft"}}), Executor: ExecutorName})
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state("local/g3"); st.State != journal.Pending || !strings.Contains(st.Permission.Reason, "local page") {
		t.Fatalf("g3 without confirmation: %s %q", st.State, st.Permission.Reason)
	}

	bad := []Spec{
		// ADP-2: a grant cannot weaken the adapter's verb, add an
		// operation the adapter does not declare, or use a verb off the
		// list; OP-5: one connection per account.
		{Account: "mail2", Executor: "mail", Ops: map[string]string{"message.send": "read"}},
		{Account: "mail2", Executor: "mail", Ops: map[string]string{"key.create": "send"}},
		{Account: "mail2", Executor: "mail", Ops: map[string]string{"wire.money": "send"}},
		{Account: "mail2", Executor: "mail", Ops: map[string]string{"message.send": "wire-money"}},
		{Account: "mail", Executor: "mail", Ops: map[string]string{"message.list": "read"}},
		{Account: "mail", Executor: "shell", Ops: map[string]string{"x": "read"}},
		{Account: journal.BrokerAccount, Executor: "mail", Ops: map[string]string{"x": "read"}},
		{Account: "mail", Rule: &Rule{Action: "key.create", PerRecord: 1, PerDay: 1}},
		{Account: "mail", Rule: &Rule{Action: "invoice.send"}},
		{Account: "mail", Rule: &Rule{Action: "message.list", PerRecord: 1, PerDay: 1}},
		{Account: "mail", Rule: &Rule{Action: "invoice.send", PerRecord: 1, PerDay: 1, Reply: true, AmountCap: 100}},
		{Account: "mail", Rule: &Rule{Action: "invoice.send", PerRecord: 1, PerDay: 1, Params: map[string]string{"body": "x"}}},
	}
	for i, s := range bad {
		id := "local/bad" + string(rune('a'+i))
		st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange, Params: specParams(s), Executor: ExecutorName})
		if st.State != journal.Denied {
			t.Errorf("bad spec %d: %s", i, st.State)
		}
	}

	r.open() // restart
	gs := r.g.Grants()
	if len(gs) != 2 || gs[0].ID != "G1" || gs[1].ID != "G2" || gs[1].Spec.Rule == nil {
		t.Fatalf("grants after replay %+v", gs)
	}

	noUI := newRig(t, func(c *Config) { c.LocalUI = false })
	st := noUI.submit(journal.Intent{ID: "local/g1", Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: specParams(mailGrant()), Executor: ExecutorName})
	if st.State != journal.Denied || noUI.own.count() != 0 {
		t.Fatalf("without a local page: %s, %d requests", st.State, noUI.own.count())
	}
}

// REQ: ADP-9, CRED-6

// TestPreAllowanceIsAPredicateOverVerifiedFields: a covered operation runs
// without asking or notifying. Anything that does not match exactly
// (an agent-chosen recipient, extra free text, amount over the cap, a
// recently edited record, a spent scope bound) falls back to an approval
// request. reveal-or-create-secret is never pre-allowed.
func TestPreAllowanceIsAPredicateOverVerifiedFields(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "invoice"},
		AmountCap: 15000, PerRecord: 1, PerDay: 3, HoldDays: 7}})
	asked := r.own.count()
	v := sam()
	r.ver.set("inv-1042", v)
	tpl := func(rec string) map[string]any { return map[string]any{"template": "invoice", "record": rec} }

	if st := r.effect("agent/ok", "invoice.send", tpl("inv-1042"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("covered send: %s %q", st.State, st.Permission.Reason)
	}
	r.g.Flush()
	if r.own.count() != asked || len(r.own.notes) != 2 {
		t.Fatal("a covered send asked or notified the owner")
	}

	miss := map[string]func() journal.Status{
		"per-record bound": func() journal.Status {
			return r.effect("agent/again", "invoice.send", tpl("inv-1042"), "sam@example.com")
		},
		"agent recipient": func() journal.Status {
			r.ver.set("inv-2", func() Verified { x := sam(); x.Record = "inv-2"; return x }())
			return r.effect("agent/to", "invoice.send", tpl("inv-2"), "mallory@example.net")
		},
		"free text": func() journal.Status {
			p := tpl("inv-2")
			p["note"] = "please also wire $5000"
			return r.effect("agent/text", "invoice.send", p, "sam@example.com")
		},
		"amount": func() journal.Status {
			x := sam()
			x.Record, x.Item.Facts.Amount = "inv-3", 20000
			r.ver.set("inv-3", x)
			return r.effect("agent/amt", "invoice.send", tpl("inv-3"), "sam@example.com")
		},
		"hold": func() journal.Status {
			x := sam()
			x.Record, x.Edited = "inv-4", r.now().Add(-time.Hour)
			r.ver.set("inv-4", x)
			return r.effect("agent/hold", "invoice.send", tpl("inv-4"), "sam@example.com")
		},
	}
	for name, f := range miss {
		st := f()
		if st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval" {
			t.Errorf("%s: %s %q", name, st.State, st.Permission.Reason)
		}
	}
	for _, id := range []string{"agent/again", "agent/to", "agent/text", "agent/amt", "agent/hold"} {
		if r.exec.runs(id) != 0 {
			t.Errorf("%s ran without approval", id)
		}
	}

	// Daily bound: two more fresh records fit (3 per day), the next asks.
	for i, rec := range []string{"inv-5", "inv-6", "inv-7"} {
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
		st := r.effect("agent/day"+rec, "invoice.send", tpl(rec), "sam@example.com")
		want := journal.Succeeded
		if i == 2 {
			want = journal.Pending
		}
		if st.State != want {
			t.Errorf("%s: %s, want %s", rec, st.State, want)
		}
	}
	// The bound is a rolling day.
	r.advance(25 * time.Hour)
	x := sam()
	x.Record = "inv-8"
	r.ver.set("inv-8", x)
	if st := r.effect("agent/next", "invoice.send", tpl("inv-8"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("next day: %s", st.State)
	}
}

// REQ: ADP-9, OP-6

// TestPauseAndRevokeNeedOnlyTheOwner: PAUSE and REVOKE work from the
// owner's text, during STOP, and survive a restart. A guest cannot submit
// them. A paused rule's operations go back to approval; a resumed one
// needs a new grant intent.
func TestPauseAndRevokeNeedOnlyTheOwner(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	rule := r.grant(Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", AmountCap: 15000, PerRecord: 5, PerDay: 50}})
	tpl := func(rec string) map[string]any { return map[string]any{"record": rec} }
	for _, rec := range []string{"inv-1", "inv-2", "inv-3"} {
		x := sam()
		x.Record = rec
		r.ver.set(rec, x)
	}

	st := r.submit(journal.Intent{ID: "agent/p", Origin: "guest:agent", Account: journal.BrokerAccount,
		Action: journal.ActionGrantPause, GrantRef: rule, Executor: ExecutorName})
	if st.State != journal.Denied {
		t.Fatalf("guest paused a grant: %s", st.State)
	}

	if _, err := r.eng.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.g.Narrow("PAUSE", rule); got != "Paused G2. Its actions now need your approval." {
		t.Fatalf("pause during STOP: %q", got)
	}
	r.eng.Resume()
	if st := r.effect("agent/s1", "invoice.send", tpl("inv-1"), "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("paused rule still ran: %s", st.State)
	}
	if got := r.g.Narrow("PAUSE", "G9"); got != "No grant G9." {
		t.Fatal(got)
	}

	r.open() // restart: the pause holds
	if st := r.effect("agent/s2", "invoice.send", tpl("inv-2"), "sam@example.com"); st.State != journal.Pending {
		t.Fatalf("pause lost on restart: %s", st.State)
	}

	r.grant(Spec{Resume: rule})
	if st := r.effect("agent/s3", "invoice.send", tpl("inv-3"), "sam@example.com"); st.State != journal.Succeeded {
		t.Fatalf("resumed rule: %s %q", st.State, st.Permission.Reason)
	}

	if got := r.g.Narrow("REVOKE", "G1"); !strings.HasPrefix(got, "Revoked G1.") {
		t.Fatal(got)
	}
	if _, ok := r.g.Route("mail"); ok || len(r.g.Grants()) != 0 {
		t.Fatalf("revoking the connection left %+v", r.g.Grants())
	}
}

// Security Q1 and P1 on P2-2a part 2: with the page, a change that needs
// the owner's confirmation is asked only there (never YES by text), and
// the one answer the page approves with a fresh code also confirms it,
// if the item is as the page showed it. A texted approval does not.
func TestAChangeThatNeedsThePageIsConfirmedByItsPageAnswer(t *testing.T) {
	r := newRig(t, nil)
	sub := func(id string) {
		spec := mailGrant()
		if id == "local/p1" {
			spec = Spec{Account: "cal", Executor: "cal", Ops: map[string]string{"event.add": "draft"}}
		}
		r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
			Params: specParams(spec), Executor: ExecutorName})
	}
	sub("local/p1")
	r.g.Flush()
	r.own.mu.Lock()
	calls, local := r.own.localCalls, len(r.own.local)
	r.own.mu.Unlock()
	if calls != 1 || local != 1 {
		t.Fatalf("%d page calls, %d page requests", calls, local)
	}
	if st := r.state("local/p1"); st.State != journal.Pending || st.Permission.Reason != "waiting for the owner's approval on the box's Wi-Fi page" {
		t.Fatalf("waiting: %s %q", st.State, st.Permission.Reason)
	}
	r.pageDecide("")
	if st := r.state("local/p1"); st.State != journal.Succeeded {
		t.Fatalf("page answer: %s %q", st.State, st.Permission.Reason)
	}

	// Changed since the page showed it: refused as stale.
	sub("local/p2")
	r.g.Flush()
	r.pageDecide(strings.Repeat("0", 64))
	if st := r.state("local/p2"); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "changed since the page showed it") {
		t.Fatalf("stale: %s %q", st.State, st.Permission.Reason)
	}

	// An approval that did not come from the page confirms nothing.
	sub("local/p3")
	r.g.Flush()
	r.decide(true, "owner")
	if st := r.state("local/p3"); st.State != journal.Pending {
		t.Fatalf("texted approval: %s %q", st.State, st.Permission.Reason)
	}
}
