package grants

import (
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: ADP-9, CH-3, CH-12

// invoiceRule is SR3-3's synthetic rule: an operation on a service, a
// recipient restriction, a fixed template, an amount cap, per-record and
// daily bounds, and a recent-edit hold.
func invoiceRule() Spec {
	return Spec{Account: "mail", Rule: &Rule{Action: "invoice.send", Params: map[string]string{"template": "inv-std"},
		Recipients: []string{"billing@acme.example"}, AmountCap: 15000000, PerRecord: 25, PerDay: 50, HoldDays: 7}}
}

// askRule submits s as a page grant change and returns the item the gate
// asks the owner with.
func (r *rig) askRule(id string, s Spec) owner.Item {
	r.t.Helper()
	st := r.submit(journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount,
		Action: journal.ActionGrantChange, Params: specParams(s), Executor: ExecutorName})
	if st.State != journal.Pending {
		r.t.Fatalf("%s: %s %q", id, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	_, items := r.own.last(r.t)
	if len(items) != 1 || items[0].Ref != id {
		r.t.Fatalf("%s: asked %+v", id, items)
	}
	return items[0]
}

func termsText(l owner.TermList) string {
	ts, _ := l.List()
	var b strings.Builder
	for _, t := range ts {
		b.WriteString(t.Label + ": " + t.Value + "\n")
	}
	return b.String()
}

// SR3-3 (review F3): the item the gate asks a pre-allowance with carries
// every consequential field of the rule in broker wording, beside the
// short line the text keeps.
func TestSR3_3RuleApprovalCarriesTheWholeRule(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	it := r.askRule("local/r1", invoiceRule())
	if it.Object != "pre-allow invoice.send on mail, 50/day" || it.Detail != "" {
		t.Fatalf("short line changed: %q %q", it.Object, it.Detail)
	}
	got := termsText(it.Terms)
	for _, want := range []string{
		"Runs: invoice.send on mail, without asking or notifying you",
		"When: every field comes from the source record",
		"Fixed field: template=inv-std",
		"Recipients: only those of billing@acme.example the source record names",
		"Amount: up to 150000.00",
		"Per record: at most 25 runs per source record per day",
		"Per day: at most 50 runs",
		"Recent edits: a record edited in the last 7 days needs your approval",
	} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("terms lack %q:\n%s", want, got)
		}
	}
}

// SR3-3: changing any one authority-bearing field changes what the card
// shows and the sum the owner's approval is bound to, and an approval of
// the prior rule's card does not approve the changed rule.
func TestSR3_3EachRuleFieldChangesTheCardAndItsBinding(t *testing.T) {
	r := newRig(t, nil)
	r.grant(mailGrant())
	r.grant(Spec{Account: "books", Executor: "mail", Ops: mailOps()})
	base := r.askRule("local/base", invoiceRule())
	edits := map[string]func(*Rule){
		"action":         func(x *Rule) { x.Action = "message.send" },
		"template value": func(x *Rule) { x.Params = map[string]string{"template": "inv-alt"} },
		"template key":   func(x *Rule) { x.Params = map[string]string{"layout": "inv-std"} },
		"no template":    func(x *Rule) { x.Params = nil },
		"recipient":      func(x *Rule) { x.Recipients = []string{"billing@acme.example", "ops@acme.example"} },
		"no recipients":  func(x *Rule) { x.Recipients = nil },
		"amount":         func(x *Rule) { x.AmountCap = 15000001 },
		"no amount":      func(x *Rule) { x.AmountCap = 0 },
		"per record":     func(x *Rule) { x.PerRecord = 24 },
		"hold":           func(x *Rule) { x.HoldDays = 6 },
		"no hold":        func(x *Rule) { x.HoldDays = 0 },
	}
	// Fields the short line already shows are covered by the same check.
	edits["per day"] = func(x *Rule) { x.PerDay = 49 }
	edits["reply"] = func(x *Rule) { x.Reply, x.AmountCap = true, 0 }
	edits["account"] = func(*Rule) {} // the loop moves the rule to books
	i := 0
	for name, edit := range edits {
		i++
		s := invoiceRule()
		edit(s.Rule)
		if name == "account" {
			s.Account = "books"
		}
		id := "local/e" + string(rune('a'+i))
		it := r.askRule(id, s)
		if termsText(it.Terms) == termsText(base.Terms) {
			t.Errorf("%s: card terms unchanged:\n%s", name, termsText(it.Terms))
		}
		if owner.ItemSum(it) == owner.ItemSum(base) {
			t.Errorf("%s: approval binding unchanged", name)
		}
		// The page's approval of the prior rule's card, carried to this
		// rule's request, is refused.
		r.pageDecide(owner.ItemSum(base))
		if st := r.state(id); st.State != journal.Denied {
			t.Errorf("%s: approval of the prior card left it %s", name, st.State)
		}
	}
	// The unchanged rule, approved as shown, is added.
	r.askRule("local/same", invoiceRule())
	r.pageDecide("")
	if st := r.state("local/same"); st.State != journal.Succeeded {
		t.Fatalf("unchanged rule: %s %q", st.State, st.Permission.Reason)
	}
}

// SR3-3: an adapter grant's card lists every operation it allows with its
// verb, and a reply rule's card says who replies may go to.
func TestSR3_3GrantAndReplyCardsCarryTheirScope(t *testing.T) {
	got := termsText(owner.NewTerms(Terms(mailGrant())))
	for _, want := range []string{"Account: mail, through mail", "Allows: invoice.send (send)", "Allows: key.create (reveal-or-create-secret)",
		"Allows: message.list (read)", "Without asking: reads, drafts; every other verb needs your approval or a pre-allowance"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("grant terms lack %q:\n%s", want, got)
		}
	}
	// An organize op runs without asking behind the account's guard, so
	// the card says so.
	got = termsText(owner.NewTerms(Terms(Spec{Account: "mail", Executor: "mail", Ops: map[string]string{"label.add": "organize"}})))
	if want := "Without asking: organize changes that undo in the account, when its guard allows them; every other verb needs your approval or a pre-allowance"; !strings.Contains(got, want+"\n") {
		t.Errorf("organize grant terms lack %q:\n%s", want, got)
	}
	got = termsText(owner.NewTerms(Terms(Spec{Account: "mail", Rule: &Rule{Action: "message.send", PerRecord: 3, PerDay: 10, Reply: true}})))
	for _, want := range []string{"Runs: message.send on mail, as agent replies texted to you first; each sends after the undo window unless you reply UNDO",
		"When: the reply is in an existing thread", "Recipients: the thread's own participants only", "Amount: no money may move"} {
		if !strings.Contains(got, want+"\n") {
			t.Errorf("reply terms lack %q:\n%s", want, got)
		}
	}
	if Terms(Spec{Resume: "G1"}) != nil {
		t.Fatal("a resume's card carries the paused grant's description in its detail")
	}
}
