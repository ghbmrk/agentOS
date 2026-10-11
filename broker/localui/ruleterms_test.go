package localui

import (
	"context"
	"encoding/json"
	"html"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/attention"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/verb"
)

// REQ: ADP-9, CH-3, CH-12

type noExec struct{}

func (noExec) Execute(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}
func (noExec) Reconcile(context.Context, journal.Intent, int) journal.Outcome {
	return journal.Outcome{Result: journal.ResultSucceeded}
}

// gateRig is an approval rig whose page is backed by the real gate and
// owner channel, so a grant's card is the one the gate asks with.
type gateRig struct {
	*approvalRig
	g   *grants.Gate
	eng *journal.Engine
}

func newGateRig(t *testing.T) *gateRig {
	t.Helper()
	a := newApprovalRig(t)
	g := grants.New(grants.Config{LocalUI: true, Now: a.clock, Declared: map[string]map[string]string{
		"mail": {"message.list": "read", "message.send": "send", "invoice.send": "send"}}})
	eng, err := journal.Open(&journal.MemStore{}, g, map[string]journal.Executor{"mail": noExec{}, grants.ExecutorName: g},
		func(s string) string { return s }, journal.WithClock(a.clock))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := owner.New(owner.Config{Owner: ownerNum, Modem: a.carrier.Line("+15550000077"), Engine: eng, Store: &owner.MemStore{},
		Secrets: owner.Secrets{TOTPSeed: a.hooks.seed, GridSeed: a.card.GridSeed}, Now: a.clock, Location: time.UTC,
		Decide: g.Decide, Narrow: g.Narrow})
	if err != nil {
		t.Fatal(err)
	}
	g.Attach(eng, ch)
	a.ch = ch
	a.served.Owner = ch
	return &gateRig{approvalRig: a, g: g, eng: eng}
}

func specParams(s grants.Spec) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	json.Unmarshal(b, &m)
	return map[string]any{"grant": m}
}

// ask submits a page grant change for s and returns its request's ID.
func (r *gateRig) ask(id string, s grants.Spec) string {
	r.t.Helper()
	in := journal.Intent{ID: id, Origin: "local", Account: journal.BrokerAccount, Action: journal.ActionGrantChange,
		Params: specParams(s), Executor: grants.ExecutorName}
	st, err := r.g.Submit(in)
	if err == nil && st.State == journal.Pending {
		st, err = r.g.Authorize(context.Background(), id)
	}
	if err != nil || st.State != journal.Pending {
		r.t.Fatalf("%s: %v %s %q", id, err, st.State, st.Permission.Reason)
	}
	r.g.Flush()
	for _, rq := range r.ch.LocalRequests() {
		if len(rq.Items) == 1 && rq.Items[0].Ref == id {
			return rq.ID
		}
	}
	r.t.Fatalf("%s is not on the page", id)
	return ""
}

func (r *gateRig) approve(rid string) string {
	r.t.Helper()
	r.advance(30 * time.Second) // a fresh code-generator step
	w := r.post("/approvals/", answer(r.form(rid), "approve", r.code()))
	r.g.Wait()
	return w.Body.String()
}

func (r *gateRig) state(id string) journal.State {
	r.t.Helper()
	st, err := r.eng.Get(id)
	if err != nil {
		r.t.Fatal(err)
	}
	return st.State
}

// card is request rid's card on the page, unescaped.
func (r *gateRig) card(rid string) string {
	r.t.Helper()
	p := r.get("/approvals/")
	i := strings.Index(p, "<h2>"+rid)
	if i < 0 {
		r.t.Fatalf("no card for %s:\n%s", rid, p)
	}
	j := strings.Index(p[i:], "</section>")
	return p[i : i+j]
}

func invoiceRule() grants.Spec {
	return grants.Spec{Account: "mail", Rule: &grants.Rule{Action: "invoice.send", Params: map[string]string{"template": "inv-std"},
		Recipients: []string{"billing@acme.example"}, AmountCap: 15000000, PerRecord: 25, PerDay: 50, HoldDays: 7}}
}

// SR3-3 (review F3): the final approval card the page shows for a
// pre-allowance names every consequential field of the rule in the
// broker's wording, on the same card as the code that approves it.
func TestSR3_3ThePageCardShowsTheWholeRule(t *testing.T) {
	r := newGateRig(t)
	if p := r.approve(r.ask("local/g1", grants.Spec{Account: "mail", Executor: "mail",
		Ops: map[string]string{"message.list": "read", "invoice.send": "send"}})); !strings.Contains(p, "Approved") {
		t.Fatalf("connect: %s", p)
	}
	rid := r.ask("local/r1", invoiceRule())
	c := html.UnescapeString(r.card(rid))
	for _, want := range []string{
		"pre-allow invoice.send on mail, 50/day",
		"Runs:</b> invoice.send on mail, without asking or notifying you",
		"When:</b> every field comes from the source record",
		"Fixed field:</b> template=inv-std",
		"Recipients:</b> only those of billing@acme.example the source record names",
		"Amount:</b> up to 150000.00",
		"Per record:</b> at most 25 runs per source record per day",
		"Per day:</b> at most 50 runs",
		"Recent edits:</b> a record edited in the last 7 days needs your approval",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("card lacks %q:\n%s", want, c)
		}
	}
	if i, j := strings.Index(c, "Recent edits:"), strings.Index(c, `value="approve"`); i < 0 || j < i {
		t.Fatal("the rule is not on the card above its approve button")
	}
	// One code approves it; no second confirmation.
	if p := r.approve(rid); !strings.Contains(p, "Approved "+rid) {
		t.Fatalf("approve: %s", p)
	}
	if st := r.state("local/r1"); st != journal.Succeeded {
		t.Fatalf("rule: %s", st)
	}
}

// SR3-3: changing any one authority-bearing field changes what the
// owner sees on the card; the form for the prior card does not approve
// the changed one; and record values on the card are escaped and shown
// as code points.
func TestSR3_3EachRuleFieldChangesTheCard(t *testing.T) {
	r := newGateRig(t)
	r.approve(r.ask("local/g1", grants.Spec{Account: "mail", Executor: "mail",
		Ops: map[string]string{"message.list": "read", "invoice.send": "send", "message.send": "send"}}))
	shown := func(rid string) string {
		c := r.card(rid)
		// Only what the owner reads: drop the form's ids and tokens.
		c = c[strings.Index(c, "</h2>"):]
		return c[:strings.Index(c, "<form")]
	}
	base := r.ask("local/base", invoiceRule())
	baseCard, baseForm := shown(base), r.form(base)
	edits := []func(*grants.Rule){
		func(x *grants.Rule) { x.Action = "message.send" },
		func(x *grants.Rule) { x.Params = map[string]string{"template": "inv-alt"} },
		func(x *grants.Rule) { x.Recipients = []string{"billing@acme.example", "ops@acme.example"} },
		func(x *grants.Rule) { x.Recipients = nil },
		func(x *grants.Rule) { x.AmountCap = 15000001 },
		func(x *grants.Rule) { x.PerRecord = 24 },
		func(x *grants.Rule) { x.PerDay = 49 },
		func(x *grants.Rule) { x.HoldDays = 0 },
	}
	for i, edit := range edits {
		s := invoiceRule()
		edit(s.Rule)
		rid := r.ask("local/e"+string(rune('a'+i)), s)
		if got := shown(rid); strings.ReplaceAll(got, rid, base) == baseCard {
			t.Errorf("edit %d: card unchanged:\n%s", i, got)
		}
		// The prior card's sum, posted for this request, is refused.
		f := r.form(rid)
		f.Set("sum", baseForm.Get("sum"))
		r.advance(30 * time.Second)
		if p := r.post("/approvals/", answer(f, "approve", r.code())).Body.String(); strings.Contains(p, "Approved "+rid) {
			t.Errorf("edit %d: the prior card approved it", i)
		}
	}

	// Record values the rule fixes are escaped and shown as they are.
	s := invoiceRule()
	s.Rule.Params = map[string]string{"template": "<b>CANARY</b> іnv"}
	c := r.card(r.ask("local/x", s))
	if strings.Contains(c, "<b>CANARY") || strings.Contains(c, "і") ||
		!strings.Contains(html.UnescapeString(c), "template=<b>CANARY</b> [U+0456]nv") || !strings.Contains(c, "unusual character") {
		t.Fatalf("escaping:\n%s", c)
	}
}

// SR3-3: the card the page shows is the one the owner channel holds:
// every term crosses the socket between agentosd and the page as the
// channel holds it, and the page's sum is the channel's.
func TestSR3_3TheCardCrossesTheSocketWhole(t *testing.T) {
	r := newGateRig(t)
	r.approve(r.ask("local/g1", grants.Spec{Account: "mail", Executor: "mail", Ops: map[string]string{"invoice.send": "send"}}))
	rid := r.ask("local/r1", invoiceRule())
	var held owner.LocalRequest
	for _, rq := range r.ch.LocalRequests() {
		if rq.ID == rid {
			held = rq
		}
	}
	var terms []owner.Term
	if len(held.Items) == 1 {
		terms, _ = held.Items[0].Terms.List()
	}
	if len(terms) < 8 {
		t.Fatalf("held: %+v", held)
	}
	if got := r.form(rid).Get("sum"); got != held.Sum {
		t.Fatalf("page sum %s, channel %s", got, held.Sum)
	}
	c := html.UnescapeString(r.card(rid))
	for _, tm := range terms {
		if !strings.Contains(c, "<b>"+tm.Label+":</b> "+tm.Value+"</li>") {
			t.Errorf("card lacks %+v:\n%s", tm, c)
		}
	}
}

// SR3-3 (review F3, L3 point 2 on #433): an attention suggestion that
// carried Describe(X) does not stand in for the final card. When the
// final ask is X' (one field changed), the page shows X”s terms, not
// the suggestion's wording, and an approval bound to X's card is
// refused for X'.
func TestSR3_3ASuggestionIsNotTheFinalCard(t *testing.T) {
	r := newGateRig(t)
	r.approve(r.ask("local/g1", grants.Spec{Account: "mail", Executor: "mail", Ops: map[string]string{"invoice.send": "send"}}))
	o, err := attention.New(attention.Config{Store: &change.MemStore{}, Threshold: 2, UserContent: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := o.Observe(attention.Decision{Account: "mail", Action: "invoice.send", Verb: verb.Send, Approved: true, Verified: true,
			Params:     map[string]any{"template": "inv-std", attention.Record: "inv-" + string(rune('a'+i))},
			Recipients: []string{"billing@acme.example"}, Amount: 15000000, At: r.clock().Add(time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	sg, err := o.Suggestions()
	if err != nil || len(sg) != 1 || sg[0].Spec.Rule == nil || !strings.Contains(sg[0].Detail, "inv-std") {
		t.Fatalf("suggestion: %+v %v", sg, err)
	}
	x := sg[0].Spec
	xr := r.ask("local/x", x)
	xSum := r.form(xr).Get("sum")

	// X': the same suggestion with its fixed template changed.
	changed := *x.Rule
	changed.Params = map[string]string{"template": "inv-alt"}
	x2 := x
	x2.Rule = &changed
	x2r := r.ask("local/x2", x2)
	c := html.UnescapeString(r.card(x2r))
	if !strings.Contains(c, "Fixed field:</b> template=inv-alt") || strings.Contains(c, "inv-std") || strings.Contains(c, sg[0].Detail) {
		t.Fatalf("X' card does not carry X''s own terms:\n%s", c)
	}
	f := r.form(x2r)
	f.Set("sum", xSum)
	r.advance(30 * time.Second)
	if p := r.post("/approvals/", answer(f, "approve", r.code())).Body.String(); strings.Contains(p, "Approved "+x2r) {
		t.Fatal("X's card approved X'")
	}
	r.g.Wait()
	if st := r.state("local/x2"); st == journal.Succeeded {
		t.Fatal("X' was added on X's approval")
	}
}
