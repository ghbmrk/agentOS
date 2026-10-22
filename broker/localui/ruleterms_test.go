package localui

import (
	"html"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/attention"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: KEY-5, KEY-2, CH-3, CH-12

// keyItem is the page's ask for a standing key on clerk with caveats cs:
// its terms are the key's fixed wording, one per caveat (attention.Describe),
// so the card is rendered from the caveats the passkey tap would sign.
func keyItem(ref, clerk string, cs []key.Caveat) owner.Item {
	ds := attention.Describe(clerk, cs)
	ts := make([]owner.Term, len(ds))
	for i, d := range ds {
		ts[i] = owner.Term{Label: d.Label, Value: d.Value}
	}
	return owner.Item{Ref: ref, Object: "a standing key on " + clerk, Terms: owner.NewTerms(ts),
		Facts: owner.Facts{Kind: owner.GrantChange, Verb: "grant", NoRecipient: true}}
}

// ask puts the key on the page and returns its request's ID.
func (a *approvalRig) ask(ref, clerk string, cs []key.Caveat) string {
	a.t.Helper()
	id, err := a.ch.RequestLocal(keyItem(ref, clerk, cs), 0)
	if err != nil {
		a.t.Fatalf("%s: %v", ref, err)
	}
	return id
}

func (a *approvalRig) approve(rid string) string {
	a.t.Helper()
	a.advance(30 * time.Second) // a fresh code-generator step
	return a.post("/approvals/", answer(a.form(rid), "approve", a.code())).Body.String()
}

// approved reports whether the owner channel decided ref approved.
func (a *approvalRig) approved(ref string) bool {
	for _, d := range a.decided() {
		if d.Ref == ref && d.Approved {
			return true
		}
	}
	return false
}

// cardOf is request rid's card on the page.
func (a *approvalRig) cardOf(rid string) string {
	a.t.Helper()
	p := a.get("/approvals/")
	i := strings.Index(p, "<h2>"+rid)
	if i < 0 {
		a.t.Fatalf("no card for %s:\n%s", rid, p)
	}
	j := strings.Index(p[i:], "</section>")
	return p[i : i+j]
}

func invoiceKey() []key.Caveat {
	return []key.Caveat{key.LimitVerbs(key.Send), key.LimitContent("template:inv-std"),
		key.LimitArg(key.ArgBound{Name: "to", OneOf: []string{"billing@acme.example"}}),
		key.LimitRate(50), key.LimitRateRecipient(25), key.LimitHold(600000, 900000)}
}

// SR3-3 (review F3), KEY-5: the final approval card the page shows for a
// standing key names every caveat of the key in fixed wording, on the same
// card as the code that approves it.
func TestSR3_3ThePageCardShowsTheWholeKey(t *testing.T) {
	a := newApprovalRig(t)
	rid := a.ask("k1", "mail", invoiceKey())
	c := html.UnescapeString(a.cardOf(rid))
	for _, want := range []string{
		"a standing key on mail",
		"Clerk:</b> mail",
		"Runs:</b> send, without asking or notifying you",
		"Content:</b> only template:inv-std",
		"Argument to:</b> only billing@acme.example",
		"Per day:</b> at most 50 runs",
		"Per recipient:</b> at most 25 runs a day",
		"Hold:</b> 10m0s before it runs, 15m0s when new",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("card lacks %q:\n%s", want, c)
		}
	}
	if i, j := strings.Index(c, "Hold:"), strings.Index(c, `value="approve"`); i < 0 || j < i {
		t.Fatal("the key is not on the card above its approve button")
	}
	// One code approves it; no second confirmation.
	if p := a.approve(rid); !strings.Contains(p, "Approved "+rid) || !a.approved("k1") {
		t.Fatalf("approve: %s", p)
	}
}

// SR3-3, KEY-2: changing any one caveat changes what the owner sees on the
// card; the form for the prior card does not approve the changed one; and
// values on the card are escaped and shown as code points.
func TestSR3_3EachCaveatChangesTheCard(t *testing.T) {
	a := newApprovalRig(t)
	shown := func(rid string) string {
		c := a.cardOf(rid)
		// Only what the owner reads: drop the form's ids and tokens.
		c = c[strings.Index(c, "</h2>"):]
		return c[:strings.Index(c, "<form")]
	}
	base := a.ask("base", "mail", invoiceKey())
	baseCard, baseForm := shown(base), a.form(base)
	edits := []func([]key.Caveat) []key.Caveat{
		func(cs []key.Caveat) []key.Caveat { cs[0] = key.LimitVerbs(key.Post); return cs },
		func(cs []key.Caveat) []key.Caveat { cs[1] = key.LimitContent("template:inv-alt"); return cs },
		func(cs []key.Caveat) []key.Caveat {
			cs[2] = key.LimitArg(key.ArgBound{Name: "to", OneOf: []string{"billing@acme.example", "ops@acme.example"}})
			return cs
		},
		func(cs []key.Caveat) []key.Caveat { return append(cs[:2], cs[3:]...) },
		func(cs []key.Caveat) []key.Caveat { cs[3] = key.LimitRate(49); return cs },
		func(cs []key.Caveat) []key.Caveat { cs[4] = key.LimitRateRecipient(24); return cs },
		func(cs []key.Caveat) []key.Caveat { cs[5] = key.LimitHold(0, 900000); return cs },
		func(cs []key.Caveat) []key.Caveat { return append(cs, key.LimitSpendDay(1)) },
	}
	for i, edit := range edits {
		rid := a.ask("e"+string(rune('a'+i)), "mail", edit(invoiceKey()))
		if got := shown(rid); strings.ReplaceAll(got, rid, base) == baseCard {
			t.Errorf("edit %d: card unchanged:\n%s", i, got)
		}
		// The prior card's sum, posted for this request, is refused.
		f := a.form(rid)
		f.Set("sum", baseForm.Get("sum"))
		a.advance(30 * time.Second)
		if p := a.post("/approvals/", answer(f, "approve", a.code())).Body.String(); strings.Contains(p, "Approved "+rid) {
			t.Errorf("edit %d: the prior card approved it", i)
		}
	}

	// Caveat values are escaped and shown as they are.
	cs := invoiceKey()
	cs[1] = key.LimitContent("<b>CANARY</b> іnv")
	c := a.cardOf(a.ask("x", "mail", cs))
	if strings.Contains(c, "<b>CANARY") || strings.Contains(c, "і") ||
		!strings.Contains(html.UnescapeString(c), "only <b>CANARY</b> [U+0456]nv") || !strings.Contains(c, "unusual character") {
		t.Fatalf("escaping:\n%s", c)
	}
}

// SR3-3: the card the page shows is the one the owner channel holds:
// every term crosses the socket between agentosd and the page as the
// channel holds it, and the page's sum is the channel's.
func TestSR3_3TheCardCrossesTheSocketWhole(t *testing.T) {
	a := newApprovalRig(t)
	rid := a.ask("k1", "mail", invoiceKey())
	var held owner.LocalRequest
	for _, rq := range a.ch.LocalRequests() {
		if rq.ID == rid {
			held = rq
		}
	}
	var terms []owner.Term
	if len(held.Items) == 1 {
		terms, _ = held.Items[0].Terms.List()
	}
	if len(terms) != len(invoiceKey())+1 {
		t.Fatalf("held: %+v", held)
	}
	if got := a.form(rid).Get("sum"); got != held.Sum {
		t.Fatalf("page sum %s, channel %s", got, held.Sum)
	}
	c := html.UnescapeString(a.cardOf(rid))
	for _, tm := range terms {
		if !strings.Contains(c, "<b>"+tm.Label+":</b> "+tm.Value+"</li>") {
			t.Errorf("card lacks %+v:\n%s", tm, c)
		}
	}
}

// SR3-3 (review F3, L3 point 2 on #433), KEY-5: a suggestion that carried
// Describe(X) does not stand in for the final card. When the final ask is
// X' (one caveat changed), the page shows X”s terms, not the
// suggestion's wording, and an approval bound to X's card is refused for
// X'.
func TestSR3_3ASuggestionIsNotTheFinalCard(t *testing.T) {
	a := newApprovalRig(t)
	o, err := attention.New(attention.Config{Store: &memBytes{}, Threshold: 2, UserContent: func(string) bool { return false }})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := o.Observe(attention.Decision{Clerk: "mail", Verb: key.Send, Approved: true, Verified: true, Content: "template:inv-std",
			Recipients: []string{"billing@acme.example"}, At: a.clock().Add(time.Duration(i) * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	sg, err := o.Suggestions()
	if err != nil || len(sg) != 1 || !strings.Contains(sg[0].Text, "send on mail") {
		t.Fatalf("suggestion: %+v %v", sg, err)
	}
	x := sg[0].Caveats
	xr := a.ask("x", sg[0].Clerk, x)
	xSum := a.form(xr).Get("sum")

	// X': the same suggestion with its template changed.
	x2 := append([]key.Caveat(nil), x...)
	for i, c := range x2 {
		if c.Kind == key.KContent {
			x2[i] = key.LimitContent("template:inv-alt")
		}
	}
	x2r := a.ask("x2", sg[0].Clerk, x2)
	c := html.UnescapeString(a.cardOf(x2r))
	if !strings.Contains(c, "Content:</b> only template:inv-alt") || strings.Contains(c, "inv-std") {
		t.Fatalf("X' card does not carry X''s own terms:\n%s", c)
	}
	f := a.form(x2r)
	f.Set("sum", xSum)
	a.advance(30 * time.Second)
	if p := a.post("/approvals/", answer(f, "approve", a.code())).Body.String(); strings.Contains(p, "Approved "+x2r) || a.approved("x2") {
		t.Fatal("X's card approved X'")
	}
}

// memBytes is an attention.Store in memory.
type memBytes struct{ b []byte }

func (m *memBytes) Load() ([]byte, error) { return m.b, nil }
func (m *memBytes) Save(b []byte) error   { m.b = append([]byte(nil), b...); return nil }
