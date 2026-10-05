package attention

// REQ: CAP-6, ADP-9, ADP-11, A10

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/grants"
	"github.com/ghbmrk/agentos/broker/verb"
)

var t0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

func newOpt(t *testing.T, st Store, mod func(*Config)) *Optimizer {
	t.Helper()
	cfg := Config{Store: st}
	if mod != nil {
		mod(&cfg)
	}
	o, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// invoice is a verified, templated send: the template is fixed and the
// record is read from the source.
func invoice(i int) Decision {
	return Decision{Account: "books", Action: "invoice.send", Verb: verb.Send, Approved: true, Verified: true,
		Params:     map[string]any{"template": "monthly", Record: "inv-" + strconv.Itoa(i)},
		Recipients: []string{"ap@client.test"}, At: t0.Add(time.Duration(i) * 6 * time.Hour)}
}

func observe(t *testing.T, o *Optimizer, ds ...Decision) {
	t.Helper()
	for _, d := range ds {
		if err := o.Observe(d); err != nil {
			t.Fatal(err)
		}
	}
}

func suggestions(t *testing.T, o *Optimizer) []Suggestion {
	t.Helper()
	s, err := o.Suggestions()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// CAP-6, ADP-9: a class approved unchanged Threshold times in a row earns a
// suggestion: a deterministic rule with the fixed params, the recipients
// that never changed, scope bounds from what was approved, and the owner's
// line in fixed wording with its evidence.
func TestSuggestsAfterRunOfApprovals(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 9; i++ {
		observe(t, o, invoice(i))
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("suggested before the run was earned: %+v", s)
	}
	observe(t, o, invoice(9))
	s := suggestions(t, o)
	if len(s) != 1 {
		t.Fatalf("%+v", s)
	}
	r := s[0].Spec.Rule
	if s[0].Spec.Account != "books" || r.Action != "invoice.send" || r.Params["template"] != "monthly" || len(r.Params) != 1 ||
		len(r.Recipients) != 1 || r.Recipients[0] != "ap@client.test" || r.PerRecord != 1 || r.PerDay != 4 || r.AmountCap != 0 || r.Reply {
		t.Fatalf("rule %+v", r)
	}
	if s[0].Short != "S1" || s[0].Approved != 10 || s[0].Detail != grants.Describe(s[0].Spec) || !strings.Contains(s[0].Text, "up to 4 a day, no money.") ||
		!strings.Contains(s[0].Text, "10 times in a row since Oct 5") || !strings.HasSuffix(s[0].Text, "Reply NO S1 to stop suggesting it.") {
		t.Fatalf("text %q", s[0].Text)
	}
	if again := suggestions(t, o); again[0].Short != "S1" {
		t.Fatal("a suggestion keeps its ID")
	}
}

// CAP-6: a NO, an UNDO, or an edit resets the run; an expiry does not; approvals of
// different recipients leave the recipients to the source record; an
// amount sets the cap and a hold.
func TestRunResetsAndShapesRule(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 8; i++ {
		observe(t, o, invoice(i))
	}
	d := invoice(8)
	d.Edited = true
	observe(t, o, d)
	for i := 0; i < 9; i++ {
		observe(t, o, invoice(10+i))
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatal("an edit must reset the run")
	}
	d = invoice(30)
	d.Approved = false
	observe(t, o, d)
	for i := 0; i < 10; i++ {
		d := invoice(40 + i)
		d.Recipients = []string{"x" + strconv.Itoa(i) + "@client.test"}
		d.Amount = int64(1000 * (i + 1))
		observe(t, o, d)
	}
	s := suggestions(t, o)
	if len(s) != 1 || len(s[0].Spec.Rule.Recipients) != 0 || s[0].Spec.Rule.AmountCap != 10000 || s[0].Spec.Rule.HoldDays != 3 {
		t.Fatalf("%+v", s)
	}
}

// CAP-6, ADP-9: never suggested: CRED-6 (reveal-or-create-secret), a
// reversible verb (needs no rule), a user-content service, a class whose
// fixed params changed or were not plain strings (no templated content).
// An unverified approval neither counts nor resets.
func TestExclusions(t *testing.T) {
	for name, mut := range map[string]func(i int, d *Decision){
		"secret":     func(_ int, d *Decision) { d.Verb = verb.RevealSecret },
		"reversible": func(_ int, d *Decision) { d.Verb = verb.Draft },
		"paste site": func(_ int, d *Decision) { d.Account = "paste" },
		"free text":  func(i int, d *Decision) { d.Params["note"] = "text " + strconv.Itoa(i) },
		"non-string": func(_ int, d *Decision) { d.Params["copies"] = 2 },
		"unverified": func(_ int, d *Decision) { d.Verified = false },
	} {
		o := newOpt(t, &change.MemStore{}, func(c *Config) { c.UserContent = func(a string) bool { return a == "paste" } })
		for i := 0; i < 30; i++ {
			d := invoice(i)
			mut(i, &d)
			observe(t, o, d)
		}
		if s := suggestions(t, o); len(s) != 0 {
			t.Errorf("%s: suggested %+v", name, s)
		}
		if n, a := o.Split(); a != 0 {
			t.Errorf("%s: %d avoidable of %d", name, a, n+a)
		}
	}
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		if i == 5 {
			d := invoice(99)
			d.Verified, d.Approved = false, false
			observe(t, o, d)
			e := invoice(98)
			e.Expired, e.Approved = true, false
			observe(t, o, e)
		}
		observe(t, o, invoice(i))
	}
	if len(suggestions(t, o)) != 1 {
		t.Fatal("an unverified or expired item must not reset the run")
	}
}

// ADP-11, CAP-6: context-scoped replies are earned per Mark's D2 ("earned
// after ~20 unedited approved replies", arbitrator on #52): 20 unedited
// approvals, edited ones never counting, with at most 10% edited among the
// last 30 answered. A cosmetic edit among them still earns; a higher edit
// rate does not; a NO resets. The rule fixes no recipients and no money.
func TestReplyRuleIsEarned(t *testing.T) {
	reply := func(i int, edited bool) Decision {
		return Decision{Account: "mail", Action: "message.reply", Verb: verb.Send, Approved: true, Verified: true, Edited: edited,
			Params:     map[string]any{Record: "thread-" + strconv.Itoa(i), Body: "free text " + strconv.Itoa(i)},
			Recipients: []string{"same@peer.test"}, At: t0.Add(time.Duration(i) * time.Hour)}
	}
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 19; i++ {
		observe(t, o, reply(i, i == 7)) // one cosmetic edit
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("offered after 18 unedited: %+v", s)
	}
	observe(t, o, reply(19, false))
	observe(t, o, reply(20, false))
	s := suggestions(t, o)
	if len(s) != 1 || !s[0].Spec.Rule.Reply || len(s[0].Spec.Rule.Recipients) != 0 || s[0].Spec.Rule.AmountCap != 0 || len(s[0].Spec.Rule.Params) != 0 {
		t.Fatalf("one edit among 21 must still earn: %+v", s)
	}
	if !strings.Contains(s[0].Text, "20 of the agent's replies on mail unedited") || !strings.Contains(s[0].Text, "reply in existing threads") {
		t.Fatalf("text %q", s[0].Text)
	}

	o = newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 24; i++ {
		observe(t, o, reply(i, i%6 == 0)) // 4 of 24 edited: 17%
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("an edit rate above 10%% earned: %+v", s)
	}

	o = newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 25; i++ {
		d := reply(i, false)
		if i == 10 {
			d.Approved = false // a NO
		}
		observe(t, o, d)
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("a NO must reset: %+v", s)
	}
	d := reply(30, false)
	d.Wrong = true
	o = newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 25; i++ {
		observe(t, o, reply(i, false))
		if i == 10 {
			observe(t, o, d)
		}
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("a wrong verdict must reset: %+v", s)
	}
}

// CAP-6: the owner's NO stops the suggestion until the class earns twice
// the threshold again; state survives a restart.
func TestDeclineAndRestart(t *testing.T) {
	st := &change.MemStore{}
	o := newOpt(t, st, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	s := suggestions(t, o)
	if err := o.Decline(strings.ToLower(s[0].Short)); err != nil {
		t.Fatal(err)
	}
	if err := o.Decline("S9"); err != ErrUnknown {
		t.Fatalf("unknown decline: %v", err)
	}
	o = newOpt(t, st, nil) // restart
	for i := 0; i < 19; i++ {
		observe(t, o, invoice(20+i))
	}
	if len(suggestions(t, o)) != 0 {
		t.Fatal("a declined suggestion came back early")
	}
	observe(t, o, invoice(40))
	if s := suggestions(t, o); len(s) != 1 || s[0].Short == "S1" {
		t.Fatalf("after the snooze: %+v", s)
	}
}

// A10: owner approvals split into necessary (before the class earned a
// suggestion) and avoidable (after: a pre-allowance would have covered
// them).
func TestApprovalSplit(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 14; i++ {
		observe(t, o, invoice(i))
	}
	d := invoice(20)
	d.Approved = false
	observe(t, o, d)
	if n, a := o.Split(); n != 10 || a != 4 {
		t.Fatalf("necessary %d avoidable %d", n, a)
	}
}

// CAP-6: the optimizer proposes and never enacts. It holds no handle on
// the journal, the grants gate, or the owner channel, so a suggestion can
// only take effect as the owner's own new-grant intent.
func TestCannotEnact(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "attention.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		for _, banned := range []string{"broker/journal", "broker/owner", "broker/daemon", "net", "os"} {
			if strings.HasSuffix(p, banned) {
				t.Errorf("attention imports %s", p)
			}
		}
	}
}

// CAP-6, CH-12 (UX-52-2): the owner's text fits three GSM-7 segments even
// for the longest names and an amount cap; the full rule is on the Wi-Fi
// page (Detail).
func TestTextFitsThreeSegments(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	long := strings.Repeat("a", 64)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		d.Account, d.Action, d.Amount = long, strings.Repeat("b", 64), 99999999999
		d.Params["template"] = strings.Repeat("t", 200)
		observe(t, o, d)
	}
	s := suggestions(t, o)
	if len(s) != 1 || len(s[0].Text) > MaxText || !strings.Contains(s[0].Text, "amounts up to") {
		t.Fatalf("%d chars: %q", len(s[0].Text), s[0].Text)
	}
}

// CAP-6 (UX-52-3): a suggestion goes to the owner at most weekly, and two
// unanswered offers count as a NO.
func TestOffersAreWeeklyAndLapse(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	due := func(at time.Time) int {
		t.Helper()
		s, err := o.Due(at)
		if err != nil {
			t.Fatal(err)
		}
		return len(s)
	}
	day := t0.Add(10 * 24 * time.Hour)
	if due(day) != 1 || due(day.Add(time.Hour)) != 0 || due(day.Add(6*24*time.Hour)) != 0 {
		t.Fatal("offered more than weekly")
	}
	if due(day.Add(7*24*time.Hour)) != 1 {
		t.Fatal("not re-offered after a week")
	}
	if due(day.Add(14*24*time.Hour)) != 0 || len(suggestions(t, o)) != 0 {
		t.Fatal("two unanswered offers must count as a NO")
	}
}
