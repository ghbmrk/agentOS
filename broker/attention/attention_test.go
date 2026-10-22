package attention

// REQ: KEY-5, KEY-2, A10

import (
	"go/parser"
	"go/token"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

var t0 = time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)

// memStore is a Store in memory.
type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = append([]byte(nil), b...); return nil }

func newOpt(t *testing.T, st Store, mod func(*Config)) *Optimizer {
	t.Helper()
	cfg := Config{Store: st, UserContent: func(string) bool { return false }}
	if mod != nil {
		mod(&cfg)
	}
	o, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// invoice is a verified, templated send: the template is the content class
// and the record's fields fill it.
func invoice(i int) Decision {
	return Decision{Clerk: "books", Verb: key.Send, Approved: true, Verified: true, Content: "template:monthly",
		Recipients: []string{"ap@client.test"}, At: t0.Add(time.Duration(i) * 6 * time.Hour)}
}

// limits folds s's caveats, failing on a malformed one: a proposal the
// key-check library would refuse is no proposal.
func limits(t *testing.T, s Suggestion) key.Limits {
	t.Helper()
	l, err := key.Fold(s.Caveats)
	if err != nil {
		t.Fatalf("caveats %+v: %v", s.Caveats, err)
	}
	return l
}

// rate is the daily rate cap l carries, 0 for none.
func rate(l key.Limits) int64 {
	for _, c := range l.Caps {
		if c.Kind == key.KRateDay {
			return c.N
		}
	}
	return 0
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

// KEY-5: a class approved unchanged Threshold times in a row earns a
// suggestion: the narrowest key that covers it, with its one verb, its
// content class, the recipients that never changed, a daily rate from what
// was approved, and the owner's line in fixed wording with its evidence.
func TestSuggestsAfterRunOfApprovals(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
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
	l := limits(t, s[0])
	to := l.Args["to"]
	if s[0].Clerk != "books" || strings.Join(l.Verbs, ",") != "send" || strings.Join(l.Content, ",") != "template:monthly" || len(l.Args) != 1 ||
		strings.Join(to.OneOf, ",") != "ap@client.test" || rate(l) != 3 || len(l.Caps) != 1 {
		t.Fatalf("key %+v", l)
	}
	if s[0].Short != "S1" || s[0].Approved != 10 || !slices.Equal(s[0].Detail, Describe("books", false, s[0].Caveats)) || !strings.Contains(s[0].Text, "up to 3 a day, no money.") ||
		!strings.Contains(s[0].Text, "10 times in a row since Oct 5") || !strings.HasSuffix(s[0].Text, "Reply NO S1 to stop suggesting it.") {
		t.Fatalf("text %q", s[0].Text)
	}
	if again := suggestions(t, o); again[0].Short != "S1" {
		t.Fatal("a suggestion keeps its ID")
	}
}

// KEY-5: a NO, an UNDO, or an edit resets the run; an expiry does not;
// approvals of different recipients bound the key to those seen
// (security on #2796); a verb's amount argument is capped at the largest approved.
func TestRunResetsAndShapesRule(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
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
	if len(s) != 1 || len(limits(t, s[0]).Args) != 1 || len(limits(t, s[0]).Args["to"].OneOf) != 10 || strings.Contains(s[0].Text, "amounts up to") {
		t.Fatalf("the key bounds the recipients to the ten seen, and a send has no amount argument to cap: %+v", s)
	}
	o = newOpt(t, &memStore{}, nil)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		d.Verb, d.Content, d.Args = key.Buy, "template:refill", map[string]string{"item": "toner"}
		d.Amount = int64(1000 * (i + 1))
		observe(t, o, d)
	}
	s = suggestions(t, o)
	if len(s) != 1 {
		t.Fatalf("%+v", s)
	}
	l := limits(t, s[0])
	if a := l.Args[key.ArgAmount]; a.Max == nil || *a.Max != 10000 || strings.Join(l.Args["item"].OneOf, ",") != "toner" ||
		!strings.Contains(s[0].Text, "amounts up to 100.00") {
		t.Fatalf("%+v %q", l, s[0].Text)
	}
}

// KEY-5: never suggested: reveal-or-create-secret (VRB-1 keeps per-step
// approval), a reversible verb (needs no key), a user-content service, a
// class whose arguments changed or whose content is no template or thread
// scope. An unverified approval does not count; an expired item neither
// counts nor resets.
func TestExclusions(t *testing.T) {
	for name, mut := range map[string]func(i int, d *Decision){
		"secret":       func(_ int, d *Decision) { d.Verb = key.RevealOrCreateSecret },
		"reversible":   func(_ int, d *Decision) { d.Verb = key.Draft },
		"unknown verb": func(_ int, d *Decision) { d.Verb = "wire" },
		"paste site":   func(_ int, d *Decision) { d.Clerk = "paste" },
		"changed arg":  func(i int, d *Decision) { d.Args = map[string]string{"note": "text " + strconv.Itoa(i)} },
		"free text":    func(_ int, d *Decision) { d.Content = "" },
		"content":      func(i int, d *Decision) { d.Content = "template:" + strconv.Itoa(i%2) },
		"unverified":   func(_ int, d *Decision) { d.Verified = false },
	} {
		o := newOpt(t, &memStore{}, func(c *Config) { c.UserContent = func(a string) bool { return a == "paste" } })
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
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < 10; i++ {
		if i == 5 {
			d := invoice(99)
			d.Verified = false
			observe(t, o, d)
			e := invoice(98)
			e.Expired, e.Approved = true, false
			observe(t, o, e)
		}
		observe(t, o, invoice(i))
	}
	if len(suggestions(t, o)) != 1 {
		t.Fatal("an unverified approval or an expired item must not reset the run")
	}
	if _, err := New(Config{Store: &memStore{}}); err == nil {
		t.Fatal("New must require UserContent")
	}
}

// KEY-5 (L3 B1): a NO, UNDO, edit, or wrong verdict resets the run
// even when the item was unverified; the owner's rejection of an item the
// verifier could not read is still evidence.
func TestUnverifiedRejectionResets(t *testing.T) {
	for name, mut := range map[string]func(d *Decision){
		"no":    func(d *Decision) { d.Approved = false },
		"edit":  func(d *Decision) { d.Edited = true },
		"wrong": func(d *Decision) { d.Wrong = true },
	} {
		o := newOpt(t, &memStore{}, strict)
		for i := 0; i < 25; i++ {
			d := reply(i, false)
			if i == 10 {
				d.Verified = false
				mut(&d)
			}
			observe(t, o, d)
		}
		if s := suggestions(t, o); len(s) != 0 {
			t.Errorf("%s: suggested %q", name, s[0].Text)
		}
		o = newOpt(t, &memStore{}, nil)
		for i := 0; i < 15; i++ {
			d := invoice(i)
			if i == 7 {
				d.Verified = false
				mut(&d)
			}
			observe(t, o, d)
		}
		if s := suggestions(t, o); len(s) != 0 {
			t.Errorf("templated %s: suggested %q", name, s[0].Text)
		}
	}
	// Under the default light-edit rule, unverified edits still count in
	// the edit rate: 4 unverified edits among 24 replies (17%) earn nothing.
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < 24; i++ {
		d := reply(i, i%6 == 0)
		d.Verified = i%6 != 0
		observe(t, o, d)
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("unverified edits left out of the rate: %q", s[0].Text)
	}
	// The reviewer's probe: an unverified NO at #10 and edit at #11 among
	// 25 replies leave a run of 14, short of 20.
	o = newOpt(t, &memStore{}, nil)
	for i := 0; i < 25; i++ {
		d := reply(i, i == 10)
		if i == 9 || i == 10 {
			d.Verified = false
		}
		if i == 9 {
			d.Approved = false
		}
		observe(t, o, d)
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("probe: suggested %q", s[0].Text)
	}
}

func reply(i int, edited bool) Decision {
	return Decision{Clerk: "mail", Verb: key.Send, Thread: true, Approved: true, Verified: true, Edited: edited, Content: "thread",
		Recipients: []string{"same@peer.test"}, At: t0.Add(time.Duration(i) * time.Hour)}
}

// isReply reports whether s is a thread-scoped key: send under the thread
// content class, with no recipient or amount bound by value.
func isReply(t *testing.T, s Suggestion) bool {
	l := limits(t, s)
	return strings.Join(l.Verbs, ",") == "send" && strings.Join(l.Content, ",") == "thread" && len(l.Args) == 0
}

// strict is the reply rule without light edits: any edit resets the run.
func strict(c *Config) { c.ReplyEditPercent = -1 }

// KEY-5, KEY-2: with the strict setting a thread-scoped key is offered only
// after a run of 20 unedited approvals; an edit, a NO, or a wrong verdict
// resets the run. The key fixes no recipients and no money: the thread's
// participants are the clerk's to read.
func TestReplyRuleIsEarned(t *testing.T) {
	o := newOpt(t, &memStore{}, strict)
	for i := 0; i < 15; i++ {
		observe(t, o, reply(i, false))
	}
	observe(t, o, reply(15, true))
	for i := 16; i < 35; i++ {
		observe(t, o, reply(i, false))
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("offered after 19 unedited since an edit: %+v", s)
	}
	observe(t, o, reply(35, false))
	s := suggestions(t, o)
	if len(s) != 1 || !isReply(t, s[0]) {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(s[0].Text, "20 of my replies on mail unedited") || !strings.Contains(s[0].Text, "reply in existing threads") {
		t.Fatalf("text %q", s[0].Text)
	}
	// KEY-2 (combined review on #2796): the card says each reply is
	// texted first with UNDO and goes only to the thread's participants.
	d := s[0].Detail
	if !slices.Contains(d, Term{"Runs", "send as replies in existing threads, without asking; each is texted to you first and sends after the undo window unless you reply UNDO"}) ||
		!slices.Contains(d, Term{"Recipients", "the thread's own participants only"}) || slices.Contains(d, Term{"Argument to", "any"}) {
		t.Fatalf("thread card %+v", d)
	}
	for _, x := range d {
		if strings.Contains(x.Value, "notifying") {
			t.Fatalf("thread card says %q", x.Value)
		}
	}
}

// KEY-5 (L3 F1): a reset keeps the edit-rate window. Five edits, a NO,
// then 20 unedited approvals: 5 of the last 25 answered were edited (20%),
// so nothing is offered.
func TestResetKeepsEditRate(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < 5; i++ {
		observe(t, o, reply(i, true))
	}
	no := reply(5, false)
	no.Approved = false
	observe(t, o, no)
	for i := 6; i < 26; i++ {
		observe(t, o, reply(i, false))
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("a reset forgot earlier edits: %q", s[0].Text)
	}
}

// KEY-5 by default (Mark, 2026-10-05, "Allow light edits"): 20 unedited
// approvals, edited ones never counting, with at most 10% edited among the
// last 30 answered. A cosmetic edit still earns; a higher edit rate does
// not; a NO or a wrong verdict resets.
func TestReplyLightEdits(t *testing.T) {
	var pa2 func(*Config)
	o := newOpt(t, &memStore{}, pa2)
	for i := 0; i < 19; i++ {
		observe(t, o, reply(i, i == 7)) // one cosmetic edit
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("offered after 18 unedited: %+v", s)
	}
	observe(t, o, reply(19, false))
	observe(t, o, reply(20, false))
	s := suggestions(t, o)
	if len(s) != 1 || !isReply(t, s[0]) {
		t.Fatalf("one edit among 21 must still earn: %+v", s)
	}
	if !strings.Contains(s[0].Text, "20 of my replies on mail unedited") || !strings.Contains(s[0].Text, "reply in existing threads") {
		t.Fatalf("text %q", s[0].Text)
	}

	o = newOpt(t, &memStore{}, pa2)
	for i := 0; i < 24; i++ {
		observe(t, o, reply(i, i%6 == 0)) // 4 of 24 edited: 17%
	}
	if s := suggestions(t, o); len(s) != 0 {
		t.Fatalf("an edit rate above 10%% earned: %+v", s)
	}

	o = newOpt(t, &memStore{}, pa2)
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
	o = newOpt(t, &memStore{}, pa2)
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

// KEY-5: the owner's NO stops the suggestion until the class earns twice
// the threshold again; state survives a restart.
func TestDeclineAndRestart(t *testing.T) {
	st := &memStore{}
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
// suggestion) and avoidable (after: a standing key would have covered
// them).
func TestApprovalSplit(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < 14; i++ {
		observe(t, o, invoice(i))
	}
	d := invoice(20)
	d.Approved = false
	observe(t, o, d)
	if n, a := o.Split(); n != 10 || a != 4 {
		t.Fatalf("necessary %d avoidable %d", n, a)
	}
	// Unverified, ineligible, and edited approvals were all necessary; a
	// later wrong verdict is not a second approval.
	o = newOpt(t, &memStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	u, r, e, w := invoice(10), invoice(11), invoice(12), invoice(3)
	u.Verified = false
	r.Verb = key.Draft
	e.Edited = true
	w.Wrong = true
	observe(t, o, u, r, e, w)
	if n, a := o.Split(); n != 13 || a != 0 {
		t.Fatalf("necessary %d avoidable %d", n, a)
	}
}

// KEY-5: the drafted daily rate is the median day, so bunching approvals
// into one day cannot raise it.
func TestPerDayIsMedian(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		d.At = t0.Add(time.Duration(i) * 24 * time.Hour)
		if i >= 3 {
			d.At = t0.Add(3 * 24 * time.Hour) // seven on one day
		}
		observe(t, o, d)
	}
	if s := suggestions(t, o); len(s) != 1 || rate(limits(t, s[0])) != 1 {
		t.Fatalf("%+v", s)
	}
}

// CH-12: fallback short IDs stay within three characters.
func TestShortIDsAreBounded(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	for i := 0; i < MaxShort; i++ {
		o.st.Classes[strconv.Itoa(i)] = &class{Short: "taken"}
		s, err := o.shortLocked()
		if err != nil || len(s) > 3 {
			t.Fatalf("%q %v", s, err)
		}
		o.st.Classes[strconv.Itoa(i)].Short = s
	}
	if _, err := o.shortLocked(); err != ErrShortIDs {
		t.Fatal(err)
	}
}

// KEY-5: the optimizer proposes and never enacts. It holds no handle on
// the kernel, a key, or the owner channel: only the key package's types,
// so a suggestion can only take effect as the owner's passkey tap.
func TestCannotEnact(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "attention.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"encoding/json": true, "errors": true, "fmt": true, "maps": true, "slices": true, "sort": true,
		"strings": true, "sync": true, "time": true, "github.com/ghbmrk/agentos/broker/kernel/key": true}
	for _, im := range f.Imports {
		p, _ := strconv.Unquote(im.Path.Value)
		if !allowed[p] {
			t.Errorf("attention imports %s", p)
		}
	}
}

// KEY-5, CH-12 (UX-52-2): the owner's text fits three GSM-7 segments even
// for the longest names and an amount cap; the full key is on the owner
// page (Detail).
func TestTextFitsThreeSegments(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
	long := strings.Repeat("a", 64)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		d.Clerk, d.Verb, d.Amount = long, key.Buy, 99999999999
		d.Content = strings.Repeat("t", 200)
		observe(t, o, d)
	}
	s := suggestions(t, o)
	if len(s) != 1 || len(s[0].Text) > MaxText || !strings.Contains(s[0].Text, "amounts up to") {
		t.Fatalf("%d chars: %q", len(s[0].Text), s[0].Text)
	}
}

// KEY-5 (UX-52-3): a suggestion goes to the owner at most weekly, and two
// unanswered offers count as a NO.
func TestOffersAreWeeklyAndLapse(t *testing.T) {
	o := newOpt(t, &memStore{}, nil)
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

// KEY-2, KEY-5: Describe words every closed caveat kind, one term each, so
// a card built from it leaves no caveat off; a change to any caveat
// changes the wording.
func TestDescribeWordsEveryCaveat(t *testing.T) {
	lo, hi := int64(100), int64(15000000)
	cs := []key.Caveat{
		key.LimitVerbs(key.Buy), key.LimitContent("template:inv"), key.LimitLabels("public"),
		key.LimitArg(key.ArgBound{Name: "to", OneOf: []string{"billing@acme.example"}}),
		key.LimitArg(key.ArgBound{Name: key.ArgAmount, Min: &lo, Max: &hi}),
		key.LimitSpendTask(500), key.LimitSpendDay(900), key.LimitRate(50), key.LimitRateRecipient(25),
		key.LimitExpires(t0.UnixMilli()), key.LimitUses(3), key.LimitHold(600000, 900000), key.LimitTask("T1"),
	}
	d := Describe("books", false, cs)
	if len(d) != len(cs)+2 || d[0] != (Term{"Clerk", "books"}) {
		t.Fatalf("%+v", d)
	}
	want := []Term{
		{"Runs", "buy, without asking or notifying you"}, {"Content", "only template:inv"}, {"Data labels", "only public"},
		{"Argument to", "only billing@acme.example"}, {"Argument amount", "at least 1.00, up to 150000.00"},
		{"Spend per task", "up to 5.00"}, {"Spend per day", "up to 9.00"}, {"Per day", "at most 50 runs"},
		{"Per recipient", "at most 25 runs a day"}, {"Expires", "Oct 5 2026 09:00 UTC"}, {"Uses", "at most 3"},
		{"Hold", "10m0s before it runs, 15m0s when new"}, {"Task", "only T1"},
		{"Argument item", "any"}, // buy's one argument no caveat bounds
	}
	if !slices.Equal(d[1:], want) {
		t.Fatalf("got  %+v\nwant %+v", d[1:], want)
	}
	for i := range cs {
		c := slices.Clone(cs)
		switch c[i].Kind {
		case key.KArg:
			b := *c[i].Arg
			b.Name += "x"
			c[i].Arg = &b
		case key.KVerbs:
			c[i] = key.LimitVerbs(key.Send)
		default:
			c[i].N += 60000 // a minute: the expiry shows minutes
			c[i].Set = append(slices.Clone(c[i].Set), "zz")
		}
		if slices.Equal(Describe("books", false, c), d) {
			t.Errorf("caveat %d (%s) changed but the wording did not", i, cs[i].Kind)
		}
	}
	if Describe("books", false, []key.Caveat{{Kind: "novel"}})[1].Label != "Unknown limit" {
		t.Fatal("an unknown kind must still show")
	}
}

// KEY-5, KEY-2 (security on #2796): a proposal for every eligible verb
// bounds its object argument to the objects the run named, so a planner
// cannot pick another; a run that named none earns nothing. A template
// filled per record (msg) still earns, and the card shows each unbounded
// argument as "any".
func TestEveryProposalBoundsItsObject(t *testing.T) {
	for _, v := range []key.Verb{key.Unsubscribe, key.Send, key.Post, key.Actuate, key.Buy, key.Share, key.DeleteRemote,
		key.ChangeAccount, key.ActuatePhysical} {
		o := newOpt(t, &memStore{}, nil)
		for i := 0; i < 10; i++ {
			d := invoice(i)
			d.Verb, d.Recipients = v, []string{"r" + strconv.Itoa(i%3)}
			d.Args = map[string]string{"msg": "Invoice #" + strconv.Itoa(i) + " is attached."}
			observe(t, o, d)
		}
		s := suggestions(t, o)
		if len(s) != 1 {
			t.Fatalf("%s: %+v", v, s)
		}
		obj := limits(t, s[0]).Args[key.RecipientArg(v)]
		if strings.Join(obj.OneOf, ",") != "r0,r1,r2" {
			t.Errorf("%s: object bound %+v", v, obj)
		}
		for _, n := range key.ArgNames(v) {
			if _, ok := limits(t, s[0]).Args[n]; !ok && !slices.Contains(s[0].Detail, Term{"Argument " + n, "any"}) {
				t.Errorf("%s: unbounded %s is not on the card: %+v", v, n, s[0].Detail)
			}
		}
		o = newOpt(t, &memStore{}, nil)
		for i := 0; i < 10; i++ {
			d := invoice(i)
			d.Verb, d.Recipients = v, nil
			observe(t, o, d)
		}
		if s := suggestions(t, o); len(s) != 0 {
			t.Errorf("%s: a run naming no object earned %+v", v, s)
		}
	}
}
