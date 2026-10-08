package attention

// REQ: CAP-6, ADP-9, ADP-11, CH-12, CH-15, A10

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

func templated(i int, template string) Decision {
	d := invoice(i)
	d.Params["template"] = template
	return d
}

func TestCohortsEarnIndependently(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 40; i++ {
		name := "monthly"
		if i%2 == 1 {
			name = "quarterly"
		}
		observe(t, o, templated(i, name))
	}
	s := suggestions(t, o)
	if len(s) != 2 {
		t.Fatalf("two templates with 20 approvals each: got %d suggestions", len(s))
	}
	for _, sg := range s {
		if sg.Approved != 20 || len(sg.Spec.Rule.Params) != 1 || sg.Spec.Rule.PerRecord != 1 {
			t.Fatalf("cohort evidence or rule mixed: %+v", sg)
		}
	}
}

func TestOneOutlierDoesNotPoisonRecurringTemplate(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	observe(t, o, templated(10, "outlier"))
	for i := 11; i < 111; i++ {
		observe(t, o, invoice(i))
	}
	s := suggestions(t, o)
	if len(s) != 1 || s[0].Spec.Rule.Params["template"] != "monthly" || s[0].Approved != 110 {
		t.Fatalf("one outlier poisoned recurring template: %+v", s)
	}
}

func TestAvoidableRequiresExistingExactTemplate(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	observe(t, o, templated(10, "new-template"))
	if n, a := o.Split(); n != 11 || a != 0 {
		t.Fatalf("new template counted as avoidable: %d necessary, %d avoidable", n, a)
	}
	observe(t, o, invoice(11))
	if n, a := o.Split(); n != 11 || a != 1 {
		t.Fatalf("existing earned template not counted: %d necessary, %d avoidable", n, a)
	}
}

func TestDuePacesAllSuggestionsForOneAccount(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
		d := templated(i, "quarterly")
		d.Action = "invoice.other"
		observe(t, o, d)
	}
	now := t0.Add(4 * 24 * time.Hour)
	for week := 0; week < 2; week++ {
		s, err := o.Due(now.Add(time.Duration(week) * Reoffer))
		if err != nil || len(s) != 1 {
			t.Fatalf("account digest must offer at most one per week: %+v, %v", s, err)
		}
	}
}

func TestSuggestionCannotMutateEvidence(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
	}
	s := suggestions(t, o)
	s[0].Spec.Rule.Params["template"] = "unapproved"
	s[0].Spec.Rule.Recipients[0] = "unapproved@invalid.test"
	again := suggestions(t, o)
	if again[0].Spec.Rule.Params["template"] != "monthly" || again[0].Spec.Rule.Recipients[0] != "ap@client.test" {
		t.Fatal("returned draft mutated persisted evidence")
	}
}

func TestNegativeEvidenceResetsEveryTemplate(t *testing.T) {
	for name, mutate := range map[string]func(*Decision){
		"NO or UNDO": func(d *Decision) { d.Approved = false },
		"edit":       func(d *Decision) { d.Edited = true },
		"wrong":      func(d *Decision) { d.Wrong = true },
	} {
		t.Run(name, func(t *testing.T) {
			o := newOpt(t, &change.MemStore{}, nil)
			for i := 0; i < 10; i++ {
				observe(t, o, invoice(i), templated(i, "quarterly"))
			}
			old := suggestions(t, o)
			d := templated(11, "never-seen")
			d.Verified = false
			mutate(&d)
			observe(t, o, d)
			if s := suggestions(t, o); len(s) != 0 {
				t.Fatalf("negative evidence left another template earned: %+v", s)
			}
			for _, sg := range old {
				if err := o.Decline(sg.Short); err != ErrUnknown {
					t.Fatalf("retired ID still resolves: %v", err)
				}
			}
			if due, err := o.Due(d.At); err != nil || len(due) != 0 {
				t.Fatalf("cached offer survived negative decision: %+v %v", due, err)
			}
			for i := 12; i < 21; i++ {
				observe(t, o, invoice(i))
			}
			if len(suggestions(t, o)) != 0 {
				t.Fatal("reset template earned before ten new approvals")
			}
			observe(t, o, invoice(21))
			if len(suggestions(t, o)) != 1 {
				t.Fatal("reset template did not re-earn")
			}
		})
	}
}

func TestReplyEditsCannotBePartitionedByTemplate(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 24; i++ {
		d := reply(i, i < 4)
		if d.Edited {
			d.Params["template"] = "different"
			d.Verified = false
		}
		observe(t, o, d)
	}
	if len(suggestions(t, o)) != 0 {
		t.Fatal("reply template variations escaped the account edit-rate window")
	}
	for i := 24; i < 34; i++ {
		observe(t, o, reply(i, false))
	}
	if s := suggestions(t, o); len(s) != 1 || !s[0].Spec.Rule.Reply || s[0].Approved != 30 {
		t.Fatalf("reply light-edit count changed: %+v", s)
	}
}

func TestCanonicalShapesAndVerbAreDistinct(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		if i%2 == 0 {
			d.Params = map[string]any{Record: "other", "z": "one\x00two", "a": "x=y"}
		} else {
			d.Params = map[string]any{"a": "x=y", "z": "one\x00two", Record: "another"}
		}
		observe(t, o, d)
	}
	if len(suggestions(t, o)) != 1 {
		t.Fatal("map order or record ID split one canonical template")
	}
	d := invoice(11)
	d.Params = map[string]any{"a": "x", "z": "y=one\x00two"}
	observe(t, o, d)
	d.Params = map[string]any{"a": "x=y", "z": "one\x00two"}
	d.Verb = "share"
	observe(t, o, d)
	if n, a := o.Split(); n != 12 || a != 0 {
		t.Fatalf("distinct predicate or verb inherited evidence: %d %d", n, a)
	}
}

func TestAvoidableDoesNotBorrowRecipientOrAmountBounds(t *testing.T) {
	for _, kind := range []string{"recipient", "amount", "non-string", "user-content"} {
		t.Run(kind, func(t *testing.T) {
			blocked := false
			o := newOpt(t, &change.MemStore{}, func(c *Config) { c.UserContent = func(string) bool { return blocked } })
			for i := 0; i < 10; i++ {
				observe(t, o, invoice(i))
			}
			d := invoice(10)
			switch kind {
			case "recipient":
				d.Recipients = []string{"another@client.test"}
			case "amount":
				d.Amount = 1
			case "non-string":
				d.Params["template"] = []string{"monthly"}
			case "user-content":
				blocked = true
			}
			observe(t, o, d)
			if n, a := o.Split(); n != 11 || a != 0 {
				t.Fatalf("different bound counted avoidable: %d %d", n, a)
			}
		})
	}
}

func TestCohortExhaustionAndRetention(t *testing.T) {
	st := &change.MemStore{}
	o := newOpt(t, st, nil)
	for i := 0; i < 10; i++ {
		for shape := 0; shape < MaxCohorts; shape++ {
			observe(t, o, templated(i, fmt.Sprintf("template-%d", shape)))
		}
	}
	for i := 10; i < 40; i++ {
		observe(t, o, templated(i, "overflow"))
	}
	if s := suggestions(t, o); len(s) != MaxCohorts {
		t.Fatalf("overflow evicted or added a live cohort: %d", len(s))
	}
	o = newOpt(t, st, nil)
	if s := suggestions(t, o); len(s) != MaxCohorts {
		t.Fatal("bounded cohorts did not survive reload")
	}
	later := t0.Add(EvidenceWindow + 24*time.Hour)
	if s, err := o.Due(later); err != nil || len(s) != 0 {
		t.Fatalf("expired evidence remained offerable: %+v %v", s, err)
	}
	for i := 0; i < 10; i++ {
		d := templated(i, "overflow")
		d.At = later.Add(time.Duration(i) * time.Hour)
		observe(t, o, d)
	}
	if s := suggestions(t, o); len(s) != 1 || s[0].Approved != 10 || s[0].Spec.Rule.Params["template"] != "overflow" {
		t.Fatalf("new evidence did not earn after expiry: %+v", s)
	}
	observe(t, o, invoice(0)) // delayed old observation cannot revive evidence
	if len(suggestions(t, o)) != 1 {
		t.Fatal("stale observation revived expired cohort")
	}
}

func TestDeclineSurvivesNewShapesExpiryAndReload(t *testing.T) {
	st := &change.MemStore{}
	o := newOpt(t, st, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i), templated(i, "quarterly"))
	}
	if err := o.Decline(suggestions(t, o)[0].Short); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(2 * EvidenceWindow)
	if _, err := o.Due(later); err != nil {
		t.Fatal(err)
	}
	o = newOpt(t, st, nil)
	for i := 0; i < 19; i++ {
		d := templated(i, "new-after-expiry")
		d.At = later.Add(time.Duration(i) * time.Hour)
		observe(t, o, d)
	}
	if len(suggestions(t, o)) != 0 {
		t.Fatal("new shape or expiry bypassed account/action decline")
	}
	d := templated(20, "new-after-expiry")
	d.At = later.Add(20 * time.Hour)
	observe(t, o, d)
	if len(suggestions(t, o)) != 1 {
		t.Fatal("declined action failed to re-earn after 20")
	}
}

func TestAccountPacingSurvivesReloadAndDecline(t *testing.T) {
	st := &change.MemStore{}
	o := newOpt(t, st, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, invoice(i))
		d := invoice(i)
		d.Action = "other.action"
		observe(t, o, d)
	}
	now := t0.Add(4 * 24 * time.Hour)
	s, err := o.Due(now)
	if err != nil || len(s) != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	if err := o.Decline(s[0].Short); err != nil {
		t.Fatal(err)
	}
	o = newOpt(t, st, nil)
	if s, err := o.Due(now.Add(time.Hour)); err != nil || len(s) != 0 {
		t.Fatalf("decline/reload bypassed account pacing: %+v %v", s, err)
	}
}

func TestLegacyMigrationKeepsOnlyHomogeneousEvidence(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprintf("mixed=%v", mixed), func(t *testing.T) {
			st := &change.MemStore{}
			legacy := state{Seq: 7, Necessary: 10, Classes: map[string]*class{
				key("books", "invoice.send", false): {
					Account: "books", Action: "invoice.send", Verb: "send", Run: 10,
					Since: t0, Fixed: map[string]string{"template": "monthly"}, Templated: !mixed,
					Days: map[string]int{"2026-10-05": 10}, Short: "S7", Offered: t0, Offers: 1,
				},
			}}
			raw, _ := json.Marshal(legacy)
			if err := st.Save(raw); err != nil {
				t.Fatal(err)
			}
			o := newOpt(t, st, nil)
			if err := o.Decline("S7"); err != ErrUnknown {
				t.Fatalf("legacy ID survived: %v", err)
			}
			s := suggestions(t, o)
			if mixed && len(s) != 0 {
				t.Fatal("mixed legacy evidence inherited a cohort")
			}
			if !mixed && (len(s) != 1 || s[0].Approved != 10 || s[0].Short == "S7") {
				t.Fatalf("homogeneous migration: %+v", s)
			}
			if s, err := o.Due(t0.Add(time.Hour)); err != nil || len(s) != 0 {
				t.Fatal("migration bypassed prior account offer")
			}
			o = newOpt(t, st, nil)
			if n, a := o.Split(); n != 10 || a != 0 {
				t.Fatalf("migration changed metric history: %d %d", n, a)
			}
		})
	}
}

func TestStateAndShapeExhaustionFailClosed(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < MaxClasses+10; i++ {
		d := invoice(0)
		d.Account = fmt.Sprintf("account-%d", i)
		observe(t, o, d)
	}
	if len(o.st.Classes) != MaxClasses {
		t.Fatalf("class bound: %d", len(o.st.Classes))
	}
	d := invoice(0)
	d.Account = "account-0"
	d.Params["template"] = strings.Repeat("x", MaxShapeBytes+1)
	observe(t, o, d)
	if len(o.st.Classes[key(d.Account, d.Action, false)].Cohorts) != 1 {
		t.Fatal("oversized shape retained")
	}
	if len(suggestions(t, o)) != 0 {
		t.Fatal("capacity exhaustion invented evidence")
	}
}

func TestMalformedAndFutureStateRejected(t *testing.T) {
	for _, raw := range []string{
		`{"version":999,"classes":{}}`,
		`{"version":2,"classes":{"bad":null}}`,
		`{"version":2,"classes":{"books\u0000invoice.send\u0000false":{"account":"books","action":"invoice.send","verb":"send","cohorts":{"wrong":{"account":"books","action":"invoice.send","verb":"send","run":10,"templated":true,"fixed":{"template":"monthly"}}}}}}`,
		`{`,
	} {
		st := &change.MemStore{}
		if err := st.Save([]byte(raw)); err != nil {
			t.Fatal(err)
		}
		if _, err := New(Config{Store: st, Now: func() time.Time { return t0 }, UserContent: func(string) bool { return false }}); err == nil {
			t.Fatalf("accepted invalid persisted state: %s", raw)
		}
	}
}

func TestShortIDExhaustionKeepsExistingDraftsUsable(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, func(c *Config) { c.Threshold = 1 })
	for i := 0; i < MaxShort+1; i++ {
		d := invoice(0)
		d.Account = fmt.Sprintf("account-%d", i)
		observe(t, o, d)
	}
	s := suggestions(t, o)
	if len(s) != MaxShort {
		t.Fatalf("addressable drafts lost at exhaustion: %d", len(s))
	}
	if err := o.Decline(s[0].Short); err != nil {
		t.Fatal(err)
	}
	s = suggestions(t, o)
	if len(s) != MaxShort {
		t.Fatalf("freed ID not available for queued draft: %d", len(s))
	}
}

func TestReplyHistoryAndLegacyDaysSurviveMigration(t *testing.T) {
	st := &change.MemStore{}
	days := map[string]int{}
	for i := 0; i < 120; i++ {
		days[t0.Add(time.Duration(-i)*24*time.Hour).Format("2006-01-02")] = 1
	}
	old := state{Classes: map[string]*class{key("mail", "message.reply", true): {
		Account: "mail", Action: "message.reply", Verb: "send", Reply: true, Run: 20,
		Since: t0.Add(-120 * 24 * time.Hour), Templated: true, Days: days, Recent: make([]bool, 20),
	}}}
	raw, _ := json.Marshal(old)
	if err := st.Save(raw); err != nil {
		t.Fatal(err)
	}
	o := newOpt(t, st, nil)
	if s := suggestions(t, o); len(s) != 1 || s[0].Approved != 20 {
		t.Fatalf("reply count changed on migration: %+v", s)
	}
	if len(o.st.Classes[key("mail", "message.reply", true)].Days) > 91 {
		t.Fatal("old daily buckets remain unbounded")
	}
}

func TestEmptyFixedShapeCanonicalizesNilAndEmpty(t *testing.T) {
	a, okA := cohortKey("send", nil)
	b, okB := cohortKey("send", map[string]string{})
	if !okA || !okB || a != b {
		t.Fatal("empty legacy template differs from observed empty template")
	}
}

func TestOversizedFactsCannotGrowRetainedEvidence(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		d := invoice(i)
		d.Recipients = []string{strings.Repeat("x", MaxShapeBytes+1)}
		observe(t, o, d)
	}
	if len(o.st.Classes) != 0 {
		t.Fatal("oversized recipients retained")
	}
}

func TestLapsedSiblingCannotLeaveStaleOfferInDue(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, templated(i, "z-last"))
	}
	now := t0.Add(4 * 24 * time.Hour)
	for week := 0; week < 2; week++ {
		if s, err := o.Due(now.Add(time.Duration(week) * Reoffer)); err != nil || len(s) != 1 {
			t.Fatalf("%+v %v", s, err)
		}
	}
	for i := 0; i < 10; i++ {
		d := templated(i, "a-first")
		d.At = now.Add(Reoffer + time.Duration(i)*time.Hour)
		observe(t, o, d)
	}
	if s, err := o.Due(now.Add(2 * Reoffer)); err != nil || len(s) != 0 {
		t.Fatalf("lapsed sibling reset evidence but returned a stale offer: %+v %v", s, err)
	}
}

func TestLightReplyEditStillResetsTemplatedSiblings(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 20; i++ {
		observe(t, o, invoice(i))
		d := reply(i, false)
		d.Account, d.Action = "books", "invoice.send"
		observe(t, o, d)
	}
	d := reply(21, true)
	d.Account, d.Action, d.Verified = "books", "invoice.send", false
	observe(t, o, d)
	s := suggestions(t, o)
	if len(s) != 1 || !s[0].Spec.Rule.Reply {
		t.Fatalf("reply edit bypassed templated reset or changed reply light-edit rule: %+v", s)
	}
}

func TestInvalidUTF8CannotCollideWithCanonicalTemplate(t *testing.T) {
	o := newOpt(t, &change.MemStore{}, nil)
	for i := 0; i < 10; i++ {
		observe(t, o, templated(i, "\ufffd"))
	}
	observe(t, o, templated(11, string([]byte{0xff})))
	if s := suggestions(t, o); len(s) != 1 || s[0].Approved != 10 {
		t.Fatalf("lossy JSON conversion poisoned a canonical cohort: %+v", s)
	}
}
