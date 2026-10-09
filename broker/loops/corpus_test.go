package loops

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const promptInject = "../../assurance/corpora/promptinject/items.json"

func corpusItems(t *testing.T) []CorpusItem {
	t.Helper()
	items, err := LoadCorpus(promptInject)
	if err != nil {
		t.Fatal(err)
	}
	return items
}

// containsCheck hits a text carrying its payload anywhere; the weakened
// copy hits only the bare payload, as a filter anchored to the whole text.
func containsCheck(name, payload string, weak bool) ClosedCheck {
	return ClosedCheck{Name: name, Payload: payload, Hit: func(s string) bool {
		if weak {
			return s == payload
		}
		return strings.Contains(s, payload)
	}}
}

// LOOP-7: the vendored corpus loads with its published texts, and every
// item is replayed with the check's payload placed where the attack puts
// its own text, or after it.
func TestCorpusItemsCarryTheCheckedPayload(t *testing.T) {
	items := corpusItems(t)
	if len(items) < 10 || items[0].ID != "promptinject/goal_hikacking_attacks/ignore-say" {
		t.Fatalf("items %+v", items)
	}
	var seen []string
	p := &CorpusProbe{Interval: 1, Items: items, Checks: []ClosedCheck{{Name: "rec", Payload: "PAYLOAD", Hit: func(s string) bool {
		seen = append(seen, s)
		return true
	}}}}
	res, err := p.Run(context.Background())
	if err != nil || len(res.Found) != 0 || len(res.Checked) != len(items) {
		t.Fatalf("%+v %v", res, err)
	}
	// The self-check, then one replay per item.
	if len(seen) != len(items)+1 {
		t.Fatalf("seen %d", len(seen))
	}
	for _, s := range seen[1:] {
		if !strings.Contains(s, "PAYLOAD") || strings.Contains(s, "{REPLACE_") {
			t.Fatalf("replayed %q", s)
		}
	}
}

// LOOP-7 acceptance: a weakened copy of a check misses corpus items, and
// each miss is a High finding naming the check and the item, never the
// attack text; a clean run reports nothing.
func TestAWeakenedCheckIsACorpusFindingThroughReport(t *testing.T) {
	items := corpusItems(t)
	weak := &CorpusProbe{Interval: 1, Items: items, Checks: []ClosedCheck{containsCheck("code filter", "code 482913", true)}}
	r := newReportRig(t, nil)
	r.probes = []Probe{weak}
	r.reopen(t)
	ctx := context.Background()
	runJob(t, r.g, ctx)
	if name, res := runJob(t, r.g, ctx); name != "probe:corpus" || res.Err != nil || int(res.Value) != len(items) {
		t.Fatalf("%q %+v", name, res)
	}
	ev := r.g.Evidence()
	if len(ev) != len(items) {
		t.Fatalf("evidence %d", len(ev))
	}
	for _, e := range ev {
		f := e.Finding
		if f.Check != CheckCorpus || f.Severity != High || f.Detail != "code filter" || !strings.HasPrefix(f.Subject, "promptinject/") {
			t.Fatalf("finding %+v", f)
		}
	}
	for _, s := range r.texts {
		if strings.Contains(s, "nstructions") {
			t.Fatalf("owner text carries attack text: %q", s)
		}
	}
	weak.Checks = []ClosedCheck{containsCheck("code filter", "code 482913", false)}
	r.now = r.now.Add(2)
	if name, res := runJob(t, r.g, ctx); name != "probe:corpus" || res.Err != nil || res.Value != 0 {
		t.Fatalf("%q %+v", name, res)
	}
	for _, e := range ev {
		if _, open := r.open(e.Finding.ID); open {
			t.Fatalf("%s left open by a clean run", e.Finding.Subject)
		}
	}
}

// LOOP-7: a check that misses its own payload says nothing about the
// corpus, so the run is an error and reports nothing.
func TestACorpusCheckThatMissesItsPayloadIsAnError(t *testing.T) {
	p := &CorpusProbe{Interval: 1, Items: corpusItems(t), Checks: []ClosedCheck{{Name: "broken", Payload: "x", Hit: func(string) bool { return false }}}}
	res, err := p.Run(context.Background())
	if err == nil || len(res.Found) != 0 || len(res.Checked) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := LoadCorpus("testdata/none.json"); err == nil {
		t.Fatal("a missing corpus loaded")
	}
}

// LOOP-7 (corpus replay through a guest, P3-4b-4d): a check with Deliver
// is taken through it, not Hit, bare payload first; a miss is a finding
// naming only the broker-held item ID and check name.
func TestADeliveredCheckIsTakenThroughItsGuest(t *testing.T) {
	items := corpusItems(t)
	var got []string
	c := ClosedCheck{Name: "code filter", Payload: "code 482913",
		Hit: func(string) bool { t.Fatal("Hit used for a delivered check"); return false },
		Deliver: func(_ context.Context, s string) (bool, error) {
			got = append(got, s)
			return s == "code 482913", nil // the guest route catches only the bare payload
		}}
	res, err := (&CorpusProbe{Interval: 1, Items: items, Checks: []ClosedCheck{c}}).Run(context.Background())
	if err != nil || len(res.Found) != len(items) || len(got) != len(items)+1 || got[0] != "code 482913" {
		t.Fatalf("%+v %v (%d deliveries)", res, err, len(got))
	}
	for i, f := range res.Found {
		if f.Check != CheckCorpus || f.Subject != items[i].ID || f.Detail != "code filter" || f.Severity != High || f.Rule != nil {
			t.Fatalf("finding %+v", f)
		}
	}
}

// LOOP-7: a delivery that fails (the guest did not act, the broker saw
// nothing) fails the run and reports nothing, bare payload or item.
func TestAFailedDeliveryFailsTheRun(t *testing.T) {
	for _, failAt := range []int{1, 3} {
		n := 0
		c := ClosedCheck{Name: "label check", Payload: "", Deliver: func(context.Context, string) (bool, error) {
			if n++; n == failAt {
				return false, errors.New("no reply reached the owner line")
			}
			return false, nil
		}}
		res, err := (&CorpusProbe{Interval: 1, Items: corpusItems(t), Checks: []ClosedCheck{c}}).Run(context.Background())
		if err == nil || len(res.Found) != 0 {
			t.Fatalf("fail at %d: %+v %v", failAt, res, err)
		}
	}
}
