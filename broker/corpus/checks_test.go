package corpus

// REQ: LOOP-7

import (
	"context"
	"testing"

	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

type noStore struct{ mail.Store }

func adapter(t *testing.T) *mail.Adapter {
	t.Helper()
	a, err := mail.New(mail.Config{Account: "acct", Address: "owner@example.test", Store: noStore{}})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func probe(t *testing.T, checks []loops.ClosedCheck) *loops.CorpusProbe {
	t.Helper()
	items, err := loops.LoadCorpus("../../assurance/corpora/promptinject/items.json")
	if err != nil {
		t.Fatal(err)
	}
	return &loops.CorpusProbe{Interval: 1, Items: items, Checks: checks}
}

// LOOP-7, clean run: every published item, carrying each check's payload,
// is still caught by CH-19's code filter, the commitment filter and the
// alert patterns, and is refused as a label.
func TestTheClosedChecksHoldOverThePublishedCorpus(t *testing.T) {
	checks := Checks(adapter(t), owner.Commitments{})
	if len(checks) != 4 {
		t.Fatalf("%d checks", len(checks))
	}
	res, err := probe(t, checks).Run(context.Background())
	if err != nil || len(res.Found) != 0 || len(res.Checked) < 10 {
		t.Fatalf("%+v %v", res, err)
	}
}

// LOOP-7 control: a copy of the code filter weakened to scan only a
// text's first 40 bytes misses the corpus items, which report findings.
func TestAWeakenedCodeFilterMissesCorpusItems(t *testing.T) {
	code := Checks(adapter(t), owner.Commitments{})[0]
	weak := code
	weak.Hit = func(s string) bool { return owner.SecretShaped(s[:min(len(s), 40)]) }
	res, err := probe(t, []loops.ClosedCheck{weak}).Run(context.Background())
	if err != nil || len(res.Found) == 0 {
		t.Fatalf("%+v %v", res, err)
	}
	for _, f := range res.Found {
		if f.Detail != code.Name {
			t.Fatalf("finding %+v", f)
		}
	}
}
