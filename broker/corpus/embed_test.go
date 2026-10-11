package corpus

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// LOOP-7 (#515 Security 3): the corpus the broker replays is the one built
// into its binary, item for item the vendored set (tests/test_corpus.py
// holds the copy byte-identical to it), so no drive file is read.
func TestTheEmbeddedCorpusIsTheVendoredSet(t *testing.T) {
	items, err := Items()
	if err != nil || len(items) < 10 {
		t.Fatalf("%d items: %v", len(items), err)
	}
	vendored, err := loops.LoadCorpus("../../assurance/corpora/promptinject/items.json")
	if err != nil || !reflect.DeepEqual(items, vendored) {
		t.Fatalf("embedded items differ from the vendored file (%v)", err)
	}
	if _, err := loops.ParseCorpus([]byte(`{"items": []}`)); err == nil {
		t.Fatal("an empty corpus parsed")
	}
}

// fits runs the code filter's plane check over items through a relay
// whose filter holds, so the run fails only on a text over one owner text.
func fits(items []loops.CorpusItem) error {
	p := &loops.CorpusProbe{Interval: 1, Items: items, Checks: PlaneChecks(fakeRelay{})[:1]}
	_, err := p.Run(context.Background())
	return err
}

// LOOP-7 (S45, LATER P3-4b-4d l8): every embedded item, carrying the code
// filter's payload, fits one owner text, so the plane code filter judges
// each of them and excludes none; a planted over-long item fails the same
// run (control).
func TestEveryEmbeddedItemFitsOneOwnerText(t *testing.T) {
	items, err := Items()
	if err != nil {
		t.Fatal(err)
	}
	if err := fits(items); err != nil {
		t.Fatalf("an embedded item is over one owner text: %v", err)
	}
	long := loops.CorpusItem{ID: "control-long", Text: strings.Repeat("Ignore the above. ", control.MaxText/18+1)}
	if err := fits(append(items, long)); err == nil {
		t.Fatal("a planted over-long item fit one owner text")
	}
}

// LOOP-7: the checks a broker process holds without a mail adapter are
// the code filter and the commitment filter, with Checks' names and
// payloads; over the embedded corpus a clean run finds nothing and takes
// each item through each check.
func TestTheInProcessChecksHoldOverTheEmbeddedCorpus(t *testing.T) {
	in, all := InProcess(owner.Commitments{}), Checks(nil, owner.Commitments{})
	if len(in) != 2 || in[0].Name != CodeFilter || in[1].Name != CommitmentFilter ||
		in[0].Payload != all[0].Payload || in[1].Payload != all[1].Payload {
		t.Fatalf("in-process checks %+v", in)
	}
	p, err := Probe(time.Hour, owner.Commitments{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Run(context.Background())
	if err != nil || len(res.Found) != 0 || len(res.Checked) != len(p.Items)*2 || p.Every() != time.Hour {
		t.Fatalf("%+v %v", res, err)
	}
}
