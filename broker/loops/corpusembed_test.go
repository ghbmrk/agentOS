package loops_test

// REQ: LOOP-7, LOOP-9

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/corpus"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// LOOP-7, LOOP-9: a planted code filter that misses one embedded item
// gives one High corpus finding, naming the item and the check; a clean
// run of the same probe finds nothing and lists the item as checked.
func TestAWeakenedInProcessCheckIsOneHighFinding(t *testing.T) {
	p, err := corpus.Probe(time.Hour, owner.Commitments{})
	if err != nil {
		t.Fatal(err)
	}
	target := p.Items[len(p.Items)-1]
	code := p.Checks[0]
	weak := code
	weak.Hit = func(s string) bool { return code.Hit(s) && !strings.HasPrefix(s, target.Text) }
	p.Checks = []loops.ClosedCheck{weak, p.Checks[1]}
	res, err := p.Run(context.Background())
	if err != nil || len(res.Found) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	if f := res.Found[0]; f.Check != loops.CheckCorpus || f.Severity != loops.High || f.Subject != target.ID || f.Detail != corpus.CodeFilter {
		t.Fatalf("finding %+v", f)
	}
	p.Checks[0] = code
	res, err = p.Run(context.Background())
	if err != nil || len(res.Found) != 0 || !slices.Contains(res.Checked, loops.CorpusKey(target.ID, corpus.CodeFilter)) {
		t.Fatalf("clean run %+v %v", res, err)
	}
}

// LOOP-7: a probe over no items fails closed, an error and not a pass.
func TestACorpusProbeOverNoItemsFailsClosed(t *testing.T) {
	p, err := corpus.Probe(time.Hour, owner.Commitments{})
	if err != nil {
		t.Fatal(err)
	}
	p.Items = nil
	if res, err := p.Run(context.Background()); err == nil {
		t.Fatalf("%+v", res)
	}
}
