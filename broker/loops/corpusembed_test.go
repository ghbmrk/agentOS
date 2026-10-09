package loops_test

// REQ: LOOP-7, LOOP-9

import (
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/corpus"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// LOOP-7, LOOP-9: through Guard, a planted code filter that misses one
// embedded item gives one High corpus finding through Report, naming the
// item and the check; a clean run of the same probe closes it.
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
	rig := loops.NewProbeRig(t, p)
	rig.Run(t)
	if name, res := rig.Run(t); name != "probe:corpus" || res.Err != nil || res.Value != 1 {
		t.Fatalf("%q %+v", name, res)
	}
	ev := rig.Evidence()
	if len(ev) != 1 {
		t.Fatalf("evidence %+v", ev)
	}
	if f := ev[0].Finding; f.Check != loops.CheckCorpus || f.Severity != loops.High || f.Subject != target.ID || f.Detail != corpus.CodeFilter {
		t.Fatalf("finding %+v", f)
	}
	p.Checks[0] = code
	rig.Advance(time.Hour)
	if name, res := rig.Run(t); name != "probe:corpus" || res.Err != nil || res.Value != 0 {
		t.Fatalf("%q %+v", name, res)
	}
	if rig.Open(ev[0].Finding.ID) {
		t.Fatal("a clean run left the finding open")
	}
}

// LOOP-7: a probe over no items fails closed, an error and not a pass.
func TestACorpusProbeOverNoItemsFailsClosed(t *testing.T) {
	p, err := corpus.Probe(time.Hour, owner.Commitments{})
	if err != nil {
		t.Fatal(err)
	}
	p.Items = nil
	rig := loops.NewProbeRig(t, p)
	rig.Run(t)
	if name, res := rig.Run(t); name != "probe:corpus" || res.Err == nil {
		t.Fatalf("%q %+v", name, res)
	}
}
