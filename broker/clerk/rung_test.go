package clerk_test

// REQ: CH-3, KEY-2, CLK-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/check"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// rungAt is the view with every step a test built dispatched at rung.
type rungAt struct {
	inFlight
	rung key.Proof
}

func (v rungAt) Dispatched(r kernel.Request) (kernel.Dispatch, bool) {
	d, ok := v.inFlight.Dispatched(r)
	d.Rung = v.rung
	return d, ok
}

// The clerk judges a step's rung from the log's dispatch, never from the
// request: below the key's rung caveat it refuses `rung` and acts on
// nothing; at or above it, it runs the step (CH-3, D-311).
func TestClerkRefusesAStepBelowItsKeysRung(t *testing.T) {
	f := setup(t, key.Trash)
	hpub, _ := gen(2)
	d, err := key.Derive(f.root, hpubPriv(), hpub, key.LimitRung(key.P3))
	if err != nil {
		t.Fatal(err)
	}
	u := f.request("r1", d, stepOf(key.Trash))
	anchors := []key.PublicKey{key.Ed25519(opubOf())}
	for r := key.P0; r <= key.P4; r++ {
		rf := check.Check(anchors, "mail", f.mail.Facts, 1, u, rungAt{inFlight{f.k.State(), f.plans}, r})
		if r < key.P3 && (rf == nil || rf.Code != key.RRung) || r >= key.P3 && rf != nil {
			t.Fatalf("%v: %v", r, rf)
		}
	}
	if res := f.mail.Do(u, rungAt{inFlight{f.k.State(), f.plans}, key.P2}); res.Outcome != "failed" || len(f.mail.Effects()) != 0 {
		t.Fatalf("a P2 dispatch under a P3 key: %+v, %d effects", res, len(f.mail.Effects()))
	}
	if res := f.mail.Do(u, rungAt{inFlight{f.k.State(), f.plans}, key.P3}); res.Outcome != "ok" {
		t.Fatalf("a P3 dispatch under a P3 key: %+v", res)
	}
}
