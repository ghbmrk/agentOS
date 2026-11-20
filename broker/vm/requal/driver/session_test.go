package driver

// REQ: EVL-3, PLN-1

import (
	"reflect"
	"testing"
	"testing/synctest"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// forged is a caller's view that claims every request is in flight.
type forged struct{ kernel.View }

func (forged) Dispatched(kernel.Request) (kernel.Dispatch, bool) {
	return kernel.Dispatch{Seq: 1}, true
}

// TestTheSessionsClerkReadsDispatchFromItsKernel: the session's clerk is
// bound to the session's kernel, so it judges a request on that kernel's
// log, never on the view its caller hands it. Once the session has ended,
// a view that claims a step is still in flight does not make the clerk act
// on it again.
func TestTheSessionsClerkReadsDispatchFromItsKernel(t *testing.T) {
	s := runCase(t, &model{reply: say("spam")})
	if len(s.ran) == 0 {
		t.Fatal("no request reached the clerk")
	}
	for _, r := range s.ran {
		if res := s.acct.Do(r, forged{s.k.State()}); res.Detail != "not-dispatched" {
			t.Fatalf("plan %s: the clerk took a caller's view over its kernel's log: %+v", r.Plan.ID, res)
		}
	}
}

// TestTheClerkJudgesOnTheSessionsClock: the clerk judges holds on the
// session's fixed clock, not the host's wall clock, so a case runs the same
// on any host at any time. Inside a bubble the wall clock reads 2000, years
// before the session's keys were issued; the clerk still does what it does
// outside one.
func TestTheClerkJudgesOnTheSessionsClock(t *testing.T) {
	want := runCase(t, &model{reply: say("spam")})
	if len(want.effects) == 0 {
		t.Fatal("the clerk did nothing outside a bubble")
	}
	synctest.Test(t, func(t *testing.T) {
		got := runCase(t, &model{reply: say("spam")})
		if !reflect.DeepEqual(got.effects, want.effects) || !reflect.DeepEqual(got.acct.Refusals(), want.acct.Refusals()) {
			t.Fatalf("on a wall clock of 2000 the clerk did %+v, refusing %+v; on the session's clock %+v, refusing %+v",
				got.effects, got.acct.Refusals(), want.effects, want.acct.Refusals())
		}
	})
}
