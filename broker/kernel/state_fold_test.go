package kernel_test

// REQ: KRN-1, KRN-3, KEY-8

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// The folds of a line, an undo, a retry and a recovery rotation refuse an
// entry whose body does not decode, rather than folding the zero value or
// nothing in its place (KRN-1).
func TestTheseFoldsRefuseABodyTheyCannotRead(t *testing.T) {
	for _, typ := range []string{kernel.TLine, kernel.TStepUndone, kernel.TStepRetried, kernel.TRecoveryRotate} {
		_, err := kernel.Replay(nil, []kernel.Entry{{Seq: 1, Type: typ, Body: json.RawMessage(`"x"`)}})
		if !errors.Is(err, kernel.ErrCorrupt) {
			t.Errorf("%s with an unreadable body: %v", typ, err)
		}
	}
}

// An amount of "0" is the amount zero, in its one canonical spelling; only
// another spelling is unreadable (KRN-3).
func TestAZeroAmountIsZero(t *testing.T) {
	for v, want := range map[string]int64{"0": 0, "7": 7, "-0": -1, "00": -1} {
		got := kernel.Normalize("t", kernel.PlanStep{Verb: key.Buy, Args: map[string]string{key.ArgAmount: v}}).Amount
		if got != want {
			t.Errorf("amount %q read as %d, want %d", v, got, want)
		}
	}
}

// A grant is pending strictly before its From and live from it on; the
// pending list is in ID order, whatever order the map yields (D-146).
func TestPendingEndsAtFromAndListsInIDOrder(t *testing.T) {
	s := kernel.NewState(nil)
	for i := range 20 {
		k := key.Key{Root: key.Root{Clerk: "mail", Serial: fmt.Sprint(i)}}
		s.Grants[k.Tip()] = kernel.Grant{Key: k, From: 10}
	}
	got := s.Pending(9)
	if len(got) != 20 {
		t.Fatalf("%d pending before From, want 20", len(got))
	}
	for i := 1; i < len(got); i++ {
		if bytes.Compare(got[i-1][:], got[i][:]) >= 0 {
			t.Fatalf("pending out of ID order at %d", i)
		}
	}
	if got := s.Pending(10); len(got) != 0 {
		t.Fatalf("%d pending at From, want none", len(got))
	}
}

// Undoing a done step takes its shape back out of the root's history, so
// the same shape is novel again and waits the novelty window; without the
// undo it is known (KEY-8).
func TestAnUndoneShapeIsNovelAgain(t *testing.T) {
	for _, undo := range []bool{false, true} {
		r := newRig(t)
		k := r.derive(key.LimitHold(hour, 4*hour))
		r.plan("p1", k, st(key.Unsubscribe, "list-a"))
		must(t, r.tick(0))
		must(t, r.tick(4*hour))
		if r.k.State().Plans["p1"].Steps[0].Phase != kernel.PDone {
			t.Fatalf("p1 did not run: %s", r.k.State().Plans["p1"].Steps[0].Phase)
		}
		if undo {
			must(t, r.k.Undo(5*hour, "p1", 0))
		}
		// a day on, the same effect is no duplicate (KRN-8), and only its shape decides the window
		must(t, r.k.Submit(30*hour, r.sign(kernel.Plan{ID: "p2", Key: k, Steps: []kernel.PlanStep{st(key.Unsubscribe, "list-a")}})))
		must(t, r.tick(30*hour))
		if st := r.k.State().Plans["p2"].Steps[0]; st.Phase != kernel.PHeld || st.Novel != undo {
			t.Fatalf("undo %v: p2 %s novel %v, want held novel %v", undo, st.Phase, st.Novel, undo)
		}
	}
}
