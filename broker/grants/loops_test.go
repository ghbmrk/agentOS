package grants

// The gate delegates meta.loops.* to Config.Loops (GR18): with no
// scheduler they are denied, and only the sentinel itself asks the owner.
// The loop scheduler no longer sends its settings through the journal
// (#2786), so these drive the gate's evaluateLoops with fakes.
// REQ: LOOP-0, CH-10

import (
	"context"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// loopsExecutor is the loop scheduler's retired executor name.
const loopsExecutor = "loops"

// needsOwner is a sentinel whose NeedsOwner is true, as loops'
// ErrNeedsOwner was.
type needsOwner struct{}

func (needsOwner) Error() string    { return "loops: needs the owner's approval" }
func (needsOwner) NeedsOwner() bool { return true }

var errNeedsOwner error = needsOwner{}

func TestLoopSettingsDeniedWithoutScheduler(t *testing.T) {
	exec := &fakeExec{ran: map[string]int{}}
	r := newRigExecs(t, nil, map[string]journal.Executor{loopsExecutor: exec})
	st := r.submit(journal.Intent{ID: "loops:n1:off:all", Origin: "owner", Account: journal.BrokerAccount,
		Action: journal.ActionLoopsOff, Executor: loopsExecutor})
	if st.State != journal.Denied || st.Permission.Reason != "the loop scheduler is not running" {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// fakeLoops answers Check with a fixed error.
type fakeLoops struct{ err error }

func (f fakeLoops) Check(context.Context, journal.Phase, journal.Intent) error { return f.err }
func (fakeLoops) Line(journal.Intent) (owner.Item, error) {
	return owner.Item{Object: "x", Facts: owner.Facts{Verb: "raise"}}, nil
}

func TestOnlyTheLoopsSentinelItselfAsks(t *testing.T) {
	in := journal.Intent{ID: "loops:n1:budget:400", Action: "meta.loops.budget"}
	for _, err := range []error{
		errors.Join(errors.New("loops: refused"), errNeedsOwner),
		wrapErr(errNeedsOwner),
		errors.New("loops: needs the owner's approval"),
	} {
		if v := New(Config{Loops: fakeLoops{err}}).evaluateLoops(context.Background(), journal.PhaseAuthorize, in); v.kind != deny {
			t.Fatalf("%v: %v", err, v.kind)
		}
	}
	if v := New(Config{Loops: fakeLoops{errNeedsOwner}}).evaluateLoops(context.Background(), journal.PhaseAuthorize, in); v.kind != ask {
		t.Fatal(v.kind)
	}
}
