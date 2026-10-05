package grants

// The gate delegates meta.loops.* to the loop scheduler (GR18): settings
// the owner's text may make run at once, a budget raise is a low-tier
// owner request, guests never reach them, and an unanswered raise lapses.
// REQ: LOOP-0, LOOP-6, OP-5, CH-10, CHG-2

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/owner"
)

// The scheduler is what the gate expects.
var _ Loops = (*loops.Scheduler)(nil)

func loopsRig(t *testing.T) (*rig, *loops.Scheduler) {
	t.Helper()
	spare, err := meter.Open(meter.Config{Path: filepath.Join(t.TempDir(), "spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000}, OverallCap: loops.SpareLimits(loops.DefaultSpareCalls)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare})
	if err != nil {
		t.Fatal(err)
	}
	r := newRigExecs(t, func(c *Config) { c.Loops = s }, map[string]journal.Executor{loops.Executor: s})
	s.Attach(r.g)
	return r, s
}

func TestLoopSettingsGoThroughTheScheduler(t *testing.T) {
	r, s := loopsRig(t)
	ctx := context.Background()
	if got, ok := s.Text(ctx, "LOOPS OFF"); !ok || !strings.HasPrefix(got, "Spare-time work is off") || !s.Settings().Off {
		t.Fatalf("%q %v %+v", got, ok, s.Settings())
	}
	if got, ok := s.Text(ctx, "spare budget 40"); !ok || s.Settings().SpareCalls != 40 {
		t.Fatalf("lowering the budget: %q %v", got, ok)
	}
	n := r.own.count()
	if got, ok := s.Text(ctx, "SPARE BUDGET 80"); !ok || !strings.Contains(got, "needs your approval") {
		t.Fatalf("%q %v", got, ok)
	}
	r.g.Flush()
	_, items := r.own.last(t)
	want := owner.Item{Object: "spare-time AI use", Detail: "from 40 to 80 paid AI calls a day", UndoBy: "SPARE BUDGET 40 any time",
		Facts: owner.Facts{Kind: owner.Ordinary, Verb: "raise", NoRecipient: true}}
	if r.own.count() != n+1 || len(items) != 1 || !sameItem(items[0], want) {
		t.Fatalf("owner item: %+v", items)
	}
	if r.own.Tier(items[0].Facts) != owner.Low {
		t.Fatal("a small budget raise is not low tier")
	}
	r.decide(true, "owner")
	if s.Settings().SpareCalls != 80 {
		t.Fatalf("approved raise not applied: %+v", s.Settings())
	}
	// A large raise spends real provider money: it needs the code
	// generator, not a texted code (security B1 on #57).
	if _, ok := s.Text(ctx, "SPARE BUDGET 5000"); !ok {
		t.Fatal("not a setting")
	}
	r.g.Flush()
	if _, items := r.own.last(t); len(items) != 1 || r.own.Tier(items[0].Facts) != owner.High {
		t.Fatalf("a raise from 80 to 5000 is not high tier: %+v", items)
	}
}

// GR14, LOOP-6: no guest, loop, or pipeline origin changes a setting.
func TestOnlyTheOwnerChangesLoopSettings(t *testing.T) {
	r, _ := loopsRig(t)
	for i, origin := range []string{"guest:agent", "loop1"} {
		st := r.submit(journal.Intent{ID: fmt.Sprintf("loops:n%d:budget:5", i+1), Origin: origin, Account: journal.BrokerAccount,
			Action: loops.ActionBudgetLower, Executor: loops.Executor})
		if st.State != journal.Denied {
			t.Fatalf("%s: %s", origin, st.State)
		}
	}
}

func TestLoopSettingsDeniedWithoutScheduler(t *testing.T) {
	exec := &fakeExec{ran: map[string]int{}}
	r := newRigExecs(t, nil, map[string]journal.Executor{loops.Executor: exec})
	st := r.submit(journal.Intent{ID: "loops:n1:off:all", Origin: loops.OriginOwner, Account: journal.BrokerAccount,
		Action: loops.ActionOff, Executor: loops.Executor})
	if st.State != journal.Denied || st.Permission.Reason != "the loop scheduler is not running" {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
}

// An unanswered raise closes as lapsed, not declined (arbitrator Q3 on #48).
func TestAnUnansweredRaiseLapses(t *testing.T) {
	r, s := loopsRig(t)
	if _, ok := s.Text(context.Background(), "SPARE BUDGET 400"); !ok {
		t.Fatal("not a setting")
	}
	r.g.Flush()
	_, items := r.own.last(t)
	r.decide(false, "expired")
	if st := r.state(items[0].Ref); st.State != journal.Denied || !strings.Contains(st.Permission.Reason, "lapsed, not declined") {
		t.Fatalf("%s %q", st.State, st.Permission.Reason)
	}
	if s.Settings().SpareCalls != loops.DefaultSpareCalls {
		t.Fatal("a lapsed raise was applied")
	}
}

// fakeLoops answers Check with a fixed error.
type fakeLoops struct{ err error }

func (f fakeLoops) Check(context.Context, journal.Phase, journal.Intent) error { return f.err }
func (fakeLoops) Line(journal.Intent) (owner.Item, error) {
	return owner.Item{Object: "x", Facts: owner.Facts{Verb: "raise"}}, nil
}

func TestOnlyTheLoopsSentinelItselfAsks(t *testing.T) {
	in := journal.Intent{ID: "loops:n1:budget:400", Action: loops.ActionBudget}
	for _, err := range []error{
		errors.Join(errors.New("loops: refused"), loops.ErrNeedsOwner),
		wrapErr(loops.ErrNeedsOwner),
		errors.New("loops: needs the owner's approval"),
	} {
		if v := New(Config{Loops: fakeLoops{err}}).evaluateLoops(context.Background(), journal.PhaseAuthorize, in); v.kind != deny {
			t.Fatalf("%v: %v", err, v.kind)
		}
	}
	if v := New(Config{Loops: fakeLoops{loops.ErrNeedsOwner}}).evaluateLoops(context.Background(), journal.PhaseAuthorize, in); v.kind != ask {
		t.Fatal(v.kind)
	}
}
