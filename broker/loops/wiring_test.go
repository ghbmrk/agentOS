package loops

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: LOOP-0, CH-10, CH-11, OP-5, CHG-1
//
// What the grants gate and the owner channel use: the sentinel the gate
// recognizes, the broker-rendered line for a budget raise, the owner text
// hook, and the review follow-ups from #49.

func TestNeedsOwnerIsRecognizedWithoutImportingLoops(t *testing.T) {
	no, ok := ErrNeedsOwner.(interface{ NeedsOwner() bool })
	if !ok || !no.NeedsOwner() {
		t.Fatal("ErrNeedsOwner does not report NeedsOwner")
	}
	if !errors.Is(ErrNeedsOwner, ErrNeedsOwner) {
		t.Fatal("ErrNeedsOwner is not comparable")
	}
}

func TestABudgetRaiseIsALowTierLineFromBrokerState(t *testing.T) {
	r := newRig(t)
	it, err := r.s.Line(journal.Intent{ID: "loops:n7:budget:400", Action: ActionBudget})
	must(t, err)
	want := owner.Item{Object: "spare-time AI use", Detail: "from 100 to 400 paid AI calls a day", UndoBy: "SPARE BUDGET 100 any time",
		Facts: owner.Facts{Kind: owner.GrantChange, Verb: "raise", NoRecipient: true}}
	if it != want {
		t.Fatalf("%+v", it)
	}
	// Only a small step is low tier: at most twice the budget and at most
	// LowTierRaiseMax; anything else needs the code generator (security B1
	// on #57).
	for id, low := range map[string]bool{
		"loops:n8:budget:200":  true,
		"loops:n8:budget:201":  false,
		"loops:n8:budget:5000": false,
	} {
		it, err := r.s.Line(journal.Intent{ID: id, Action: ActionBudget})
		must(t, err)
		if got := owner.Classify(it.Facts, owner.Limits{}, time.Now()) == owner.Low; got != low {
			t.Fatalf("%s: low tier %v, want %v", id, got, low)
		}
	}

	for _, in := range []journal.Intent{
		{ID: "loops:n7:budget:40", Action: ActionBudgetLower},
		{ID: "loops:n7:off:all", Action: ActionOff},
		{ID: "loops:n7:budget:400x", Action: ActionBudget},
	} {
		if _, err := r.s.Line(in); err == nil {
			t.Fatalf("%s: a line for an intent that never asks", in.ID)
		}
	}
}

func TestOwnerTextChangesSettingsAndLeavesTaskChatAlone(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	if _, ok := r.s.Text(ctx, "learning is off, right?"); ok {
		t.Fatal("task chat taken as a setting")
	}
	if got, ok := r.s.Text(ctx, "learning off"); !ok || got != "Learning is off until you reply LEARNING ON." {
		t.Fatalf("%q %v", got, ok)
	}
	if !r.s.Settings().Paused[Improve] {
		t.Fatal("LEARNING OFF did not pause Loop 1")
	}
	// The rig's policy refuses a raise outright; the reply says so.
	if got, ok := r.s.Text(ctx, "SPARE BUDGET 400"); !ok || got != "That setting did not take effect. Reply HELP LOOPS for the settings." {
		t.Fatalf("%q %v", got, ok)
	}
	// The gate leaves it pending for the owner's approval instead.
	r.s.Attach(pending{r.eng})
	if got, ok := r.s.Text(ctx, "SPARE BUDGET 400"); !ok || got != "Raising spare-time AI use needs your approval; a request follows." {
		t.Fatalf("%q %v", got, ok)
	}
	r.s.Attach(r.eng)
	if r.s.Settings().SpareCalls != DefaultSpareCalls {
		t.Fatal("a raise took effect without approval")
	}
	if got, ok := r.s.Text(ctx, "help loops"); !ok || got != HelpText {
		t.Fatalf("%q %v", got, ok)
	}
}

// L3 R2 on #49: settings are pruned by apply order, so one applied after
// many newer submissions (an approval that waited) is still reconciled.
func TestASettingAppliedLateIsKeptForReconcile(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for i := 0; i < keepApplied+20; i++ {
		msg := "LOOPS OFF"
		if i%2 == 1 {
			msg = "LOOPS ON"
		}
		r1, _ := ParseText(msg)
		must(t, r.s.Set(ctx, r1))
	}
	late := journal.Intent{ID: "loops:n0:budget:400", Origin: OriginOwner, Account: journal.BrokerAccount,
		Action: ActionBudget, Executor: Executor}
	if o := r.s.Execute(ctx, late, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("%+v", o)
	}
	if o := r.s.Reconcile(ctx, late, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("a setting just applied was pruned: %+v", o)
	}
	r.s.mu.Lock()
	n, m := len(r.s.st.Applied), len(r.s.st.Order)
	r.s.mu.Unlock()
	if n != keepApplied || m != keepApplied {
		t.Fatalf("kept %d applied, %d in order; want %d", n, m, keepApplied)
	}
	// After a restart the order is what was saved.
	r.restart()
	if o := r.s.Reconcile(ctx, late, 1); o.Result != journal.ResultSucceeded {
		t.Fatalf("after restart: %+v", o)
	}
}

type failFirst struct {
	change.MemStore
	n int
}

func (f *failFirst) Save(b []byte) error {
	f.n++
	if f.n == 1 {
		return errors.New("disk gone")
	}
	return f.MemStore.Save(b)
}

// L3 follow-up on #49: a crash before the case is added leaves no case in
// the pipeline and nothing saved, and a retry adds the case once.
func TestACrashBeforeTheCaseIsAddedIsRetried(t *testing.T) {
	r := newRig(t)
	st := &failFirst{}
	h := &Harvester{J: r.eng, Pipeline: r.p, Store: st}
	id := "early-1"
	r.task(id, "g"+id, "mail", "draft", "private")
	o := Outcome{Intent: id, Action: Approved, Input: []byte("draft a note"), Output: []byte("note")}
	if err := h.Harvest(o); err == nil {
		t.Fatal("the first save did not fail")
	}
	inSuite := func() bool {
		ids := map[string]bool{}
		for _, c := range r.p.Dev(change.ClassTask) {
			ids[c.ID] = true
		}
		ev, err := h.Evidence()
		must(t, err)
		return ids[id] || ev.HeldOut > 0
	}
	if inSuite() {
		t.Fatal("a case was added though its task was never saved")
	}
	h2 := &Harvester{J: r.eng, Pipeline: r.p, Store: &st.MemStore}
	must(t, h2.Harvest(o))
	must(t, h2.Harvest(o)) // a second retry adds nothing
	ev, err := h2.Evidence()
	must(t, err)
	dev := 0
	for _, c := range r.p.Dev(change.ClassTask) {
		if c.ID == id {
			dev++
		}
	}
	if dev+ev.HeldOut != 1 {
		t.Fatal(fmt.Sprintf("the case was added %d times", dev+ev.HeldOut))
	}
}

func TestPluralLoopNamesReadAsPlural(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.s.Text(ctx, "SECURITY TESTS OFF")
	found := false
	for _, l := range r.s.Digest() {
		found = found || l == "Security tests are off. Reply SECURITY TESTS ON to restart them."
	}
	if !found {
		t.Fatalf("%q", r.s.Digest())
	}
}

// pending is a journal whose policy, like the grants gate's, leaves an
// intent that needs the owner pending.
type pending struct{ Journal }

func (pending) Submit(in journal.Intent) (journal.Status, error) {
	return journal.Status{Intent: in, State: journal.Pending}, nil
}

func (pending) Authorize(_ context.Context, id string) (journal.Status, error) {
	return journal.Status{State: journal.Pending}, nil
}
