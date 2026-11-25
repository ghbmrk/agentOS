package kernel

// REQ: KRN-8

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// recentStep is a step of verb v whose arguments all name to.
func recentStep(v key.Verb, to string) PlanStep {
	s := PlanStep{Verb: v, Clerk: "mail", Args: map[string]string{}}
	for _, n := range key.ArgNames(v) {
		s.Args[n] = to
	}
	return s
}

// s.recent holds only irreversible effects, the only ones the duplicate
// guard reads (repeats): a completed reversible step is counted toward its
// shape's history but never recorded as a recent effect, so undoing it has
// nothing there to remove (#6281).
func TestRecentHoldsOnlyIrreversibleEffects(t *testing.T) {
	s := NewState(nil)
	var root key.ID
	root[0] = 1
	p := &PlanState{
		Plan:   Plan{ID: "p1", Steps: []PlanStep{recentStep(key.Draft, "a"), recentStep(key.Unsubscribe, "list-a")}},
		Status: SActive, Root: root,
		Steps: make([]StepState, 2),
	}
	if c, _ := key.ClassOf(key.Draft); c.Irreversible() {
		t.Fatal("draft is no longer reversible; pick another reversible verb")
	}
	if c, _ := key.ClassOf(key.Unsubscribe); !c.Irreversible() {
		t.Fatal("unsubscribe is no longer irreversible; pick another irreversible verb")
	}
	s.complete(p, 0, 10)
	s.complete(p, 1, 20)
	rev, irr := Fingerprint(p.Plan.Step(0)), Fingerprint(p.Plan.Step(1))
	if _, ok := s.recent[root][rev]; ok {
		t.Errorf("a reversible step is recorded in recent: %v", s.recent[root])
	}
	if at, ok := s.recent[root][irr]; !ok || at != 20 {
		t.Errorf("the irreversible step is not recorded at 20: %v", s.recent[root])
	}
	if s.seen[root][Shape(p.Plan.Step(0))] != 1 || s.seen[root][Shape(p.Plan.Step(1))] != 1 {
		t.Errorf("both shapes count toward the history: %v", s.seen[root])
	}
}
