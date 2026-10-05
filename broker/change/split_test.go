package change

// REQ: CHG-1

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// goalCase journals a task under goal, records the owner's acceptance, and
// adds a case for it, passing claim as the caller's Goal. It returns the
// case's ID.
func (e *env) goalCase(goal, claim string) string {
	e.t.Helper()
	e.tasks++
	id := fmt.Sprintf("task-%d", e.tasks)
	if _, err := e.eng.Submit(journal.Intent{ID: id, GoalID: goal, Origin: "guest:a", Account: "mail", Action: "draft", Executor: "task"}); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"}); err != nil {
		e.t.Fatal(err)
	}
	c := Case{ID: "case-" + id, Class: ClassSkill, Input: []byte("skills/greet"), Expect: []byte("hello"), Outcome: Accepted, Task: id, Goal: claim}
	if err := e.p.AddTaskCase(c); err != nil {
		e.t.Fatal(err)
	}
	return c.ID
}

func (e *env) stored(id string) Case {
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	return e.p.st.Cases[id]
}

// CHG-1: every case of one goal lands on the same side of the
// split, in both the builder's dev view and the frozen held-out set, so a
// candidate is never scored on a goal whose sibling cases it was built from.
func TestSplitKeepsGoalTogether(t *testing.T) {
	e := newEnv(t, nil)
	byGoal := map[string][]string{}
	for g := 0; g < 80; g++ {
		goal := fmt.Sprintf("owner:msg-%d", g)
		for i := 0; i < 3; i++ {
			byGoal[goal] = append(byGoal[goal], e.goalCase(goal, ""))
		}
	}
	dev := map[string]bool{}
	for _, c := range e.p.Dev(ClassSkill) {
		dev[c.ID] = true
	}
	e.p.mu.Lock()
	held := map[string]bool{}
	for _, c := range e.p.freezeLocked([]Class{ClassSkill}).heldOut {
		held[c.ID] = true
	}
	e.p.mu.Unlock()
	sides := map[bool]int{}
	for goal, ids := range byGoal {
		first := dev[ids[0]]
		sides[first]++
		for _, id := range ids {
			if dev[id] != first {
				t.Fatalf("goal %s is split across dev and held-out", goal)
			}
			if dev[id] == held[id] {
				t.Fatalf("case %s is in both or neither of dev and held-out", id)
			}
		}
	}
	if sides[true] == 0 || sides[false] == 0 {
		t.Fatalf("all goals landed on one side: %v", sides)
	}
}

// CHG-1 (security C2): the goal that decides a case's side comes from the
// journal, never from the caller, so a guest cannot choose the split.
func TestSplitIgnoresCallerGoal(t *testing.T) {
	e := newEnv(t, nil)
	id := e.goalCase("owner:real", "owner:chosen")
	if got := e.stored(id).Goal; got != "owner:real" {
		t.Fatalf("stored goal %q, want the journal's", got)
	}
	id = e.goalCase("", "owner:chosen")
	if got := e.stored(id).Goal; got != "" {
		t.Fatalf("goal-less task stored caller goal %q", got)
	}
	// A case ID shaped like a goal key would share that goal's side.
	e.mustTask("t-shaped")
	e.eng.RecordQuality("t-shaped", journal.Quality{Verdict: journal.VerdictGood, Source: "owner"})
	if err := e.p.AddTaskCase(Case{ID: "goal:owner:real", Class: ClassSkill, Task: "t-shaped", Outcome: Accepted}); !errors.Is(err, ErrProvenance) {
		t.Fatalf("case id shaped like a goal key: %v", err)
	}
}

// CHG-1: a persisted suite never reshuffles. A case with no goal, whether
// from before goals were stamped or from a task with none, keeps the side
// its bare ID hashes to.
func TestSplitKeepsLegacySide(t *testing.T) {
	e := newEnv(t, nil)
	var ids []string
	for i := 0; i < 40; i++ {
		ids = append(ids, e.goalCase("", ""))
	}
	inDev := map[string]bool{}
	for _, c := range e.p.Dev(ClassSkill) {
		inDev[c.ID] = true
	}
	for _, id := range ids {
		if want := splitOf(e.p.key, id, 30) == dev; inDev[id] != want {
			t.Fatalf("legacy case %s moved sides", id)
		}
	}
	if k := splitKey(Case{ID: "case-1", Task: "task-1"}); k != "case-1" {
		t.Fatalf("legacy split key %q, want the bare ID", k)
	}
	if k := splitKey(Case{ID: "case-1", Goal: "owner:m"}); k != "goal:owner:m" {
		t.Fatalf("goal split key %q", k)
	}
}
