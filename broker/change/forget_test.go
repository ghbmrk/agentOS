package change

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CAP-3, CHG-2

// W3-tasks part 1 (security R1 on PW3): forgetting a task removes every
// task case harvested from it, by the goal the journal stamped, and saves
// the suite without them. Other goals' cases and the security fixtures
// stay. It is the owner's deletion (CAP-3), not a suite change a candidate
// or loop could make, so it needs no second approval.
func TestForgetGoalRemovesItsCases(t *testing.T) {
	e := newEnv(t, nil)
	add := func(goal string, n int) {
		for i := range n {
			id := fmt.Sprintf("%s-t%d", goal, i)
			if _, err := e.eng.Submit(journal.Intent{ID: id, GoalID: goal, Origin: "guest:a", Account: "mail", Action: "draft", Executor: "task"}); err != nil {
				t.Fatal(err)
			}
			if _, err := e.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner"}); err != nil {
				t.Fatal(err)
			}
			if err := e.p.AddTaskCase(Case{ID: "case-" + id, Class: ClassSkill, Input: []byte("CANARY-" + goal), Expect: []byte("ok"), Outcome: Accepted, Task: id}); err != nil {
				t.Fatal(err)
			}
		}
	}
	add("owner:g1", 2)
	add("owner:g2", 1)
	n, err := e.p.ForgetGoal("owner:g1")
	if err != nil || n != 2 {
		t.Fatalf("forgot %d cases: %v", n, err)
	}
	e.p.mu.Lock()
	_, kept := e.p.st.Cases["case-owner:g2-t0"]
	_, sec := e.p.st.Cases["sec-1"]
	left := len(e.p.st.Cases)
	e.p.mu.Unlock()
	if !kept || !sec || left != 2 {
		t.Fatalf("left %d cases (g2 %v, security %v)", left, kept, sec)
	}
	raw, err := e.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	var saved state
	if err := json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	for _, c := range saved.Cases {
		if c.Goal == "owner:g1" || bytes.Contains(c.Input, []byte("CANARY-owner:g1")) {
			t.Fatalf("the saved suite still holds %s", c.ID)
		}
	}
	if len(saved.Cases) != 2 {
		t.Fatalf("saved %d cases, want 2", len(saved.Cases))
	}
	if n, err := e.p.ForgetGoal("owner:g1"); err != nil || n != 0 {
		t.Fatalf("second forget: %d %v", n, err)
	}
	if _, err := e.p.ForgetGoal(""); err == nil {
		t.Fatal("an empty goal forgot cases without a goal")
	}
}
