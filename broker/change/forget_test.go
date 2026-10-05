package change

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
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
	ids, err := e.p.ForgetGoal("owner:g1")
	if err != nil || strings.Join(ids, ",") != "case-owner:g1-t0,case-owner:g1-t1" {
		t.Fatalf("forgot %q: %v", ids, err)
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
	if ids, err := e.p.ForgetGoal("owner:g1"); err != nil || len(ids) != 0 {
		t.Fatalf("second forget: %q %v", ids, err)
	}
	if _, err := e.p.ForgetGoal(""); err == nil {
		t.Fatal("an empty goal forgot cases without a goal")
	}
}

// W3-tasks part 1 (L3 on #123): forgetting skips CHG-2's second approval
// because only the owner's authenticated forget may call it, and dropping
// harvest records un-holds tasks Loop 1 must never mine. So only the
// composition root (cmd/agentosd) may call ForgetGoal or ForgetCases:
// a loop, a builder or the evaluator calling either fails this test.
func TestOnlyTheDaemonForgets(t *testing.T) {
	root := ".."
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if dir := filepath.ToSlash(filepath.Dir(rel)); dir == "cmd/agentosd" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "ForgetGoal" || sel.Sel.Name == "ForgetCases") {
				t.Errorf("%s calls %s; only cmd/agentosd may", rel, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
