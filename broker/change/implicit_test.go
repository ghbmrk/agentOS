package change

// REQ: CHG-1, CHG-6

import (
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
)

// implicitCase journals a task whose auto-reply the owner let go (loops
// L6) and adds its case. The caller's Implicit mark is ignored: the
// journal's verdict source decides it.
func (e *env) implicitCase(class Class, input, expect string) {
	e.t.Helper()
	e.tasks++
	id := "task-" + itoa(e.tasks)
	e.mustTask(id)
	if _, err := e.eng.RecordQuality(id, journal.Quality{Verdict: journal.VerdictGood, Source: "owner-implicit"}); err != nil {
		e.t.Fatal(err)
	}
	if err := e.p.AddTaskCase(Case{ID: "case-" + id, Class: class, Input: []byte(input), Expect: []byte(expect), Outcome: Accepted, Task: id}); err != nil {
		e.t.Fatal(err)
	}
}

// PW3 part B (security B1(d), potency C3(c) on #90): implicit cases test a
// candidate and count half toward MinHeldOut, but a candidate whose passed
// held-out cases are all implicit never adopts on its own: it goes to the
// owner, at the tier Line gives it (potency C1).
func TestImplicitCasesNeverAnchorAnAdoption(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 20; i++ {
		e.implicitCase(ClassSkill, "skills/greet", "hello")
	}
	e.p.Attach(holdJournal{e.eng})
	rep := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if rep.Implicit == 0 || rep.Implicit != rep.HeldOut || rep.ImplicitPassed != rep.Passed {
		t.Fatalf("implicit cases not counted as implicit: %+v", rep)
	}
	if rep.State != StateAwaitingOwner || rep.Basis != BasisOwner || !rep.NeedsExplicit {
		t.Fatalf("an implicit-only win adopted on its own: %+v", rep)
	}
	if !e.p.Waiting(rep.ID) || e.p.Waiting("c999") {
		t.Fatal("Waiting does not track the open request")
	}
	if it, err := e.p.Line(journal.Intent{ID: adoptID(rep.ID), Action: ActionAdopt}); err != nil || it.Facts.Kind != owner.Ordinary {
		t.Fatalf("a tested, undoable local skill is not low tier: %+v %v", it, err)
	}

	// With explicit evidence too, it adopts, and the explicit cases count
	// whole while implicit ones count half.
	e = newEnv(t, nil)
	for i := 0; i < 4; i++ {
		e.implicitCase(ClassSkill, "skills/greet", "hello")
	}
	for i := 0; i < 12; i++ {
		e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
	}
	rep = e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if rep.Passed-rep.ImplicitPassed == 0 || rep.State != StateAdopted || rep.Basis != BasisStanding || rep.NeedsExplicit {
		t.Fatalf("with explicit evidence: %+v", rep)
	}
}

// Half weight: too few implicit cases leave a candidate short of the
// evidence an auto-adoption needs even when every one passed.
func TestImplicitCasesCountHalf(t *testing.T) {
	e := newEnv(t, nil) // MinHeldOut 3
	// heldOnly drops dev-side cases, so the held-out suite is exactly what
	// the test added.
	heldOnly := func() {
		dev := map[string]bool{}
		for _, c := range e.p.Dev(ClassSkill) {
			dev[c.ID] = true
		}
		e.p.mu.Lock()
		for id := range dev {
			delete(e.p.st.Cases, id)
		}
		e.p.mu.Unlock()
	}
	held := func(implicit bool) int {
		n := 0
		e.p.mu.Lock()
		for _, c := range e.p.st.Cases {
			if !c.Security && c.Implicit == implicit {
				n++
			}
		}
		e.p.mu.Unlock()
		return n
	}
	for held(false) < 1 {
		e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
		heldOnly()
	}
	for held(true) < 3 {
		e.implicitCase(ClassSkill, "skills/greet", "hello")
		heldOnly()
	}
	e.p.Attach(holdJournal{e.eng})
	rep := e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if rep.HeldOut != 4 || rep.Implicit != 3 || weighed(rep.Score) != 2 || rep.Basis == BasisStanding {
		t.Fatalf("1 explicit and 3 implicit cases (weighing 2 of 3): %+v", rep)
	}
	e.p.Attach(e.eng)
	for held(true) < 4 {
		e.implicitCase(ClassSkill, "skills/greet", "hello")
		heldOnly()
	}
	rep = e.propose(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}})
	if weighed(rep.Score) != 3 || rep.State != StateAdopted {
		t.Fatalf("1 explicit and 4 implicit cases (weighing 3 of 3): %+v", rep)
	}
}

// Provenance: an implicit verdict makes only an accepted, implicit case,
// whatever the caller says; an owner verdict never an implicit one.
func TestImplicitProvenanceComesFromTheJournal(t *testing.T) {
	e := newEnv(t, nil)
	e.mustTask("t-imp")
	e.eng.RecordQuality("t-imp", journal.Quality{Verdict: journal.VerdictWrong, Source: "owner-implicit"})
	if err := e.p.AddTaskCase(Case{ID: "a", Class: ClassSkill, Task: "t-imp", Outcome: Rejected}); err == nil {
		t.Fatal("an implicit verdict made a rejected case")
	}
	e.taskCase(ClassSkill, "skills/greet", "hi", Accepted)
	e.mustTask("t-own")
	e.eng.RecordQuality("t-own", journal.Quality{Verdict: journal.VerdictGood, Source: "owner"})
	if err := e.p.AddTaskCase(Case{ID: "b", Class: ClassSkill, Task: "t-own", Outcome: Accepted, Implicit: true}); err != nil {
		t.Fatal(err)
	}
	e.implicitCase(ClassSkill, "skills/greet", "hi")
	e.p.mu.Lock()
	defer e.p.mu.Unlock()
	if e.p.st.Cases["b"].Implicit || !e.p.st.Cases["case-task-"+itoa(e.tasks)].Implicit {
		t.Fatalf("implicit marks: %+v", e.p.st.Cases)
	}
}

// Security B1(b): an implicit case is never an owner-facing example.
func TestAnImplicitCaseIsNeverAnExample(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SecurityAutoStage = true })
	for i := 0; i < 12; i++ {
		e.implicitCase(ClassSkill, "skills/greet", "hi")
	}
	e.p.cfg.Graders = map[Class]Grader{ClassSkill: func(c Case, out []byte) bool {
		return c.Security || string(out) == "hi"
	}}
	ev := e.p.cfg.Evaluator
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, t Tree, pr Probe) ([]byte, error) {
		if _, ok := t["host-image/release"]; ok {
			return []byte("worse"), nil
		}
		return ev.Run(ctx, t, pr)
	})
	e.p.Attach(holdJournal{e.eng})
	r := e.release(release(t, 30, true, map[string][]byte{"host-image/release": []byte("h")}))
	if r.Regressions == 0 {
		t.Fatalf("no regressions: %+v", r)
	}
	if ask, err := e.p.Ask(r.ID); err != nil || strings.Contains(ask, "for example") {
		t.Fatalf("ask: %q %v", ask, err)
	}
}
