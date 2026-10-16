package change

// REQ: OP-7, QCR-1, QCR-2, QCR-3, QCR-5

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/journal"
)

// heldOutGoal journals an owner task that is a goal, records verdict good
// on it and adds its accepted case, input skills/greet with reply
// "hello", on the held-out side of the split. It returns the goal and the
// case.
func (e *env) heldOutGoal() (string, Case) {
	e.t.Helper()
	for i := 0; ; i++ {
		g := fmt.Sprintf("goal-task-%d", i)
		if splitOf(e.p.key, "case-"+g, e.p.cfg.DevPercent) != heldOut {
			continue
		}
		e.goal(g, journal.VerdictGood)
		c := Case{ID: "case-" + g, Class: ClassSkill, Input: []byte("skills/greet"), Expect: []byte("hello"), Outcome: Accepted, Task: g}
		if err := e.p.AddTaskCase(c); err != nil {
			e.t.Fatal(err)
		}
		return g, c
	}
}

// adoptLearnedFrom adopts skills/greet = "hello", learned from goal g, on
// a suite whose other held-out cases it passes as well as the baseline
// does. Only g's own case tells the two apart.
func (e *env) adoptLearnedFrom(g string) Report {
	e.t.Helper()
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep := e.propose(Candidate{Source: Local, Goals: []string{g}, Files: Tree{"skills/greet": []byte("hello")}})
	if rep.State != StateAdopted {
		e.t.Fatalf("setup: %+v", rep)
	}
	return rep
}

// undo is the owner revising goal g's verdict to wrong: the reply the
// case held as accepted is now the one the owner rejected.
func (e *env) undo(g string, c Case) Case {
	e.t.Helper()
	e.verdict(g, journal.VerdictWrong)
	c.Outcome = Rejected
	return c
}

// QCR-1: a later owner outcome on a task supersedes its case in place,
// with no removal and no owner approval; a restated one changes nothing.
func TestRevisedOutcomeSupersedesCase(t *testing.T) {
	e := newEnv(t, nil)
	g, c := e.heldOutGoal()
	e.cases(5, ClassSkill, "skills/greet", "hello")
	n := len(e.p.st.Cases)
	asked := len(e.owner.asked)

	r := e.undo(g, c)
	if err := e.p.AddTaskCase(r); err != nil {
		t.Fatal("revision refused:", err)
	}
	got := e.stored(c.ID)
	if got.Outcome != Rejected || string(got.Expect) != "hello" || got.Task != g || got.Class != ClassSkill {
		t.Fatalf("case not revised in place: %+v", got)
	}
	if len(e.p.st.Cases) != n {
		t.Fatalf("suite changed size: %d -> %d", n, len(e.p.st.Cases))
	}
	if splitOf(e.p.key, splitKey(got), e.p.cfg.DevPercent) != heldOut {
		t.Fatal("the revised case moved to the dev side")
	}
	if len(e.owner.asked) != asked {
		t.Fatal("a revision asked the owner")
	}
	if err := e.p.AddTaskCase(r); !errors.Is(err, ErrDuplicate) || errors.Is(err, ErrConflict) {
		t.Fatalf("restated outcome: %v", err)
	}

	// Corrected, then accepted again: each revision is the latest.
	e.verdict(g, journal.VerdictWrong)
	cr := c
	cr.Outcome, cr.Expect = Corrected, []byte("hello there")
	if err := e.p.AddTaskCase(cr); err != nil {
		t.Fatal("correction refused:", err)
	}
	e.verdict(g, journal.VerdictGood)
	if err := e.p.AddTaskCase(c); err != nil {
		t.Fatal("re-acceptance refused:", err)
	}
	if got := e.stored(c.ID); got.Outcome != Accepted || string(got.Expect) != "hello" {
		t.Fatalf("latest revision not kept: %+v", got)
	}

	// The revision survives a restart.
	e.reopen()
	if got := e.stored(c.ID); got.Outcome != Accepted {
		t.Fatalf("revision lost on reopen: %+v", got)
	}
}

// QCR-2: the re-evaluation a revision triggers scores the revised case,
// so an adoption that regresses only on the revised task is reverted.
func TestRecheckScoresTheRevisedCase(t *testing.T) {
	e := newEnv(t, nil)
	g, c := e.heldOutGoal()
	a := e.adoptLearnedFrom(g)

	if err := e.p.AddTaskCase(e.undo(g, c)); err != nil {
		t.Fatal(err)
	}
	if !e.p.QualityDue() {
		t.Fatal("not due after the revision")
	}
	ids, err := e.p.RecheckQuality(bg)
	if err != nil || len(ids) != 1 || ids[0] != a.ID || e.active(a.ID) || !e.revertedFor(a.ID, WhyRegression) {
		t.Fatalf("adoption regressing on the revised task kept: %v %v", ids, err)
	}
}

// QCR-3: while a due goal's case still holds the verdict before the
// revision, the trigger neither scores on it nor settles; the refresh
// makes it due again at once, and a refresh that never comes holds it for
// one retry wait only.
func TestTriggerWaitsForTheCaseRefresh(t *testing.T) {
	now := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	e := newEnv(t, func(c *Config) { c.Now = func() time.Time { return now } })
	g, c := e.heldOutGoal()
	a := e.adoptLearnedFrom(g)
	r := e.undo(g, c) // the journal has the revision; the case not yet

	if !e.p.QualityDue() {
		t.Fatal("not due after the revision")
	}
	e.ev.reset()
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if len(e.ev.ran) != 0 {
		t.Fatal("scored on the stale case")
	}
	if got := e.adoption(a.ID).GoalVerdicts; len(got) != 1 || got[0].Verdict != journal.VerdictGood {
		t.Fatalf("settled on the stale case: %+v", got)
	}
	if e.p.QualityDue() {
		t.Fatal("due again before the refresh or the retry wait")
	}

	if err := e.p.AddTaskCase(r); err != nil {
		t.Fatal(err)
	}
	if !e.p.QualityDue() {
		t.Fatal("not due at once after the refresh")
	}
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("not reverted after the refresh: %v %v", ids, err)
	}

	// A refresh that never comes (a crash between the verdict and the
	// case) holds the adoption one retry wait, then it is scored on the
	// suite as it stands rather than never.
	e2 := newEnv(t, func(c *Config) { c.Now = func() time.Time { return now } })
	g2, c2 := e2.heldOutGoal()
	b := e2.adoptLearnedFrom(g2)
	e2.undo(g2, c2)
	if _, err := e2.p.RecheckQuality(bg); err != nil || e2.adoption(b.ID).GoalVerdicts[0].Verdict != journal.VerdictGood {
		t.Fatal("not held:", err)
	}
	now = now.Add(QualityRetry)
	if !e2.p.QualityDue() {
		t.Fatal("not due after the retry wait")
	}
	if _, err := e2.p.RecheckQuality(bg); err != nil || e2.adoption(b.ID).GoalVerdicts[0].Verdict != journal.VerdictWrong {
		t.Fatal("held past the retry wait:", err)
	}
}

// QCR-5: a revision cannot overwrite another case: a security case or
// another task's case under the ID, or one with another input or class,
// is a conflict, an outcome the journal's verdict does not back is
// refused, and an implicit acceptance never supersedes an owner's case.
func TestRevisionCannotOverwriteAnotherCase(t *testing.T) {
	e := newEnv(t, nil)
	g, c := e.heldOutGoal()
	other := e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
	sec := Case{ID: "qcr-sec", Input: []byte("x"), Expect: []byte("y")}
	if err := e.p.AddSecurityCase(sec); err != nil {
		t.Fatal(err)
	}
	r := e.undo(g, c)

	for name, mod := range map[string]func(*Case){
		"another task's id": func(d *Case) { d.ID = other.ID },
		"a security id":     func(d *Case) { d.ID = sec.ID },
		"another input":     func(d *Case) { d.Input = []byte("skills/b") },
		"another class":     func(d *Case) { d.Class = ClassProcedure },
	} {
		d := r
		mod(&d)
		if err := e.p.AddTaskCase(d); !errors.Is(err, ErrDuplicate) || !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := e.p.AddTaskCase(c); !errors.Is(err, ErrProvenance) {
		t.Fatalf("outcome the verdict does not back: %v", err)
	}
	if got := e.stored(c.ID); got.Outcome != Accepted {
		t.Fatalf("case changed: %+v", got)
	}
	if got := e.stored(other.ID); got.Task != other.Task || got.Outcome != Accepted {
		t.Fatalf("another task's case changed: %+v", got)
	}
	if got := e.stored(sec.ID); !got.Security {
		t.Fatalf("security case changed: %+v", got)
	}

	e.verdict(g, journal.VerdictGood)
	if _, err := e.eng.RecordQuality(g, journal.Quality{Verdict: journal.VerdictGood, Source: "owner" + ImplicitSuffix}); err != nil {
		t.Fatal(err)
	}
	imp := c
	imp.Expect = []byte("hello again")
	if err := e.p.AddTaskCase(imp); !errors.Is(err, ErrDuplicate) || errors.Is(err, ErrConflict) {
		t.Fatalf("implicit over an owner's case: %v", err)
	}
	if got := e.stored(c.ID); got.Implicit || string(got.Expect) != "hello" {
		t.Fatalf("silence superseded the owner's case: %+v", got)
	}
}
