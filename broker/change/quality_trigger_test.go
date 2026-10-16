package change

// REQ: OP-7, SM-AQ-1, SM-AQ-2, SM-AQ-3, SM-AQ-4

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/update"
)

// goal journals an owner task to serve as a goal and records verdict v on
// it.
func (e *env) goal(id string, v journal.Verdict) {
	e.t.Helper()
	e.mustTask(id)
	e.verdict(id, v)
}

func (e *env) verdict(id string, v journal.Verdict) {
	e.t.Helper()
	if _, err := e.eng.RecordQuality(id, journal.Quality{Verdict: v, Source: "owner"}); err != nil {
		e.t.Fatal(err)
	}
}

// revertedFor reports a succeeded revert intent of adoption id for why.
func (e *env) revertedFor(id, why string) bool {
	for _, st := range e.eng.List() {
		if strings.HasPrefix(st.Intent.ID, "chg:"+id+":revert:") && strings.HasSuffix(st.Intent.ID, ":"+why) &&
			st.State == journal.Succeeded {
			return true
		}
	}
	return false
}

func (e *env) active(id string) bool {
	for _, a := range e.p.Adoptions() {
		if a.ID == id {
			return a.Reverted == ""
		}
	}
	return false
}

// twoAdoptions adopts A, learned from goals g1 and g3, and B, learned from
// g2 and g3, then adds held-out cases on which both now regress: only
// the trigger decides which of them is re-evaluated.
func twoAdoptions(t *testing.T) (*env, Report, Report) {
	e := newEnv(t, func(c *Config) { c.Initial["skills/b"] = []byte("b0") })
	for _, g := range []string{"g1", "g2", "g3"} {
		e.goal(g, journal.VerdictGood)
	}
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"g1", "g3"}, Files: Tree{"skills/greet": []byte("hello")}})
	b := e.propose(Candidate{Source: Local, Goals: []string{"g2", "g3"}, Files: Tree{"skills/b": []byte("b1")}})
	if a.State != StateAdopted || b.State != StateAdopted {
		t.Fatalf("setup: %+v %+v", a, b)
	}
	e.cases(20, ClassSkill, "skills/greet", "hi")
	e.cases(20, ClassSkill, "skills/b", "b0")
	return e, a, b
}

// SM-AQ-1: a verdict change on a goal re-evaluates exactly the active
// adoptions learned from it.
func TestVerdictChangeRechecksOnlyAffectedAdoptions(t *testing.T) {
	e, a, b := twoAdoptions(t)
	if e.p.QualityDue() {
		t.Fatal("due with no verdict changed")
	}
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 0 {
		t.Fatal("re-evaluated with no verdict changed:", ids, err)
	}

	e.ev.reset()
	e.verdict("g1", journal.VerdictWrong)
	if !e.p.QualityDue() {
		t.Fatal("not due after g1 changed")
	}
	ids, err := e.p.RecheckQuality(bg)
	if err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("g1 changed: reverted %v, %v; want only %s", ids, err, a.ID)
	}
	if !e.active(b.ID) {
		t.Fatal("B, not learned from g1, was reverted")
	}
	if e.p.QualityDue() {
		t.Fatal("still due after the re-evaluation")
	}

	// The shared goal reaches B, the one still active.
	e.verdict("g3", journal.VerdictWrong)
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 1 || ids[0] != b.ID {
		t.Fatalf("g3 changed: reverted %v, %v; want %s", ids, err, b.ID)
	}
}

// SM-AQ-1: an affected adoption that still qualifies is kept, and the
// verdict it was re-evaluated on is remembered, so it is not due again.
func TestVerdictChangeKeepsAdoptionThatStillQualifies(t *testing.T) {
	e := newEnv(t, nil)
	e.goal("g1", journal.VerdictGood)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	a := e.propose(Candidate{Source: Local, Goals: []string{"g1"}, Files: Tree{"skills/greet": []byte("hello")}})
	if a.State != StateAdopted {
		t.Fatal(a)
	}
	e.ev.reset()
	e.verdict("g1", journal.VerdictWrong)
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if len(e.ev.ran) == 0 {
		t.Fatal("the affected adoption was not re-evaluated")
	}
	if !e.active(a.ID) || e.p.QualityDue() {
		t.Fatal("kept adoption lost or still due")
	}
}

// SM-AQ-2: the regressed adoption is reverted through the normal revert
// intent, why regression.
func TestRegressedAdoptionReverted(t *testing.T) {
	e, a, _ := twoAdoptions(t)
	e.verdict("g1", journal.VerdictWrong)
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	if !e.revertedFor(a.ID, WhyRegression) {
		t.Fatal("no journaled regression revert of A")
	}
	if got := string(e.p.Files("skills")["skills/greet"]); got != "hi" {
		t.Fatalf("tree after the revert: %q", got)
	}
}

// SM-AQ-2: a protected adoption is not reverted; its regression is put to
// the owner as a Concern. A protected adoption is an image, which Propose
// never gives goals (learnedClass), so the goal is set on it here to
// exercise the shared per-adoption path.
func TestProtectedAdoptionRaisesConcern(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.SecurityAutoStage = true
		c.Initial["host-image/release"] = []byte(update.Digest([]byte("old")))
	})
	e.goal("g1", journal.VerdictGood)
	e.cases(12, ClassSkill, "skills/greet", "hi")
	e.owner.approve = true
	ev := e.p.cfg.Evaluator
	worse := false
	e.p.cfg.Evaluator = evalFunc(func(ctx context.Context, tr Tree, pr Probe) ([]byte, error) {
		if string(tr["host-image/release"]) == update.Digest([]byte("a")) && worse && string(pr.Input) != exfilProbe {
			return []byte("worse"), nil
		}
		return ev.Run(ctx, tr, pr)
	})
	sec := e.release(release(t, 50, true, map[string][]byte{"host-image/release": []byte("a")}))
	if sec.State != StateAdopted || sec.Basis != BasisSecurity {
		t.Fatal(sec)
	}
	e.p.mu.Lock()
	ad := e.p.adoptionLocked(sec.ID)
	ad.Goals, ad.GoalVerdicts = []string{"g1"}, []GoalVerdict{{Goal: "g1", Verdict: journal.VerdictGood}}
	e.p.mu.Unlock()
	e.p.Digest()

	worse = true
	e.verdict("g1", journal.VerdictWrong)
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 0 {
		t.Fatal("reverted a protected image:", ids, err)
	}
	if !e.active(sec.ID) || e.revertedFor(sec.ID, WhyRegression) {
		t.Fatal("protected image undone")
	}
	var concern string
	for _, x := range e.p.Adoptions() {
		if x.ID == sec.ID {
			concern = x.Concern
		}
	}
	if concern != WhyRegression {
		t.Fatalf("concern %q, want %q", concern, WhyRegression)
	}
	if e.p.QualityDue() {
		t.Fatal("still due once the owner was asked")
	}
}

// SM-AQ-3: a record that restates the verdict triggers nothing.
func TestSameVerdictIsNoTrigger(t *testing.T) {
	e, a, b := twoAdoptions(t)
	e.verdict("g1", journal.VerdictGood)
	e.verdict("g3", journal.VerdictGood)
	if e.p.QualityDue() {
		t.Fatal("due after a restated verdict")
	}
	e.ev.reset()
	if ids, err := e.p.RecheckQuality(bg); err != nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if len(e.ev.ran) != 0 {
		t.Fatal("re-evaluated on a restated verdict")
	}
	if !e.active(a.ID) || !e.active(b.ID) {
		t.Fatal("an adoption was reverted")
	}
}

// SM-AQ-4: a revision recorded while the broker was down is applied at
// boot: the remembered verdicts survive the restart and the journal's
// latest is compared with them after replay.
func TestRevisionWhileDownIsAppliedAtBoot(t *testing.T) {
	e, a, b := twoAdoptions(t)
	// The broker is down: only the journal takes the owner's revision.
	e.verdict("g1", journal.VerdictWrong)

	cfg := e.p.cfg
	cfg.Rand = bytes.NewReader(testSplitKey)
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.open(p)
	if !e.p.QualityDue() {
		t.Fatal("the revision made while down is not due at boot")
	}
	ids, err := e.p.RecheckQuality(bg)
	if err != nil || len(ids) != 1 || ids[0] != a.ID {
		t.Fatalf("reverted %v, %v; want only %s", ids, err, a.ID)
	}
	if !e.active(b.ID) || !e.revertedFor(a.ID, WhyRegression) {
		t.Fatal("wrong adoption reverted after the restart")
	}

	// And what was re-evaluated stays settled across the next restart.
	cfg.Rand = bytes.NewReader(testSplitKey)
	if p, err = New(cfg); err != nil {
		t.Fatal(err)
	}
	e.open(p)
	if e.p.QualityDue() {
		t.Fatal("due again after a second restart")
	}
}
