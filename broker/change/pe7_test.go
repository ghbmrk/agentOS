package change

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// REQ: LOOP-1, CHG-1

// PE7 (condition 17): a pipeline in sleep mode keeps a preempted
// evaluation's pairs for Config.ResumeFor (36 h there), so a candidate cut
// at the end of one night resumes the next.
func TestResumeForFollowsConfig(t *testing.T) {
	now := time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e, pe := newPreemptEnv(t, func(c *Config) { c.Now = clock; c.MinHeldOut = 100; c.ResumeFor = 36 * time.Hour })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	kept := e.p.keptSides()
	if kept == 0 {
		t.Fatal("nothing kept")
	}
	mu.Lock()
	now = now.Add(19 * time.Hour) // the next night
	mu.Unlock()
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total := rep.HeldOut + rep.Security + rep.NotEvaluated
	if pe.runs() != 2*total-kept {
		t.Fatalf("%d probes, want %d: kept pairs not reused the next night", pe.runs(), 2*total-kept)
	}
}

// PE7 (condition 18): when the active tree changes (an adoption, an UNDO,
// a reload), pairs kept against the old base are discarded at once, not
// left to expire.
func TestKeptPairsGoWhenTheBaseChanges(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if e.p.keptSides() == 0 {
		t.Fatal("nothing kept")
	}
	pe.arm(0)
	e.owner.approve = true
	if r, err := e.p.Propose(context.Background(), Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}}); err != nil || r.State != StateAdopted {
		t.Fatalf("changing the base: %+v %v", r, err)
	}
	if n := e.p.keptSides(); n != 0 {
		t.Fatalf("%d sides kept against the old base", n)
	}
}

// PE7 (condition 19): KeptPairs counts one candidate's kept pairs on the
// current base, so Loop 1 can finish the candidate with the most first.
func TestKeptPairsPerCandidate(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if n := e.p.KeptPairs(greet); n == 0 || n != e.p.keptPairs() {
		t.Fatalf("greet: %d kept pairs, pipeline holds %d", n, e.p.keptPairs())
	}
	if n := e.p.KeptPairs(Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hi there")}}); n != 0 {
		t.Fatalf("another candidate: %d", n)
	}
}

// PE7 (condition 18): an UNDO that changes the active tree discards the
// pairs kept against the tree it replaced too.
func TestKeptPairsGoOnUndo(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	pe.arm(0)
	e.owner.approve = true
	a, err := e.p.Propose(context.Background(), Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}})
	if err != nil || a.State != StateAdopted {
		t.Fatalf("setup: %+v %v", a, err)
	}
	e.owner.approve = false
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if e.p.keptSides() == 0 {
		t.Fatal("nothing kept")
	}
	if err := e.p.Revert(context.Background(), a.ID, OriginOwner); err != nil {
		t.Fatal(err)
	}
	if n := e.p.keptSides(); n != 0 {
		t.Fatalf("%d sides kept against the undone tree", n)
	}
}

// PE7 (condition 18): reloading the saved state (after a failed save)
// keeps only pairs on the reloaded active tree.
func TestKeptPairsGoOnReload(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	e.p.mu.Lock()
	for k, r := range e.p.kept {
		r.base = "another tree"
		e.p.kept[k] = r
	}
	err := e.p.reloadLocked()
	e.p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if n := e.p.keptSides(); n != 0 {
		t.Fatalf("%d sides kept against a tree that is not the reloaded one", n)
	}
}

// PE7 (condition 18): a reload that leaves the active tree as it was
// keeps the pairs evaluated against it.
func TestKeptPairsStayOnTheirOwnBase(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	n := e.p.keptSides()
	e.p.mu.Lock()
	err := e.p.reloadLocked()
	e.p.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := e.p.keptSides(); got != n || n == 0 {
		t.Fatalf("%d sides kept after a reload of the same tree, had %d", got, n)
	}
}

// PE7 (condition 19, L3 MUST-2 on #153): a parked candidate counts no
// kept pairs, so Loop 1 does not put it ahead of every other hypothesis
// while it is refused outside idle passes.
func TestAParkedCandidateCountsNoKeptPairs(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if e.p.KeptPairs(greet) == 0 {
		t.Fatal("nothing kept")
	}
	// Parked: MaxExempt cuts for the owner (pe5_test's park drives them
	// through evaluations).
	e.p.mu.Lock()
	for _, r := range e.p.kept {
		for range MaxExempt {
			e.p.exemptLocked(r.cand)
		}
		break
	}
	e.p.mu.Unlock()
	if n := e.p.KeptPairs(greet); n != 0 {
		t.Fatalf("a parked candidate counts %d kept pairs", n)
	}
}

// PE7 (condition 18, L3 SHOULD on #153): pairs finished against a base
// the active tree left during the evaluation are not kept.
func TestPairsOfABaseReplacedMidEvaluationAreNotKept(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	ctx := pe.arm(0)
	n := 0
	pe.mu.Lock()
	pe.cut = func(context.Context, Tree, Probe) bool {
		if n++; n < 6 {
			return false
		}
		e.p.mu.Lock()
		e.p.st.Active = Tree{"skills/greet": []byte("hi"), "procedures/file": []byte("v2")}
		e.p.mu.Unlock()
		return true
	}
	pe.mu.Unlock()
	if _, err := e.p.Propose(ctx, greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if n := e.p.keptSides(); n != 0 {
		t.Fatalf("%d sides kept against a base replaced mid-evaluation", n)
	}
}

// PE7 (L3 on #153): a kept pair lasts exactly its window: the 12 h
// default, or Config.ResumeFor; a nanosecond past it, it is gone.
func TestKeptPairsLastExactlyTheirWindow(t *testing.T) {
	now := time.Date(2026, 10, 5, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		resumeFor, after time.Duration
		kept             bool
	}{
		{0, 12 * time.Hour, true},
		{0, 12*time.Hour + time.Nanosecond, false},
		{36 * time.Hour, 36 * time.Hour, true},
		{36 * time.Hour, 36*time.Hour + time.Nanosecond, false},
	} {
		at := now
		p := &Pipeline{cfg: Config{Now: func() time.Time { return at }, ResumeFor: tc.resumeFor}, kept: map[string]pairResult{}}
		p.keepLocked("pair", pairResult{baseDone: true})
		at = now.Add(tc.after)
		if _, ok := p.keptLocked("pair"); ok != tc.kept {
			t.Errorf("ResumeFor %v, %v later: kept %v", tc.resumeFor, tc.after, ok)
		}
	}
}
