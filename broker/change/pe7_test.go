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
