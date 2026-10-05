package change

// REQ: CHG-1, LOOP-1, RES-1

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// preempting wraps the env's evaluator. It cancels the evaluation's
// context during call number at (counting from 1) and then still returns
// that call's answer, as a run that finished just as the scheduler
// preempted it. It records which sides of which cases completed before the
// cancel, by the case's task (or input, for a fixture) and the tree.
type preempting struct {
	e      *evaluator
	mu     sync.Mutex
	at     int
	calls  int
	cancel context.CancelFunc
	// cut, if it returns true for a run, cancels the evaluation during
	// that run (a candidate forcing a preemption).
	cut  func(context.Context, Tree, Probe) bool
	done map[string]int // case -> sides completed before the cancel (bit 1 base, bit 2 candidate)
}

func (p *preempting) Run(ctx context.Context, t Tree, pr Probe) ([]byte, error) {
	key, ok := p.e.p.ProbeTask(pr.ID)
	if !ok {
		key = string(pr.Input)
	}
	side := 1
	if string(t["skills/greet"]) == "hello" {
		side = 2
	}
	out, err := p.e.Run(ctx, t, pr)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if (p.calls == p.at || p.cut != nil && p.cut(ctx, t, pr)) && p.cancel != nil {
		p.cancel()
	}
	if ctx.Err() == nil {
		p.done[key] |= side
	}
	return out, err
}

func (p *preempting) pairs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.done {
		if s == 3 {
			n++
		}
	}
	return n
}

// sides counts the sides that completed before the cancel.
func (p *preempting) sides() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, s := range p.done {
		n += s&1 + s>>1
	}
	return n
}

func (p *preempting) arm(at int) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	p.mu.Lock()
	p.at, p.calls, p.cancel, p.done, p.cut = at, 0, cancel, map[string]int{}, nil
	p.mu.Unlock()
	return ctx
}

func (p *preempting) runs() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func newPreemptEnv(t *testing.T, mod func(*Config)) (*env, *preempting) {
	pe := &preempting{done: map[string]int{}}
	e := newEnv(t, func(c *Config) {
		if mod != nil {
			mod(c)
		}
		pe.e = c.Evaluator.(*evaluator)
		c.Evaluator = pe
	})
	return e, pe
}

// lateArm arms pe to preempt on the last-but-one probe of an evaluation
// of greet, so at least one pair has completed by then.
func lateArm(e *env, pe *preempting) context.Context {
	e.p.mu.Lock()
	f := e.p.freezeLocked([]Class{ClassSkill})
	e.p.mu.Unlock()
	return pe.arm(2*(len(f.heldOut)+len(f.security)) - 1)
}

var greet = Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello")}}

// LOOP-1, RES-1: an evaluation preempted part way is not a verdict. No
// proposal is reported, nothing is submitted, and nothing changes; the
// caller sees ErrInterrupted wrapping the context's error.
func TestPreemptedEvaluationIsNotAVerdict(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	rep, err := e.p.Propose(pe.arm(5), greet)
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("preempted evaluation: %+v %v", rep, err)
	}
	if rep.State != "" || rep.HeldOut != 0 || rep.Passed != 0 {
		t.Fatalf("preempted evaluation reported a result: %+v", rep)
	}
	if pe.runs() != 5 {
		t.Fatalf("evaluation went on after preemption: %d runs", pe.runs())
	}
	if string(e.p.Files("skills")["skills/greet"]) != "hi" || len(e.p.Adoptions()) != 0 || len(e.owner.asked) != 0 {
		t.Fatal("a preempted evaluation changed something")
	}
	if _, err := e.eng.Get(adoptID(rep.ID)); err == nil && rep.ID != "" {
		t.Fatal("a preempted evaluation submitted an adoption intent")
	}
	if d := e.p.Digest(); len(d) != 0 {
		t.Fatalf("a preempted evaluation reached the digest: %q", d)
	}
}

// CHG-1, LOOP-1: proposing the same candidate on the same base again runs
// only the cases without a completed pair, and the result is what an
// uninterrupted evaluation gives. A run that returned after the
// preemption is not kept.
func TestResumeRunsOnlyRemainingPairs(t *testing.T) {
	// The owner says no, so the base stays and the trees can be evaluated
	// again uninterrupted for comparison.
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100 })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	kept := pe.sides()
	if pe.pairs() == 0 || e.p.keptPairs() != pe.pairs() || e.p.keptSides() != kept {
		t.Fatalf("completed before the preemption: %d pairs, %d sides; kept %d pairs, %d sides", pe.pairs(), kept, e.p.keptPairs(), e.p.keptSides())
	}
	pe.arm(0)
	got, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total := got.HeldOut + got.Security + got.NotEvaluated
	if pe.runs() != 2*total-kept {
		t.Fatalf("resumed evaluation ran %d probes, want %d (%d of %d sides kept)", pe.runs(), 2*total-kept, kept, 2*total)
	}
	want, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Score != want.Score || got.State != want.State || got.Basis != want.Basis || got.Reason != want.Reason {
		t.Fatalf("resumed result %+v, uninterrupted %+v", got, want)
	}
}

// CHG-1: kept pairs are only for finishing that evaluation. Once it
// completes they are gone, so the next evaluation of the same trees (a
// Recheck, say) runs every case afresh.
func TestFinishedEvaluationKeepsNoPairs(t *testing.T) {
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100 }) // goes to the owner, who says no
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	pe.arm(0)
	first, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total := first.HeldOut + first.Security + first.NotEvaluated
	pe.arm(0)
	if _, err := e.p.Propose(context.Background(), greet); err != nil {
		t.Fatal(err)
	}
	if pe.runs() != 2*total {
		t.Fatalf("evaluation after a finished one ran %d probes, want %d", pe.runs(), 2*total)
	}
	if n := e.p.keptPairs(); n != 0 {
		t.Fatalf("%d pairs kept after the evaluation finished", n)
	}
}

// CHG-1: a result is kept for its exact trees, case, and evaluator. Another base or
// another candidate runs everything; a case added since runs on both
// sides, and the kept pairs still count.
func TestKeptPairsAreBoundToTreesAndCases(t *testing.T) {
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100 })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	kept := pe.sides()

	other := Candidate{Source: Local, Files: Tree{"skills/greet": []byte("hello"), "skills/extra": []byte("x")}}
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), other)
	if err != nil {
		t.Fatal(err)
	}
	total := rep.HeldOut + rep.Security + rep.NotEvaluated
	if pe.runs() != 2*total {
		t.Fatalf("another candidate reused pairs: %d probes, want %d", pe.runs(), 2*total)
	}

	e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
	e.taskCase(ClassSkill, "skills/greet", "hello", Accepted)
	pe.arm(0)
	rep, err = e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total = rep.HeldOut + rep.Security + rep.NotEvaluated
	if pe.runs() != 2*total-kept {
		t.Fatalf("with new cases: %d probes, want %d", pe.runs(), 2*total-kept)
	}
}

// CHG-1: a base that changed since the preemption runs everything.
func TestKeptPairsDieWithTheBase(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	pe.arm(0)
	e.owner.approve = true
	if r, err := e.p.Propose(context.Background(), Candidate{Source: Local, Files: Tree{"config/a": []byte("1")}}); err != nil || r.State != StateAdopted {
		t.Fatalf("changing the base: %+v %v", r, err)
	}
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total := rep.HeldOut + rep.Security + rep.NotEvaluated
	if pe.runs() != 2*total {
		t.Fatalf("pairs from an old base were reused: %d probes, want %d", pe.runs(), 2*total)
	}
}

// LOOP-1: kept pairs expire, and there is a cap on how many are kept, so
// an evaluation that never resumes holds nothing for long.
func TestKeptPairsExpireAndAreBounded(t *testing.T) {
	now := time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	e, pe := newPreemptEnv(t, func(c *Config) { c.Now = clock; c.MinHeldOut = 100 })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	if e.p.keptPairs() == 0 {
		t.Fatal("nothing kept")
	}
	mu.Lock()
	now = now.Add(ResumeFor + time.Second)
	mu.Unlock()
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	total := rep.HeldOut + rep.Security + rep.NotEvaluated
	if pe.runs() != 2*total {
		t.Fatalf("expired pairs were reused: %d probes, want %d", pe.runs(), 2*total)
	}

	e.p.mu.Lock()
	for i := 0; i < MaxKeptPairs+50; i++ {
		e.p.keepLocked(resumeKey("", Tree{}, Tree{"a": []byte(itoa(i))}, Case{ID: "x"}), pairResult{})
	}
	n := len(e.p.kept)
	e.p.mu.Unlock()
	if n > MaxKeptPairs {
		t.Fatalf("%d pairs kept, cap %d", n, MaxKeptPairs)
	}
}

// ADP-4, LOOP-1: a Recheck preempted part way blames nothing, reverts
// nothing, and is not an outage.
func TestPreemptedRecheckBlamesNothing(t *testing.T) {
	e, pe := newPreemptEnv(t, nil)
	e.cases(30, ClassSkill, "skills/greet", "hello")
	pe.arm(0)
	good, err := e.p.Propose(context.Background(), greet)
	if err != nil || good.State != StateAdopted {
		t.Fatalf("%+v %v", good, err)
	}
	// The suite now says the adoption regresses.
	for i := 0; i < 40; i++ {
		e.taskCase(ClassSkill, "skills/greet", "hi", Accepted)
	}
	out, err := e.p.Recheck(pe.arm(3))
	if !errors.Is(err, ErrInterrupted) || len(out) != 0 {
		t.Fatalf("preempted recheck: %v %v", out, err)
	}
	if string(e.p.Files("skills")["skills/greet"]) != "hello" {
		t.Fatal("a preempted recheck reverted")
	}
	e.p.mu.Lock()
	outages := e.p.st.Outages
	e.p.mu.Unlock()
	if outages != 0 {
		t.Fatalf("a preempted recheck counted as an outage: %d", outages)
	}
	pe.arm(0)
	out, err = e.p.Recheck(context.Background())
	if err != nil || len(out) != 1 {
		t.Fatalf("resumed recheck: %v %v", out, err)
	}
}

// CHG-1, LOOP-10 (security F1 on #103): a candidate that can force a
// preemption whenever a case is going badly cannot re-roll that case
// without limit. After MaxInterruptions cut-short runs of its side of one
// case, the candidate fails that case without another run.
func TestForcedPreemptionsCannotReRollACase(t *testing.T) {
	e, pe := newPreemptEnv(t, func(c *Config) { c.MinHeldOut = 100 })
	e.cases(12, ClassSkill, "skills/greet", "hello")
	ranCand := 0
	thrash := func(ctx context.Context, t Tree, pr Probe) bool {
		if string(pr.Input) == exfilProbe && string(t["skills/greet"]) == "hello" {
			ranCand++
			return true
		}
		return false
	}
	for i := 0; i < MaxInterruptions; i++ {
		ctx := pe.arm(0)
		pe.mu.Lock()
		pe.cut = thrash
		pe.mu.Unlock()
		if _, err := e.p.Propose(ctx, greet); !errors.Is(err, ErrInterrupted) {
			t.Fatalf("pass %d: %v", i, err)
		}
	}
	if ranCand != MaxInterruptions {
		t.Fatalf("candidate side of the fixture ran %d times, want %d", ranCand, MaxInterruptions)
	}
	ctx := pe.arm(0)
	pe.mu.Lock()
	pe.cut = thrash
	pe.mu.Unlock()
	rep, err := e.p.Propose(ctx, greet)
	if err != nil {
		t.Fatalf("third pass was cut again: %v", err)
	}
	if ranCand != MaxInterruptions {
		t.Fatal("the candidate side ran again after its limit")
	}
	if rep.State != StateRejected || rep.SecurityPassed == rep.Security {
		t.Fatalf("a candidate that forced preemptions passed: %+v", rep)
	}
}

// R1 on #103: kept results resume only under the same evaluator identity.
func TestKeptResultsNeedTheSameEvaluator(t *testing.T) {
	var mu sync.Mutex
	id := "v1"
	e, pe := newPreemptEnv(t, func(c *Config) {
		c.MinHeldOut = 100
		c.EvaluatorID = func() string { mu.Lock(); defer mu.Unlock(); return id }
	})
	e.cases(12, ClassSkill, "skills/greet", "hello")
	if _, err := e.p.Propose(lateArm(e, pe), greet); !errors.Is(err, ErrInterrupted) {
		t.Fatal(err)
	}
	mu.Lock()
	id = "v2"
	mu.Unlock()
	pe.arm(0)
	rep, err := e.p.Propose(context.Background(), greet)
	if err != nil {
		t.Fatal(err)
	}
	if total := rep.HeldOut + rep.Security + rep.NotEvaluated; pe.runs() != 2*total {
		t.Fatalf("another evaluator reused kept results: %d probes, want %d", pe.runs(), 2*total)
	}
}
