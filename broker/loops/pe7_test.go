package loops

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: LOOP-1

type counts map[string]int

func (c counts) KeptPairs(cand change.Candidate) int { return c[string(cand.Files["k"])] }

// PE7 (condition 19): among hypotheses with a kept candidate, the one
// whose candidate has the most kept pairs is offered first; the rest keep
// their mined order behind them.
func TestFinishTheCandidateWithTheMostPairsFirst(t *testing.T) {
	hyps := []Hypothesis{{Key: "a"}, {Key: "b"}, {Key: "c"}, {Key: "d"}}
	built := map[string]keptCandidate{
		"b": {cand: change.Candidate{Files: change.Tree{"k": []byte("b")}}},
		"c": {cand: change.Candidate{Files: change.Tree{"k": []byte("c")}}},
		"d": {cand: change.Candidate{Files: change.Tree{"k": []byte("d")}}},
	}
	got := finishFirst(hyps, built, counts{"b": 3, "c": 9})
	var keys []string
	for _, h := range got {
		keys = append(keys, h.Key)
	}
	if strings.Join(keys, "") != "cbad" {
		t.Fatalf("order %v, want c b a d", keys)
	}
}

// PE7 (condition 17): Loop 1 reuses a kept candidate for its config's
// ResumeFor, 36 h in sleep mode, and change.ResumeFor by default.
func TestLearnResumeForFollowsConfig(t *testing.T) {
	if (&Learn{}).resumeFor() != change.ResumeFor {
		t.Fatal("default")
	}
	if (&Learn{cfg: LearnConfig{ResumeFor: 36 * time.Hour}}).resumeFor() != 36*time.Hour {
		t.Fatal("configured")
	}
	if (&Guard{}).resumeFor() != change.ResumeFor || (&Guard{cfg: GuardConfig{ResumeFor: time.Hour}}).resumeFor() != time.Hour {
		t.Fatal("guard")
	}
}

// countingPipeline counts kept pairs by the candidate's "k" file.
type countingPipeline struct {
	interruptingPipeline
	counts
}

// PE7 (condition 19): Loop 1 orders its hypotheses by its kept
// candidates' pairs where the pipeline counts them, and leaves the mined
// order alone where it does not.
func TestLearnFinishesTheClosestCandidateFirst(t *testing.T) {
	hyps := []Hypothesis{{Key: "a"}, {Key: "b"}}
	built := map[string]keptCandidate{"b": {cand: change.Candidate{Files: change.Tree{"k": []byte("b")}}}}
	l := &Learn{cfg: LearnConfig{Pipeline: &countingPipeline{counts: counts{"b": 2}}}, built: built}
	if got := l.finishFirstLocked(hyps); got[0].Key != "b" {
		t.Fatalf("order %v", got)
	}
	l = &Learn{cfg: LearnConfig{Pipeline: &interruptingPipeline{}}, built: built}
	if got := l.finishFirstLocked(hyps); got[0].Key != "a" {
		t.Fatalf("no counts: order %v", got)
	}
}

// PE7 (condition 17): with ResumeFor 36 h, Loop 1 reuses a kept
// candidate a day later rather than building again, and builds afresh
// past 36 h.
func TestAKeptCandidateLastsTheConfiguredResumeFor(t *testing.T) {
	pl := &interruptingPipeline{}
	b := &builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}
	clk := &clock{t: time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC)}
	l, err := NewLearn(LearnConfig{Pipeline: pl, Journal: &journal.Engine{}, Harvest: &Harvester{Store: &change.MemStore{}}, Builder: b, Now: clk.now, ResumeFor: 36 * time.Hour})
	must(t, err)
	h := hyp("k", "task-a")
	l.propose(context.Background(), h, Evidence{})
	clk.mu.Lock()
	clk.t = clk.t.Add(24 * time.Hour)
	clk.mu.Unlock()
	l.propose(context.Background(), h, Evidence{})
	if n := len(b.got()); n != 1 {
		t.Fatalf("%d builds a day later, want 1", n)
	}
	clk.mu.Lock()
	clk.t = clk.t.Add(37 * time.Hour)
	clk.mu.Unlock()
	l.propose(context.Background(), h, Evidence{})
	if n := len(b.got()); n != 2 {
		t.Fatalf("%d builds past 36 h, want 2", n)
	}
}

// PE7 (condition 17): Loop 2 keeps a preempted fix for its ResumeFor too.
func TestAKeptFixLastsTheConfiguredResumeFor(t *testing.T) {
	b := cleanBox()
	b.pkgs[0].Version = "3.0.13"
	now := t0
	pl := &interruptOnce{Pipeline: newPipe(t), n: 1}
	fx := &fixer{cand: change.Candidate{Files: change.Tree{"config/facts.json": facts("3.0.14")}}}
	g, err := NewGuard(GuardConfig{Box: b.Box(), Pipeline: pl, Store: &change.MemStore{}, Contain: &contain{},
		FixturesLive: true, Fixer: fx, Notify: func(string, bool) {}, Now: func() time.Time { return now }, ResumeFor: 36 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	g.Pass(context.Background()) // built, preempted, kept
	now = now.Add(24 * time.Hour)
	g.Pass(context.Background())
	if fx.calls != 1 {
		t.Fatalf("%d fixer calls a day later, want 1: the kept fix was not reused", fx.calls)
	}
}

// pairsPipeline is a real pipeline whose kept pairs are counted by the
// candidate's "k" file.
type pairsPipeline struct {
	*change.Pipeline
	counts
}

func (p pairsPipeline) KeptPairs(c change.Candidate) int { return p.counts.KeptPairs(c) }

// PE7 (condition 19, L3 MUST-1 on #153): Next offers first the hypothesis
// whose kept candidate has the most pairs, not the first one mined.
func TestNextFinishesTheClosestCandidateFirst(t *testing.T) {
	r := newRig(t)
	h := r.harvester()
	for i := range 8 {
		r.corrected(h, i)
	}
	r.failing("x", "owner:mX", "refund")
	r.failing("y", "owner:mY", "pay")
	b := &builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}
	l, err := NewLearn(LearnConfig{Pipeline: pairsPipeline{r.p, counts{"kept": 4}}, Journal: r.eng, Harvest: h, Builder: b, MinHeldOut: 1})
	must(t, err)
	ev, err := h.Evidence()
	must(t, err)
	mined := l.mine(ev)
	if len(mined) < 2 {
		t.Fatalf("mined %d hypotheses, want 2 or more", len(mined))
	}
	last := mined[len(mined)-1].Key
	l.built[last] = keptCandidate{cand: change.Candidate{Files: change.Tree{"k": []byte("kept")}}}
	job, ok := l.Next(context.Background(), true)
	if !ok || job.Name != "candidate" {
		t.Fatalf("no candidate job: %v %v", job.Name, ok)
	}
	job.Run(context.Background())
	if got := b.got(); len(got) != 1 || got[0].Hypothesis.Key != last {
		t.Fatalf("offered %v first, want %s", got, last)
	}
}
