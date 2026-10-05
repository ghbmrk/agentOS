package loops

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// REQ: CAP-3, CHG-1

// goalHyp is hyp with each task's intent stamped with goal.
func goalHyp(key, goal string, tasks ...string) Hypothesis {
	h := hyp(key, tasks...)
	for i := range h.Evidence {
		h.Evidence[i].Intent.GoalID = goal
	}
	return h
}

// goalClaimer is a builder that claims goals of its own.
type goalClaimer struct{ builder }

func (g *goalClaimer) Build(ctx context.Context, br Brief) (change.Candidate, error) {
	c, err := g.builder.Build(ctx, br)
	c.Goals = []string{"owner:claimed"}
	return c, err
}

// W3-tasks part 2 (security C1 on #120): Loop 1 marks each candidate, in
// broker code, with the goals of every owner task its builder read: the
// hypothesis's evidence intents and the dev cases. What the builder
// claims is ignored, and an intent with no goal adds none.
func TestLoop1MarksTheGoalsItsBuilderRead(t *testing.T) {
	pl := &interruptingPipeline{}
	b := &goalClaimer{builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}}
	l, err := NewLearn(LearnConfig{Pipeline: pl, Journal: &journal.Engine{}, Harvest: &Harvester{Store: &change.MemStore{}}, Builder: b})
	must(t, err)
	h := goalHyp("k", "owner:g2", "task-a", "task-b")
	h.Evidence = append(h.Evidence, journal.Status{Intent: journal.Intent{ID: "task-c", Label: "private"}})
	dev := []change.Case{{ID: "d1", Goal: "owner:g1"}, {ID: "d2", Goal: "owner:g2"}, {ID: "d3"}}
	l.propose(context.Background(), h, Evidence{Dev: dev})
	if len(pl.got) != 1 || !slices.Equal(pl.got[0].Goals, []string{"owner:g1", "owner:g2"}) {
		t.Fatalf("proposed goals: %v", pl.got)
	}
}

// Forgetting a goal drops every candidate Loop 1 kept that was built from
// it, so the next offer builds afresh (from evidence without the goal, as
// the daemon's tombstone has it); other goals' kept candidates stay.
func TestLearnForgetsKeptCandidatesWithTheirGoal(t *testing.T) {
	l, _, b, _ := newKeepRig(t)
	h1, h2 := goalHyp("k1", "owner:g1", "task-a"), goalHyp("k2", "owner:g2", "task-b")
	l.propose(context.Background(), h1, Evidence{})
	l.propose(context.Background(), h2, Evidence{})
	l.ForgetGoal("owner:g1")
	l.propose(context.Background(), h1, Evidence{})
	l.propose(context.Background(), h2, Evidence{})
	if n := len(b.got()); n != 3 {
		t.Fatalf("%d builds, want 3: only the forgotten goal's candidate is built again", n)
	}
}

// forgettingPipeline forgets a goal in Loop 1 while the candidate is
// being evaluated, then reports the evaluation preempted.
type forgettingPipeline struct {
	interruptingPipeline
	l *Learn
}

func (p *forgettingPipeline) Propose(ctx context.Context, c change.Candidate) (change.Report, error) {
	p.l.ForgetGoal("owner:g1")
	return p.interruptingPipeline.Propose(ctx, c)
}

// A candidate preempted while its goal was being forgotten is not kept.
func TestLearnKeepsNoCandidateForgottenInFlight(t *testing.T) {
	pl := &forgettingPipeline{}
	b := &builder{files: map[string][]byte{"procedures/mail": []byte("v2")}}
	l, err := NewLearn(LearnConfig{Pipeline: pl, Journal: &journal.Engine{}, Harvest: &Harvester{Store: &change.MemStore{}}, Builder: b,
		Now: func() time.Time { return time.Date(2026, 10, 5, 9, 0, 0, 0, time.UTC) }})
	must(t, err)
	pl.l = l
	h := goalHyp("k", "owner:g1", "task-a")
	l.propose(context.Background(), h, Evidence{})
	l.propose(context.Background(), h, Evidence{})
	if n := len(b.got()); n != 2 {
		t.Fatalf("%d builds, want 2: a candidate forgotten in flight was kept", n)
	}
}
