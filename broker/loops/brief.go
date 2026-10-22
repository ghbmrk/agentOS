package loops

import (
	"context"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// The builder contract below outlived Loop 1, which mined the journal for
// hypotheses and was deleted with the Harvester (#2786 part a, HLD-4 "off
// until it beats the baseline"). loopbuild and e2e still build against it;
// it goes with loopbuild's own port (#2787).

// Signal is what in the journal a hypothesis comes from (LOOP-4).
type Signal string

const (
	SignalFailure    Signal = "failure"    // an effect that did not happen or is unknown
	SignalCorrection Signal = "correction" // the owner's wrong verdict
	SignalSlow       Signal = "slow"       // a step that took long to complete
	SignalExpensive  Signal = "expensive"  // a task that cost far more than usual
	SignalRepeat     Signal = "repeat"     // the same trajectory across tasks
)

// Hypothesis is one thing a builder might improve (LOOP-4). It names
// journal identifiers (accounts and actions) and the tasks behind it,
// never a held-out task.
type Hypothesis struct {
	Signal Signal
	Class  change.Class
	// Key identifies the hypothesis: the signal and the actions involved.
	Key string
	// Tasks are the task keys behind it (TaskKey).
	Tasks []string
	// Evidence is the journal record of those tasks.
	Evidence []journal.Status
}

// Brief is everything a builder gets: the hypothesis and the dev split.
// It carries no held-out case, no evaluation count, and no evaluation
// model-call record (CHG-1; replay K3; change C14 (d)).
type Brief struct {
	Hypothesis Hypothesis
	Dev        []change.Case
}

// Builder turns a hypothesis into a candidate, typically by running a
// model-backed agent in an experiment machine whose model calls go through
// the spare budget meter. Whatever it returns is only a proposal.
type Builder interface {
	Build(ctx context.Context, b Brief) (change.Candidate, error)
}

// Private is a builder whose candidates are never public, whatever the
// REV-5 labels of their inputs: it builds in a private machine with
// private model egress (loopbuild; security C-3c-4, C-3c-6).
type Private interface {
	Private(b Brief) bool
}

// TaskKey is the task an intent belongs to: its goal, or, for intents
// with none, the origin that ran it (replay ASSUMPTIONS R4).
func TaskKey(in journal.Intent) string {
	if in.GoalID != "" {
		return "goal:" + in.GoalID
	}
	return "origin:" + in.Origin
}
