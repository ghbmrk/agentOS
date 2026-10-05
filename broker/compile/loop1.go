package compile

import (
	"context"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/loops"
)

// LoopBuilder is the compiler as Loop 1's builder for repeated
// trajectories (loops.SignalRepeat): it compiles a skill from the brief's
// evidence only, which Loop 1 keeps free of held-out tasks (CHG-1). Loop 1
// sets the candidate's source, origin, and public mark itself.
type LoopBuilder struct{ C *Compiler }

func (b LoopBuilder) Build(_ context.Context, br loops.Brief) (change.Candidate, error) {
	return b.C.BuildSkill(br.Hypothesis.Evidence)
}

var _ loops.Builder = LoopBuilder{}

// Ready reports whether the evidence holds enough owner-accepted runs of
// one shape to compile (no model calls); until then Loop 1 waits for more
// supporting tasks instead of running a job that would yield ErrNoSkill.
func (b LoopBuilder) Ready(br loops.Brief) bool {
	_, err := b.C.BuildSkill(br.Hypothesis.Evidence)
	return err == nil
}

var _ loops.Readier = LoopBuilder{}
