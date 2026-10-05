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
