package compile

import (
	"context"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
)

// LoopBuilder is the compiler as Loop 1's builder for repeated
// trajectories (loops.SignalRepeat): it compiles a skill from the brief's
// evidence only, which Loop 1 keeps free of held-out tasks (CHG-1). Loop 1
// sets the candidate's source, origin, and public mark itself.
type LoopBuilder struct{ C *Compiler }

func (b LoopBuilder) Build(ctx context.Context, br loops.Brief) (change.Candidate, error) {
	if err := ctx.Err(); err != nil {
		return change.Candidate{}, err
	}
	if !bounded(br.Hypothesis.Evidence) {
		return change.Candidate{}, ErrNoSkill
	}
	return b.C.BuildSkill(br.Hypothesis.Evidence)
}

// Bounds on the evidence the in-process builder reads, so a pathological
// journal cannot stall the daemon (arbitrator on W3 step 3a): a hypothesis
// with more is not compiled.
const (
	MaxEvidence      = 256
	MaxEvidenceBytes = 1 << 20
)

// bounded reports evidence within MaxEvidence statuses and
// MaxEvidenceBytes of params and recipients.
func bounded(ev []journal.Status) bool {
	if len(ev) > MaxEvidence {
		return false
	}
	n := 0
	for _, s := range ev {
		anyString(s.Intent.Params, s.Intent.Recipients, func(v string) bool {
			n += len(v)
			return false
		})
		if n > MaxEvidenceBytes {
			return false
		}
	}
	return true
}

var _ loops.Builder = LoopBuilder{}

// Ready reports whether the evidence holds enough owner-accepted runs of
// one shape to compile (no model calls); until then Loop 1 waits for more
// supporting tasks instead of running a job that would yield ErrNoSkill.
func (b LoopBuilder) Ready(br loops.Brief) bool {
	if !bounded(br.Hypothesis.Evidence) {
		return false
	}
	_, err := b.C.BuildSkill(br.Hypothesis.Evidence)
	return err == nil
}

var _ loops.Readier = LoopBuilder{}
