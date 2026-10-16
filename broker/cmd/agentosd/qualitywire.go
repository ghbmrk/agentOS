package main

import (
	"context"

	"github.com/ghbmrk/agentos/broker/loops"
)

// qualityRechecker is the pipeline's goal-quality trigger (OP-7).
type qualityRechecker interface {
	QualityDue() bool
	RecheckQuality(ctx context.Context) ([]string, error)
}

// qualitySource offers, ahead of Loop 1's own work, the re-evaluation of
// the adoptions a goal-quality revision reached (OP-7, SM-AQ-1). The
// journal has no commit subscription, so it is found on the scheduler's
// passes: a revision made while the broker runs waits at most for the
// next one, and one made while it was down is due on the first (SM-AQ-4).
type qualitySource struct {
	loops.Source
	pipe qualityRechecker
	// model: every evaluation calls the model, as Loop 1's recheck.
	model bool
}

// Digest keeps the wrapped source's digest lines.
func (s qualitySource) Digest() []string {
	if d, ok := s.Source.(loops.Digester); ok {
		return d.Digest()
	}
	return nil
}

func (s qualitySource) Next(ctx context.Context, modelOK bool) (loops.Job, bool) {
	if (modelOK || !s.model) && s.pipe.QualityDue() {
		return loops.Job{Name: "requality", UsesModel: s.model, Evaluates: true, Run: func(ctx context.Context) loops.Result {
			reverted, err := s.pipe.RecheckQuality(ctx)
			// Each revert removed a change that no longer qualifies.
			return loops.Result{Value: float64(len(reverted)), Err: err}
		}}, true
	}
	return s.Source.Next(ctx, modelOK)
}
