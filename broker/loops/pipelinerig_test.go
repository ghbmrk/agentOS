package loops

import (
	"context"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
)

// The change pipeline's test pieces for secure_test and report_test, whose
// pipelines still need a journal engine (change.Pipeline.Attach). They move
// when change does (#2785b).

// policy is the broker's policy for change intents in these tests:
// change.ErrNeedsOwner becomes the owner's answer (approve). Other intents
// are allowed.
type policy struct {
	mu      sync.Mutex
	p       *change.Pipeline
	approve bool
}

func (o *policy) Check(ctx context.Context, ph journal.Phase, in journal.Intent) error {
	if in.Executor != change.Executor {
		return nil
	}
	err := o.p.Check(ctx, ph, in)
	if !errors.Is(err, change.ErrNeedsOwner) {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.approve {
		return nil
	}
	return errors.New("needs the owner's approval")
}

// fixed is a deterministic "random" source for the pipeline. These tests
// rely on the dev/held-out layout its split key gives; the key was changed
// when cases began splitting by goal (P3-1c), which re-laid the split.
type fixed struct{}

func (fixed) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i*7 + 5)
	}
	return len(b), nil
}
