// Package bridgeattempt prepares one durable digest transport attempt. It is
// unenabled infrastructure, not a scheduler or an authority/pacing policy.
package bridgeattempt

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/modemlink"
	"github.com/ghbmrk/agentos/broker/owner"
)

var ErrConfig = errors.New("bridgeattempt: complete trusted configuration required")
var ErrRendering = errors.New("bridgeattempt: complete digest cannot be disclosed unchanged in one text")

// Owner is implemented by owner.Channel, preserving fixed recipient, disclosure
// and line-failure watching. Only trusted broker integration may supply it.
type Owner interface {
	InformContext(context.Context, string) error
}

// Validator checks current source receipt eligibility, not owner authority.
type Validator func(context.Context, digestqueue.Snapshot) error

type Config struct {
	Queue *digestqueue.Queue
	Owner Owner
	Now   func() time.Time
	// Gate must freshly check STOP, quiet hours, shared pacing, priority and
	// resource/authority policy. The caller must serialize containment/forget
	// with this entire Send scope and cancel any in-flight transport on STOP.
	// A callback alone does not provide that serialization or qualification.
	Gate func(context.Context, digestqueue.Batch) error
	// Sources is a closed trusted source allowlist. Validators must check
	// current eligibility; hash/issuance checks alone do not implement forget.
	Sources map[string]Validator
}

type Attempt struct {
	serial chan struct{}
	cfg    Config
}

func New(cfg Config) (*Attempt, error) {
	if cfg.Queue == nil || cfg.Owner == nil || cfg.Now == nil || cfg.Gate == nil || len(cfg.Sources) == 0 {
		return nil, ErrConfig
	}
	sources := make(map[string]Validator, len(cfg.Sources))
	for id, validate := range cfg.Sources {
		if id == "" || validate == nil {
			return nil, ErrConfig
		}
		sources[id] = validate
	}
	cfg.Sources = sources
	return &Attempt{cfg: cfg, serial: make(chan struct{}, 1)}, nil
}
func copyBatch(b digestqueue.Batch) digestqueue.Batch {
	b.Acknowledged = slices.Clone(b.Acknowledged)
	b.Snapshots = slices.Clone(b.Snapshots)
	for i := range b.Snapshots {
		b.Snapshots[i].Lines = slices.Clone(b.Snapshots[i].Lines)
		b.Snapshots[i].References = slices.Clone(b.Snapshots[i].References)
	}
	return b
}
func render(b digestqueue.Batch) (string, error) {
	var lines []string
	for _, s := range b.Snapshots {
		lines = append(lines, s.Lines...)
	}
	if len(lines) == 0 {
		return "", ErrRendering
	}
	text := "Daily update: " + strings.Join(lines, " ")
	// Never silently cut a line, translate a control character, or replace a
	// secret-shaped digest with a pointer and then mark the full batch sent.
	if owner.Disclose(text) != text || control.Fit(text) != text {
		return "", ErrRendering
	}
	return text, nil
}

// Send makes at most one transport call. Source acknowledgments are checked by
// Queue.Begin; callbacks must not acknowledge or consume sources. Durable begin
// precedes the call. Any uncertain transport/save result remains quarantined.
// Use one instance in the broker's guarded dispatch scope; the local semaphore serializes
// only this instance, not other queues/processes or owner policy transitions.
func (a *Attempt) Send(ctx context.Context, id uint64) error {
	if ctx == nil {
		return ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case a.serial <- struct{}{}:
		defer func() { <-a.serial }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, err := a.cfg.Queue.Get(id)
	if err != nil {
		return err
	}
	if b.State != digestqueue.Ready {
		return digestqueue.ErrState
	}
	text, err := render(b)
	if err != nil {
		return err
	}
	for _, s := range b.Snapshots {
		validate, ok := a.cfg.Sources[s.Source]
		if !ok {
			return ErrConfig
		}
		isolated := copyBatch(digestqueue.Batch{Snapshots: []digestqueue.Snapshot{s}}).Snapshots[0]
		if err = validate(ctx, isolated); err != nil {
			return err
		}
	}
	// Dispatch policy is checked after source checks and immediately before
	// durable begin. External serialized containment remains an integration gate.
	if err = a.cfg.Gate(ctx, copyBatch(b)); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	b, err = a.cfg.Queue.Begin(id, a.cfg.Now())
	if err != nil {
		return err
	}
	// Cancellation during synchronous Begin persistence is proven local
	// non-delivery: the owner/transport boundary has not been called yet.
	if err := ctx.Err(); err != nil {
		evidence := fmt.Sprintf("digest:%d:attempt:%d:cancel-before-call", b.ID, b.Attempts)
		return errors.Join(err, a.cfg.Queue.Finish(b.ID, b.Attempts, digestqueue.NotSent, evidence))
	}
	sendErr := a.cfg.Owner.InformContext(ctx, text)
	outcome := digestqueue.OutcomeUnknown
	suffix := "ambiguous"
	if sendErr == nil {
		outcome = digestqueue.TransportAccepted
		suffix = "bridge-accepted"
	} else {
		// owner.Channel returns the bridge error unchanged. Wrapped/joined
		// errors may combine observations; they cannot prove this attempt unsent.
		canceled, direct := sendErr.(*modemlink.SendCanceledError)
		if direct && canceled != nil && !canceled.Handed &&
			(errors.Is(canceled.Cause, context.Canceled) || errors.Is(canceled.Cause, context.DeadlineExceeded)) {
			outcome = digestqueue.NotSent
			suffix = "cancel-before-handoff"
		}
	}
	// This is a local adapter observation reference, not a carrier receipt or
	// authenticated remote evidence. It names this exact durable attempt.
	evidence := fmt.Sprintf("digest:%d:attempt:%d:%s", b.ID, b.Attempts, suffix)
	finishErr := a.cfg.Queue.Finish(b.ID, b.Attempts, outcome, evidence)
	return errors.Join(sendErr, finishErr)
}
