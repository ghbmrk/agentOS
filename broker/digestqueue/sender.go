package digestqueue

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Transport hands one rendered digest to the owner's channel and reports what
// it can prove. Accepted and NotSent need an evidence reference; anything it
// cannot prove, including a lost receipt, is OutcomeUnknown. Deliver may block
// until ctx ends but must not retry: the queue owns attempts.
type Transport interface {
	Deliver(ctx context.Context, text string) (Outcome, string)
}

// Sender is the only path from a queued batch to a transport. Send begins the
// batch durably, renders that begun batch, delivers it once and records the
// outcome; nothing else in this package names begin, finish or Deliver, and a
// test pins that structurally.
type Sender struct {
	queue     *Queue
	transport Transport
	render    func(Batch) (string, error)
	now       func() time.Time
}

func NewSender(q *Queue, t Transport, render func(Batch) (string, error), now func() time.Time) (*Sender, error) {
	if q == nil || t == nil || render == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Sender{queue: q, transport: t, render: render, now: now}, nil
}

// ErrRender reports a batch that was begun but could not be rendered. It is
// recorded as NotSent (no transport call happened) and consumes an attempt.
var ErrRender = errors.New("digestqueue: render failed; nothing delivered")

// Send returns the recorded outcome. A refusal (unacknowledged, expired, wrong
// state, quarantined queue, ended context) returns before the transport is
// called. A transport panic, an ended context, or a receipt without valid
// evidence is recorded as OutcomeUnknown and never retried automatically. If
// the outcome cannot be recorded, Send returns OutcomeUnknown and the error;
// the queue is then quarantined and reopening it turns the attempt unknown.
func (s *Sender) Send(ctx context.Context, id uint64) (Outcome, error) {
	if ctx == nil {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	b, err := s.queue.begin(id, s.now())
	if err != nil {
		return "", err
	}
	outcome, evidence, failure := NotSent, "render-failed", error(nil)
	if text, err := s.rendered(b); err != nil {
		failure = err
	} else {
		outcome, evidence = func() (o Outcome, e string) {
			defer func() {
				if recover() != nil {
					o, e = OutcomeUnknown, ""
				}
			}()
			return s.transport.Deliver(ctx, text)
		}()
		outcome, evidence = proven(ctx, outcome, evidence)
	}
	if err = s.queue.finish(b.ID, b.Attempts, outcome, evidence); err != nil {
		return OutcomeUnknown, err
	}
	return outcome, failure
}

// rendered gives render an owned copy, so it never reaches queue state.
func (s *Sender) rendered(b Batch) (text string, err error) {
	defer func() {
		if r := recover(); r != nil {
			text, err = "", fmt.Errorf("%w: panic", ErrRender)
		}
	}()
	text, err = s.render(clone(b))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrRender, err)
	}
	if text == "" {
		return "", fmt.Errorf("%w: empty text", ErrRender)
	}
	return text, nil
}

// proven keeps a receipt only if it carries valid evidence and the context is
// still live; everything else becomes OutcomeUnknown without evidence.
func proven(ctx context.Context, outcome Outcome, evidence string) (Outcome, string) {
	if evidence != "" && !name.MatchString(evidence) {
		return OutcomeUnknown, ""
	}
	switch outcome {
	case TransportAccepted:
		if evidence != "" {
			return outcome, evidence
		}
	case NotSent:
		if evidence != "" && ctx.Err() == nil {
			return outcome, evidence
		}
	case OutcomeUnknown:
		return outcome, evidence
	}
	return OutcomeUnknown, ""
}
