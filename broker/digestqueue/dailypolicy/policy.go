// Package dailypolicy connects digest policy to the existing approval/question
// budget. Check reserves once; Recheck is read-only and safe after durable Begin.
package dailypolicy

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/control"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/grants"
	"slices"
	"time"
)

var ErrConfig = errors.New("dailypolicy: complete trusted policy configuration required")
var ErrStopped = errors.New("dailypolicy: engine stopped")
var ErrClock = errors.New("dailypolicy: trusted time unavailable or moved backwards")
var ErrQuiet = errors.New("dailypolicy: quiet hours")
var ErrPaced = errors.New("dailypolicy: shared notification budget unavailable")

type Config struct {
	// Budget is the same Gate used by approvals and question.Config.Reserve.
	// Never supply a dedicated digest gate or a guest-selected counter.
	Budget *grants.Gate
	Engine control.Engine
	// Clock is an atomic trusted time/health observation, e.g. clock.Guard.Now.
	Clock func(context.Context) (time.Time, error)
	// Quiet and Eligible must be read-only, repeatable and bounded. Explicitly
	// supply a false/nil-error function when reviewed policy has no such hold.
	Quiet    func(time.Time) bool
	Eligible func(context.Context, dq.Batch) error
	// AgedAfter reuses Gate.Reserve's existing aged-question fairness rule.
	// It never bypasses the hourly budget or invents an urgent class.
	AgedAfter time.Duration
}
type Policy struct{ cfg Config }

func New(cfg Config) (*Policy, error) {
	if cfg.Budget == nil || cfg.Engine == nil || cfg.Clock == nil || cfg.Quiet == nil || cfg.Eligible == nil || cfg.AgedAfter <= 0 || cfg.AgedAfter > 24*time.Hour {
		return nil, ErrConfig
	}
	return &Policy{cfg}, nil
}
func isolated(b dq.Batch) dq.Batch {
	b.Acknowledged = slices.Clone(b.Acknowledged)
	b.Snapshots = slices.Clone(b.Snapshots)
	for i := range b.Snapshots {
		b.Snapshots[i].Lines = slices.Clone(b.Snapshots[i].Lines)
		b.Snapshots[i].References = slices.Clone(b.Snapshots[i].References)
	}
	return b
}
func (p *Policy) window(ctx context.Context, b dq.Batch) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if p.cfg.Engine.Stopped() {
		return time.Time{}, ErrStopped
	}
	now, err := p.cfg.Clock(ctx)
	if ctx.Err() != nil {
		return time.Time{}, ctx.Err()
	}
	if err != nil {
		return time.Time{}, errors.Join(ErrClock, err)
	}
	if now.IsZero() || now.Before(b.Created) {
		return time.Time{}, ErrClock
	}
	if !now.Before(b.Expires) {
		return time.Time{}, dq.ErrExpired
	}
	if p.cfg.Quiet(now) {
		return time.Time{}, ErrQuiet
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	return now, nil
}
func (p *Policy) preflight(ctx context.Context, b dq.Batch) (time.Time, error) {
	if ctx == nil {
		return time.Time{}, ErrConfig
	}
	if b.ID == 0 || b.Created.IsZero() || !b.Expires.After(b.Created) {
		return time.Time{}, dq.ErrInvalid
	}
	if _, err := p.window(ctx, b); err != nil {
		return time.Time{}, err
	}
	if err := p.cfg.Eligible(ctx, isolated(b)); err != nil {
		return time.Time{}, err
	}
	// Resource checks may stall across a clock/quiet/STOP boundary. Observe it
	// again immediately before reserving or returning read-only eligibility.
	return p.window(ctx, b)
}

// Check is the reservation phase: exactly one common-budget slot on success.
// A later proven non-send does not refund it. Only trusted broker code calls it.
func (p *Policy) Check(ctx context.Context, b dq.Batch) error {
	now, err := p.preflight(ctx, b)
	if err != nil {
		return err
	}
	if !p.cfg.Budget.Reserve(now.Sub(b.Created) >= p.cfg.AgedAfter) {
		return ErrPaced
	}
	return ctx.Err()
}

// Recheck repeats current policy without reserving. Pair it with Check in the
// same contained host. It accepts persisted Sending batches after Begin.
func (p *Policy) Recheck(ctx context.Context, b dq.Batch) error {
	_, err := p.preflight(ctx, b)
	return err
}
