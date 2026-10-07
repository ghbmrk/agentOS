package bridgeattempt

import (
	"context"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/journal"
)

var ErrHeld = errors.New("bridgeattempt: dispatch held")
var ErrBusy = errors.New("bridgeattempt: dispatch scope still active")

type dispatchLease struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// Controller owns one Attempt and its containment/invalidation lifecycle. It
// starts held, and does not implement pacing, quiet hours or authority policy.
// All sends and source/queue invalidation must use this single trusted instance.
// Synchronous stores and transports still require bounded latency.
type Controller struct {
	mu       sync.Mutex
	serial   chan struct{}
	held     bool
	hold     chan struct{} // admission epoch: closed by Hold, replaced by Release
	active   *dispatchLease
	mutating bool
	attempt  *Attempt
}

func NewController(cfg Config) (*Controller, error) {
	c := &Controller{serial: make(chan struct{}, 1), held: true, hold: make(chan struct{})}
	close(c.hold)
	policy := cfg.Gate
	if policy == nil {
		return nil, ErrConfig
	}
	cfg.Gate = func(ctx context.Context, b digestqueue.Batch) error {
		if err := c.scopeReady(ctx); err != nil {
			return err
		}
		if err := policy(ctx, b); err != nil {
			return err
		}
		return c.scopeReady(ctx)
	}
	a, err := New(cfg)
	if err != nil {
		return nil, err
	}
	c.attempt = a
	return c, nil
}
func (c *Controller) scopeReady(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.held || c.active == nil || c.active.ctx != ctx {
		return ErrHeld
	}
	return nil
}
func (c *Controller) Held() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.held }
func (c *Controller) holdLocked() {
	if !c.held {
		c.held = true
		close(c.hold)
	}
	if c.active != nil {
		c.active.cancel()
	}
}

// Hold cancels active/queued admission without waiting for policy, storage,
// transport, finish persistence or invalidation callbacks. Cancellation cannot
// retract a bridge handoff; uncertain attempts retain their normal quarantine.
func (c *Controller) Hold() { c.mu.Lock(); defer c.mu.Unlock(); c.holdLocked() }

// Release is an explicit trusted composition operation, not an owner-authority
// decision. It refuses while dispatch/invalidation is live. Every later send
// still performs fresh source and policy checks. No old waiter gains admission.
func (c *Controller) Release() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != nil || c.mutating {
		return ErrBusy
	}
	if c.held {
		c.held = false
		c.hold = make(chan struct{})
	}
	return nil
}
func (c *Controller) Send(ctx context.Context, id uint64) error {
	if ctx == nil {
		return ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.held {
		c.mu.Unlock()
		return ErrHeld
	}
	epoch := c.hold
	c.mu.Unlock()
	select {
	case c.serial <- struct{}{}:
	case <-epoch:
		return ErrHeld
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.serial }()
	c.mu.Lock()
	if c.held || c.hold != epoch {
		c.mu.Unlock()
		return ErrHeld
	}
	if err := ctx.Err(); err != nil {
		c.mu.Unlock()
		return err
	}
	child, cancel := context.WithCancel(ctx)
	c.active = &dispatchLease{ctx: child, cancel: cancel}
	c.mu.Unlock()
	defer func() { cancel(); c.mu.Lock(); c.active = nil; c.mu.Unlock() }()
	return c.attempt.Send(child, id)
}

// Quiesce holds admission, cancels active work, waits through final queue
// persistence, then runs one trusted source/queue mutation exclusively. A
// deadline while draining never invokes mutate and leaves admission held.
// mutate must honor its context and have bounded synchronous storage latency.
// Success is quiescence only, not full forget/backup/transport deletion proof.
func (c *Controller) Quiesce(ctx context.Context, mutate func(context.Context) error) error {
	if ctx == nil || mutate == nil {
		return ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.mutating {
		c.mu.Unlock()
		return ErrBusy
	}
	c.mutating = true
	c.holdLocked()
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.mutating = false; c.mu.Unlock() }()
	select {
	case c.serial <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-c.serial }()
	if err := ctx.Err(); err != nil {
		return err
	}
	return mutate(ctx)
}

// WrapEngine makes text/local STOP revoke dispatch before delegating to the
// engine. It introduces no wait on dispatch. Resume delegates normal engine
// authority but intentionally leaves dispatch held for explicit policy review.
func (c *Controller) WrapEngine(engine control.Engine) (control.Engine, error) {
	if engine == nil {
		return nil, ErrConfig
	}
	return containedEngine{controller: c, engine: engine}, nil
}

type containedEngine struct {
	controller *Controller
	engine     control.Engine
}

func (e containedEngine) Stop(ctx context.Context) (journal.StopReport, error) {
	e.controller.Hold()
	return e.engine.Stop(ctx)
}
func (e containedEngine) Resume() error          { return e.engine.Resume() }
func (e containedEngine) Stopped() bool          { return e.engine.Stopped() }
func (e containedEngine) List() []journal.Status { return e.engine.List() }
