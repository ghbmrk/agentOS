// Package daily composes explicit daily collection and contained dispatch.
// It starts no goroutine or timer and is held until trusted activation.
package daily

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/control"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/bridgeattempt"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
	"github.com/ghbmrk/agentos/broker/journal"
	"sync"
	"time"
)

var ErrConfig = errors.New("daily: complete trusted configuration required")
var ErrHeld = bridgeattempt.ErrHeld
var ErrBusy = bridgeattempt.ErrBusy
var ErrAssociation = errors.New("daily: issued heartbeat has no unique durable association")
var ErrUncertain = errors.New("daily: daily transport outcome needs recovery")

type Validator = bridgeattempt.Validator

type Config struct {
	Queue     *dq.Queue
	Heartbeat *heartbeat.Source
	// Sources excludes the reserved heartbeat ID. Every source has one validator.
	Sources    map[string]dq.Source
	Validators map[string]Validator
	Owner      bridgeattempt.Owner
	Clock      func() (time.Time, error)
	TTL        time.Duration
	// Flush transfers transactional producer entries before peeking sources.
	// It must check producer health and honor cancellation; a no-op is explicit.
	Flush func(context.Context) error
	// Gate enforces current STOP, quiet hours, shared pacing, priority and resource
	// authority. Activation is not a substitute for this per-attempt policy.
	Gate func(context.Context, dq.Batch) error
}
type Workflow struct {
	cfg       Config
	collector *dq.Collector
	dispatch  *bridgeattempt.Controller
	serial    chan struct{}
	mu        sync.Mutex
	held      bool
	epoch     chan struct{}
	cancel    context.CancelFunc
	mutating  bool
}

func New(cfg Config) (*Workflow, error) {
	if cfg.Queue == nil || cfg.Heartbeat == nil || cfg.Clock == nil || cfg.Flush == nil || cfg.Owner == nil || cfg.Gate == nil || cfg.TTL <= 0 || cfg.TTL > 48*time.Hour || len(cfg.Sources) != len(cfg.Validators) {
		return nil, ErrConfig
	}
	sources := map[string]dq.Source{heartbeat.ID: cfg.Heartbeat}
	validators := map[string]Validator{heartbeat.ID: cfg.Heartbeat.Validate}
	for id, s := range cfg.Sources {
		v := cfg.Validators[id]
		if id == heartbeat.ID || s == nil || v == nil {
			return nil, ErrConfig
		}
		sources[id] = s
		validators[id] = v
	}
	collector, err := dq.NewCollector(cfg.Queue, sources)
	if err != nil {
		return nil, err
	}
	dispatch, err := bridgeattempt.NewController(bridgeattempt.Config{Queue: cfg.Queue, Owner: cfg.Owner, Now: func() time.Time {
		t, err := cfg.Clock()
		if err != nil {
			return time.Time{}
		}
		return t
	}, Sources: validators, Gate: func(ctx context.Context, b dq.Batch) error {
		t, err := cfg.Clock()
		if err != nil {
			return err
		}
		if t.IsZero() {
			return heartbeat.ErrClock
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return cfg.Gate(ctx, b)
	}})
	if err != nil {
		return nil, err
	}
	epoch := make(chan struct{})
	close(epoch)
	return &Workflow{cfg: cfg, collector: collector, dispatch: dispatch, serial: make(chan struct{}, 1), held: true, epoch: epoch}, nil
}

// Activate is a trusted composition operation, never an owner authentication
// result. It refuses active/mutating work. Engine Resume does not call it.
func (w *Workflow) Activate() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil || w.mutating {
		return ErrBusy
	}
	if err := w.dispatch.Release(); err != nil {
		return err
	}
	if w.held {
		w.held = false
		w.epoch = make(chan struct{})
	}
	return nil
}
func (w *Workflow) hold() {
	if !w.held {
		w.held = true
		close(w.epoch)
	}
	if w.cancel != nil {
		w.cancel()
	}
	w.dispatch.Hold()
}

// Hold never waits on storage, callbacks, collection or transport.
func (w *Workflow) Hold() { w.mu.Lock(); defer w.mu.Unlock(); w.hold() }
func (w *Workflow) enter(ctx context.Context) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	epoch := w.epoch
	w.mu.Unlock()
	select {
	case w.serial <- struct{}{}:
	case <-epoch:
		return nil, nil, ErrHeld
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	w.mu.Lock()
	if w.held || w.epoch != epoch || w.mutating {
		w.mu.Unlock()
		<-w.serial
		return nil, nil, ErrHeld
	}
	child, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.mu.Unlock()
	return child, func() { cancel(); w.mu.Lock(); w.cancel = nil; w.mu.Unlock(); <-w.serial }, nil
}

// Step recovers receipts, stages the due heartbeat, collects once for that daily
// identity, then sends/retries that exact batch. ID zero means no day is due.
// An error may follow durable admission; do not replace state or invent a new ID.
func (w *Workflow) Step(ctx context.Context) (uint64, error) {
	ctx, leave, err := w.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	if err = w.collector.Recover(ctx); err != nil {
		return 0, err
	}
	if err = w.cfg.Flush(ctx); err != nil {
		return 0, err
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = w.cfg.Heartbeat.Plan(ctx); err != nil {
		return 0, err
	}
	anchor, err := w.cfg.Heartbeat.Current(ctx)
	if err != nil || anchor == nil {
		return 0, err
	}
	batches, err := w.cfg.Queue.List()
	if err != nil {
		return 0, err
	}
	var found *dq.Batch
	for _, b := range batches {
		for _, s := range b.Snapshots {
			if s.Source == heartbeat.ID && s.Generation == anchor.Generation {
				if s.Hash != anchor.Hash || found != nil {
					return 0, ErrAssociation
				}
				copy := b
				found = &copy
			}
		}
	}
	if found == nil {
		pending, err := w.cfg.Heartbeat.Peek(ctx)
		if err != nil {
			return 0, err
		}
		if pending == nil || pending.Hash != anchor.Hash {
			return 0, ErrAssociation
		}
		now, err := w.cfg.Clock()
		if err != nil {
			return 0, err
		}
		if now.IsZero() {
			return 0, heartbeat.ErrClock
		}
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		found, err = w.collector.Collect(ctx, now, now.Add(w.cfg.TTL))
		if err != nil {
			return 0, err
		}
		if found == nil {
			return 0, ErrAssociation
		}
		matched := false
		for _, s := range found.Snapshots {
			if s.Source == heartbeat.ID && s.Hash == anchor.Hash {
				matched = true
			}
		}
		if !matched {
			return found.ID, ErrAssociation
		}
	}
	switch found.State {
	case dq.Accepted:
		return found.ID, nil
	case dq.Ready:
		return found.ID, w.dispatch.Send(ctx, found.ID)
	case dq.Unknown, dq.Sending:
		return found.ID, ErrUncertain
	default:
		return found.ID, dq.ErrState
	}
}

// Quiesce serializes source/queue invalidation against the entire workflow.
// Deadline before admission skips mutation; all outcomes leave the workflow held.
// Callbacks must honor deadlines and cover all independently owned stores.
func (w *Workflow) Quiesce(ctx context.Context, fn func(context.Context) error) error {
	if ctx == nil || fn == nil {
		return ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	if w.mutating {
		w.mu.Unlock()
		return ErrBusy
	}
	w.mutating = true
	w.hold()
	w.mu.Unlock()
	defer func() { w.mu.Lock(); w.mutating = false; w.mu.Unlock() }()
	select {
	case w.serial <- struct{}{}:
		defer func() { <-w.serial }()
	case <-ctx.Done():
		return ctx.Err()
	}
	return w.dispatch.Quiesce(ctx, fn)
}
func (w *Workflow) WrapEngine(e control.Engine) (control.Engine, error) {
	if e == nil {
		return nil, ErrConfig
	}
	return engine{w, e}, nil
}

type engine struct {
	w *Workflow
	e control.Engine
}

func (e engine) Stop(ctx context.Context) (journal.StopReport, error) {
	e.w.Hold()
	return e.e.Stop(ctx)
}
func (e engine) Resume() error          { return e.e.Resume() }
func (e engine) Stopped() bool          { return e.e.Stopped() }
func (e engine) List() []journal.Status { return e.e.List() }
