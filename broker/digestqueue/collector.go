package digestqueue

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"
)

var ErrSourceUnavailable = errors.New("digestqueue: pending source unavailable")

// Source is a trusted broker component, never a guest or an adapter response.
// Peek is nonconsuming and returns nil when there is no pending generation.
// Ack durably consumes only the supplied generation/hash, remains idempotent
// after restart, and preserves newer generations. Both honor ctx deadlines.
// The source itself validates that the snapshot is its actual retained output.
type Source interface {
	Peek(context.Context) (*Snapshot, error)
	Ack(context.Context, Snapshot) error
}

// Collector coordinates admission and source acknowledgment. It never sends,
// infers visibility, runs callbacks while holding Queue.mu, or invents a source
// generation. One configured Collector owns collection/recovery for a Queue.
// External dispatch/forget integration must serialize source invalidation with
// this coordinator; thread serialization does not replace process containment.
type Collector struct {
	mu      sync.Mutex
	queue   *Queue
	sources map[string]Source
	names   []string
}

func NewCollector(q *Queue, sources map[string]Source) (*Collector, error) {
	if q == nil || len(sources) == 0 || len(sources) > 16 {
		return nil, ErrInvalid
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return nil, ErrRecovery
	}
	if len(sources) > q.st.Policy.MaxSources {
		return nil, ErrInvalid
	}
	for id, s := range sources {
		if !name.MatchString(id) || s == nil {
			return nil, ErrInvalid
		}
	}
	names := slices.Sorted(maps.Keys(sources))
	return &Collector{queue: q, sources: maps.Clone(sources), names: names}, nil
}

// Recover replays incomplete source acknowledgments from durable associations.
// It does not re-peek a source or regenerate its times/text. A missing source
// blocks new collection visibly rather than abandoning a pending batch; expired
// batches are skipped because their sources re-offer them.
func (c *Collector) Recover(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recover(ctx)
}
func (c *Collector) recover(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	batches, err := c.queue.List()
	if err != nil {
		return err
	}
	for _, b := range batches {
		// An expired batch never consumed its sources: they still hold the
		// snapshot and re-offer it, admitted as a new batch (DB-6).
		if b.State == Expired {
			continue
		}
		// A held batch (ready, past expiry, partly acknowledged) is finished
		// here too, so Late can re-arm it with every source consumed (DB-4).
		for i, acked := range b.Acknowledged {
			if acked {
				continue
			}
			if b.State != Ready {
				return ErrState
			}
			if err = c.ack(ctx, b.ID, b.Snapshots[i]); err != nil {
				return err
			}
		}
	}
	return nil
}
func (c *Collector) ack(ctx context.Context, id uint64, snapshot Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	source, ok := c.sources[snapshot.Source]
	if !ok {
		return fmt.Errorf("%w: %s", ErrSourceUnavailable, snapshot.Source)
	}
	// Never move this callback before queue admission. A crash after this Ack but
	// before bitmap persistence is recovered by replaying this identical snapshot.
	if err := source.Ack(ctx, clone(snapshot)); err != nil {
		return fmt.Errorf("digestqueue: source acknowledgment: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.queue.Acknowledge(id, snapshot.Source, snapshot.Generation, snapshot.Hash)
}

// Collect first repairs partial acknowledgments, then peeks every configured
// source, admits one combined batch durably, and acknowledges it source by source.
// An error may leave a durable, partially acknowledged batch: call Recover before
// trying fresh collection. Never treat an error as evidence nothing was saved.
// No pending source returns nil, nil. A successful batch is ready, not sent.
func (c *Collector) Collect(ctx context.Context, created, expires time.Time) (*Batch, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.recover(ctx); err != nil {
		return nil, err
	}
	var snapshots []Snapshot
	for _, id := range c.names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, err := c.sources[id].Peek(ctx)
		if err != nil {
			return nil, fmt.Errorf("digestqueue: source snapshot: %w", err)
		}
		if snapshot == nil {
			continue
		}
		if snapshot.Source != id || !snapshot.valid() {
			return nil, ErrInvalid
		}
		snapshots = append(snapshots, clone(*snapshot))
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(snapshots) == 0 {
		return nil, nil
	}
	b, err := c.queue.Enqueue(snapshots, created, expires)
	if err != nil {
		return nil, err
	}
	for i, s := range b.Snapshots {
		if !b.Acknowledged[i] {
			if err = c.ack(ctx, b.ID, s); err != nil {
				return nil, err
			}
		}
	}
	saved, err := c.queue.Get(b.ID)
	if err != nil {
		return nil, err
	}
	return &saved, nil
}
