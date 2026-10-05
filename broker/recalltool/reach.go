package recalltool

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/recall"
)

// Journal is the part of the broker's journal deletion reaches
// (journal.Engine).
type Journal interface {
	Since(origin string, since time.Time) []string
	Erase(ids []string) (erased, held []string, err error)
}

// Machines is the part of the VM manager deletion reaches (vm.Manager).
type Machines interface {
	ForgetSince(ctx context.Context, lineage string, since time.Time) error
}

// Cases is the part of the change pipeline deletion reaches
// (change.Pipeline).
type Cases interface {
	ForgetTasks(tasks ...string) (int, error)
}

// Reach carries a recall deletion past the index (CAP-3, K2b). For each
// fork lineage the provenance record says was given a deleted item, first
// at T:
//
//  1. the lineage's machines go back to before T and its snapshots from T
//     on are deleted (Machines);
//  2. the journal intents the lineage submitted from T on are erased:
//     parameters and evidence go, the audit trail stays (Journal). Replay
//     recordings are read from the journal, so they go with it;
//  3. change-pipeline cases built on those intents are removed (Cases);
//  4. the provenance record forgets what the lineage was given from T on.
//
// An intent still in flight is held: the deletion stays pending and Retry
// finishes it once the intent settles. A failure keeps it pending too.
// Provenance is forgotten last, so after a crash the index's replay of its
// tombstones at start runs the reach again (machines are reset again then:
// it errs toward taking back too much).
type Reach struct {
	Prov     *Provenance
	Journal  Journal  // nil: not wired
	Machines Machines // nil: not wired
	Cases    Cases    // nil: not wired
	Logf     func(format string, args ...any)

	mu      sync.Mutex
	pending map[string]bool // deleted item IDs not yet fully reached
	reset   map[string]bool // lineage@T whose machines are done this run
}

// OnDelete is the recall.Index deletion hook.
func (r *Reach) OnDelete(d recall.Deleted) error {
	return r.reach(context.Background(), d.ID)
}

// Retry runs every pending deletion again; Service.Run calls it.
func (r *Reach) Retry(ctx context.Context) error {
	r.mu.Lock()
	ids := make([]string, 0, len(r.pending))
	for id := range r.pending {
		ids = append(ids, id)
	}
	r.mu.Unlock()
	sort.Strings(ids)
	var errs []error
	for _, id := range ids {
		errs = append(errs, r.reach(ctx, id))
	}
	return errors.Join(errs...)
}

// Pending reports how many deletions are not yet fully reached.
func (r *Reach) Pending() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.pending)
}

func (r *Reach) reach(ctx context.Context, id string) error {
	holders := r.Prov.Holders(id)
	lineages := make([]string, 0, len(holders))
	for l := range holders {
		lineages = append(lineages, l)
	}
	sort.Strings(lineages)
	var errs []error
	for _, l := range lineages {
		if err := r.lineage(ctx, l, holders[l]); err != nil {
			errs = append(errs, fmt.Errorf("deletion reach into %s: %w", l, err))
		}
	}
	err := errors.Join(errs...)
	r.mu.Lock()
	if r.pending == nil {
		r.pending = map[string]bool{}
	}
	if err != nil {
		r.pending[id] = true
	} else {
		delete(r.pending, id)
	}
	r.mu.Unlock()
	if err != nil && r.Logf != nil {
		r.Logf("recall: %v", err)
	}
	return err
}

func (r *Reach) lineage(ctx context.Context, lineage string, since time.Time) error {
	key := lineage + "@" + since.UTC().Format(time.RFC3339Nano)
	r.mu.Lock()
	done := r.reset[key]
	r.mu.Unlock()
	if r.Machines != nil && !done {
		if err := r.Machines.ForgetSince(ctx, lineage, since); err != nil {
			return err
		}
		r.mu.Lock()
		if r.reset == nil {
			r.reset = map[string]bool{}
		}
		r.reset[key] = true
		r.mu.Unlock()
	}
	if r.Journal != nil {
		ids := r.Journal.Since("guest:"+lineage, since)
		_, held, err := r.Journal.Erase(ids)
		if err != nil {
			return err
		}
		if r.Cases != nil {
			// Every intent from T on, not only those erased now, so a
			// retry after a failed removal still removes their cases.
			if _, err := r.Cases.ForgetTasks(ids...); err != nil {
				return err
			}
		}
		if len(held) > 0 {
			return fmt.Errorf("%d intents in flight; erased once they settle", len(held))
		}
	}
	if r.Machines == nil {
		// Its memory was not reached, so it still holds what it was given;
		// notes it makes keep deriving from it.
		return nil
	}
	if err := r.Prov.ForgetSince(lineage, since); err != nil {
		return err
	}
	r.mu.Lock()
	delete(r.reset, key)
	r.mu.Unlock()
	return nil
}
