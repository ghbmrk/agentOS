package daily

import (
	"context"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/digestqueue/heartbeat"
)

// Maintain retires only fully acknowledged transport-accepted daily history
// older than the explicitly retained local-day window. Current-day association
// and every undelivered/unknown outcome stay intact. It first recovers receipts
// and owns the same admission scope as collection/send/invalidation.
func (w *Workflow) Maintain(ctx context.Context, keepDays int) (int, error) {
	if keepDays < 1 || keepDays > 3650 {
		return 0, dq.ErrInvalid
	}
	ctx, leave, err := w.enter(ctx)
	if err != nil {
		return 0, err
	}
	defer leave()
	if err = w.collector.Recover(ctx); err != nil {
		return 0, err
	}
	batches, err := w.cfg.Queue.List()
	if err != nil {
		return 0, err
	}
	var ids []uint64
	for _, b := range batches {
		if b.State != dq.Accepted || b.Redacted {
			continue
		}
		complete := true
		for _, ack := range b.Acknowledged {
			if !ack {
				complete = false
			}
		}
		if !complete {
			continue
		}
		for _, s := range b.Snapshots {
			if s.Source != heartbeat.ID {
				continue
			}
			age, err := w.cfg.Heartbeat.Age(ctx, s)
			if err != nil {
				return 0, err
			}
			if age >= keepDays {
				ids = append(ids, b.ID)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := w.cfg.Queue.CompactBatches(ids); err != nil {
		return 0, err
	}
	return len(ids), nil
}
