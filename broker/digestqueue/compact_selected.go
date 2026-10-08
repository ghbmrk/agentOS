package digestqueue

import "slices"

// CompactBatches retires an explicit bounded set atomically. Every member must
// be terminal and fully source-acknowledged before any payload is removed.
// Unknown/in-flight outcomes remain private recovery records. Source high-water
// identities and the batch sequence survive; this is not a forget proof.
func (q *Queue) CompactBatches(ids []uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.broken {
		return ErrRecovery
	}
	if len(ids) > q.st.Policy.MaxBatches {
		return ErrInvalid
	}
	selected := make(map[uint64]bool, len(ids))
	for _, id := range ids {
		if id == 0 || selected[id] {
			return ErrInvalid
		}
		selected[id] = true
		b, err := find(&q.st, id)
		if err != nil {
			return err
		}
		switch b.State {
		case Unknown, Sending:
			return ErrInFlight
		case Accepted, Expired, Cancelled, Failed:
		default:
			return ErrState
		}
		for _, ack := range b.Acknowledged {
			if !ack {
				return ErrUnacknowledged
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	next := clone(q.st)
	next.Batches = slices.DeleteFunc(next.Batches, func(b Batch) bool { return selected[b.ID] })
	return q.commit(next)
}
