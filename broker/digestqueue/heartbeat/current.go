package heartbeat

import (
	"context"
	"encoding/json"
	"github.com/ghbmrk/agentos/broker/digestqueue"
)

// Current returns the authentic identity issued for the current trusted day,
// including after acknowledgment. It is nonconsuming and never issues a line.
// This lets a coordinator find its durable queue association without a second
// scheduling ledger. Old-day entries are not current; rollback remains refused.
func (s *Source) Current(ctx context.Context) (*digestqueue.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	_, day, err := s.clock(ctx)
	if err != nil {
		return nil, err
	}
	if day != s.st.LastDay {
		return nil, nil
	}
	r := receipt{Generation: s.st.Seq, Day: day, MAC: s.mac(s.st.Seq, day)}
	raw, _ := json.Marshal(r)
	snap, err := digestqueue.NewSnapshotWithReceipt(ID, s.st.Seq, []string{Line}, nil, string(raw))
	if err != nil {
		return nil, err
	}
	return &snap, nil
}
