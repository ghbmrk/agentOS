package heartbeat

import (
	"context"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"time"
)

// Age returns local calendar days since an authentic issued identity. It stays
// valid after Ack, but never bypasses clock-health or rollback checks. Calendar
// arithmetic deliberately ignores the 23/25-hour lengths of DST days.
func (s *Source) Age(ctx context.Context, snap digestqueue.Snapshot) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.ready(ctx); err != nil {
		return 0, err
	}
	r, err := s.decodeSnapshot(snap)
	if err != nil || r.Generation > s.st.Seq {
		return 0, ErrInvalid
	}
	_, day, err := s.clock(ctx)
	if err != nil {
		return 0, err
	}
	if r.Day > day {
		return 0, ErrClock
	}
	now, _ := time.Parse("2006-01-02", day)
	issued, _ := time.Parse("2006-01-02", r.Day)
	return int((now.Unix() - issued.Unix()) / 86400), nil
}
