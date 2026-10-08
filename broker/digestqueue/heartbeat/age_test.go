package heartbeat

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"testing"
	"time"
)

// REQ: TIM-1, CH-15, OP-1
func TestAuthenticatedCalendarAgeAcrossDSTAndAcknowledgment(t *testing.T) {
	for _, at := range []time.Time{time.Date(2026, 3, 7, 18, 0, 0, 0, time.UTC), time.Date(2026, 10, 31, 18, 0, 0, 0, time.UTC)} {
		now := at
		s := source(t, &change.MemStore{}, func() (time.Time, error) { return now, nil }, "America/New_York", 0)
		s.Plan(t.Context())
		snap, _ := s.Peek(t.Context())
		s.Ack(t.Context(), *snap)
		if age, err := s.Age(t.Context(), *snap); err != nil || age != 0 {
			t.Fatal(age, err)
		}
		now = now.Add(23 * time.Hour)
		if age, err := s.Age(t.Context(), *snap); err != nil || age != 1 {
			t.Fatal(age, err)
		}
		foreign := *snap
		foreign.Hash = "bad"
		if _, err := s.Age(t.Context(), foreign); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
}
func TestAgeRefusesRestrictedOrBackwardClock(t *testing.T) {
	now := testNow
	var blocked bool
	s := source(t, &change.MemStore{}, func() (time.Time, error) {
		if blocked {
			return now, errors.New("restricted")
		}
		return now, nil
	}, "UTC", 0)
	s.Plan(t.Context())
	snap, _ := s.Peek(t.Context())
	blocked = true
	if _, err := s.Age(t.Context(), *snap); !errors.Is(err, ErrClock) {
		t.Fatal(err)
	}
	blocked = false
	now = now.Add(-24 * time.Hour)
	if _, err := s.Age(t.Context(), *snap); !errors.Is(err, ErrClock) {
		t.Fatal(err)
	}
}
func TestCalendarAgeRejectsCancelledObservationAndHandlesFullDateRange(t *testing.T) {
	now := time.Date(2, 1, 1, 12, 0, 0, 0, time.UTC)
	var cancel context.CancelFunc
	s := source(t, &change.MemStore{}, func() (time.Time, error) {
		if cancel != nil {
			cancel()
		}
		return now, nil
	}, "UTC", 0)
	s.Plan(t.Context())
	snap, _ := s.Peek(t.Context())
	now = time.Date(9999, 12, 31, 12, 0, 0, 0, time.UTC)
	age, err := s.Age(t.Context(), *snap)
	if err != nil || age < 3_000_000 {
		t.Fatal("duration overflow", age, err)
	}
	ctx, c := context.WithCancel(t.Context())
	cancel = c
	if _, err := s.Age(ctx, *snap); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
