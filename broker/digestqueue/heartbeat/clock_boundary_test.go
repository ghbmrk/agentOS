package heartbeat

import (
	"bytes"
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/change"
	"testing"
	"time"
)

// REQ: TIM-1, CH-15, OP-1
func TestZeroClockCannotStageOrExposeAliveSnapshot(t *testing.T) {
	store := &change.MemStore{}
	s := source(t, store, func() (time.Time, error) { return time.Time{}, nil }, "UTC", 0)
	before, _ := store.Load()
	if err := s.Plan(t.Context()); err != ErrClock {
		t.Fatal("uninitialized clock staged heartbeat", err)
	}
	if snap, err := s.Peek(t.Context()); err != ErrClock || snap != nil {
		t.Fatal(snap, err)
	}
	after, _ := store.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("invalid clock mutated ledger")
	}
}
func TestCancelledClockObservationCannotStageOrExposeHeartbeat(t *testing.T) {
	for _, operation := range []string{"plan", "peek", "validate"} {
		t.Run(operation, func(t *testing.T) {
			store := &change.MemStore{}
			var cancel context.CancelFunc
			clock := func() (time.Time, error) {
				if cancel != nil {
					cancel()
				}
				return testNow, nil
			}
			s := source(t, store, clock, "UTC", 0)
			if operation != "plan" {
				if err := s.Plan(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			snap, _ := s.Peek(t.Context())
			before, _ := store.Load()
			ctx, stop := context.WithCancel(t.Context())
			defer stop()
			cancel = stop
			switch operation {
			case "plan":
				if err := s.Plan(ctx); !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled clock observation staged", err)
				}
			case "peek":
				if got, err := s.Peek(ctx); !errors.Is(err, context.Canceled) || got != nil {
					t.Fatal("cancelled observation published", got, err)
				}
			case "validate":
				if err := s.Validate(ctx, *snap); !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled observation validated", err)
				}
			}
			after, _ := store.Load()
			if !bytes.Equal(before, after) {
				t.Fatal("cancelled observation wrote store")
			}
		})
	}
}
