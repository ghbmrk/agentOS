package daily

import (
	"errors"
	dq "github.com/ghbmrk/agentos/broker/digestqueue"
	"testing"
	"time"
)

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestMaintenanceRetainsCurrentIdentityAndAllowsBoundedDailyProgress(t *testing.T) {
	f := setup(t)
	f.now = f.now.Add(time.Hour)
	f.w.Activate()
	first, err := f.w.Step(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n, err := f.w.Maintain(t.Context(), 1); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	again, err := f.w.Step(t.Context())
	if err != nil || again != first || f.r.calls != 1 {
		t.Fatal(again, err)
	}
	f.now = f.now.Add(24 * time.Hour)
	if n, err := f.w.Maintain(t.Context(), 2); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if n, err := f.w.Maintain(t.Context(), 1); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	f.open(t)
	f.w.Activate()
	if _, err := f.q.Get(first); !errors.Is(err, dq.ErrMissing) {
		t.Fatal(err)
	}
	second, err := f.w.Step(t.Context())
	if err != nil || second <= first || f.r.calls != 2 {
		t.Fatal(second, err)
	}
	for i := 0; i < 40; i++ {
		f.now = f.now.Add(24 * time.Hour)
		if n, err := f.w.Maintain(t.Context(), 1); err != nil || n != 1 {
			t.Fatal(n, err)
		}
		if _, err := f.w.Step(t.Context()); err != nil {
			t.Fatal("retention exhausted", i, err)
		}
	}
	batches, err := f.q.List()
	if err != nil || len(batches) != 1 {
		t.Fatal(batches, err)
	}
}
func TestMaintenanceNeverHidesUnknownOrUndeliveredDailyOutcomes(t *testing.T) {
	for _, state := range []dq.State{dq.Unknown, dq.Ready, dq.Expired} {
		t.Run(string(state), func(t *testing.T) {
			f := setup(t)
			f.now = f.now.Add(time.Hour)
			f.w.Activate()
			if state == dq.Unknown {
				f.r.err = errors.New("synthetic uncertain transport")
			} else {
				f.gateErr = errors.New("policy held")
			}
			id, _ := f.w.Step(t.Context())
			f.now = f.now.Add(24 * time.Hour)
			if state == dq.Expired {
				if err := f.q.Expire(f.now); err != nil {
					t.Fatal(err)
				}
			}
			if n, err := f.w.Maintain(t.Context(), 1); err != nil || n != 0 {
				t.Fatal(n, err)
			}
			b, err := f.q.Get(id)
			if err != nil || b.State != state {
				t.Fatal(b, err)
			}
		})
	}
}
func TestMaintenanceRefusesHeldCancelledAndInvalidPolicy(t *testing.T) {
	f := setup(t)
	if _, err := f.w.Maintain(t.Context(), 1); !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	f.w.Activate()
	if _, err := f.w.Maintain(t.Context(), 0); !errors.Is(err, dq.ErrInvalid) {
		t.Fatal(err)
	}
}
