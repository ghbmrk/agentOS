package bridgeattempt

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"testing"
	"time"
)

// REQ: CH-15, OP-1, OP-2
func TestPolicyRefusalAfterBeginNeverCallsOwnerOrReservesTwice(t *testing.T) {
	_, store, b, n, cfg := rig(t, "Fixed notice.")
	wrapped := &eligibilityBeginStore{Store: store}
	q, err := digestqueue.New(wrapped, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Queue = q
	quiet := false
	wrapped.hook = func() { quiet = true }
	gates, rechecks := 0, 0
	refused := errors.New("quiet hours began during save")
	cfg.Gate = func(context.Context, digestqueue.Batch) error { gates++; return nil }
	cfg.Recheck = func(context.Context, digestqueue.Batch) error {
		rechecks++
		if quiet {
			return refused
		}
		return nil
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(t.Context(), b.ID); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	got := state(t, q, b.ID)
	if n.calls != 0 || gates != 1 || rechecks != 1 || got.State != digestqueue.Ready || got.Attempts != 1 {
		t.Fatal(n.calls, gates, rechecks, got)
	}
}
func TestCancellationDuringFinalClockObservationNeverCallsOwner(t *testing.T) {
	q, _, b, n, cfg := rig(t, "Fixed notice.")
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	reads := 0
	cfg.Now = func() time.Time {
		reads++
		if reads == 3 {
			cancel()
		}
		return now
	}
	cfg.Recheck = func(context.Context, digestqueue.Batch) error { return nil }
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.calls != 0 || state(t, q, b.ID).State != digestqueue.Ready {
		t.Fatal(n.calls, state(t, q, b.ID))
	}
}
