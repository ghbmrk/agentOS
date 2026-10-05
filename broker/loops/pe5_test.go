package loops

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: LOOP-1, RES-1, CHG-1

// causeSource runs one unit that waits for its preemption and records the
// cause its context was cancelled with.
type causeSource struct {
	started chan struct{}
	mu      sync.Mutex
	cause   error
}

func (c *causeSource) Loop() Loop { return Improve }
func (c *causeSource) Next(context.Context, bool) (Job, bool) {
	return Job{Name: "unit", Evaluates: true, Run: func(ctx context.Context) Result {
		c.started <- struct{}{}
		<-ctx.Done()
		c.mu.Lock()
		c.cause = context.Cause(ctx)
		c.mu.Unlock()
		return Result{Err: ctx.Err()}
	}}, true
}

// PE5 (arbitrator): the scheduler tells the change pipeline why it
// preempted. STOP, and the owner's work arriving while memory pressure is
// within its limit, are the owner's (change.ErrOwnerPreempt), so they do
// not count against a candidate; pressure is a cause a candidate can
// drive and wins when both hold, read in one BusyCause call; with only
// Busy configured, every busy preemption counts.
func TestPreemptionCarriesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		stop, busy, pressure bool
		busyOnly             bool
		want                 error
	}{
		{name: "STOP", stop: true, want: change.ErrOwnerPreempt},
		{name: "owner's work", busy: true, want: change.ErrOwnerPreempt},
		{name: "pressure", busy: true, pressure: true, want: change.ErrPressurePreempt},
		{name: "STOP under pressure", stop: true, busy: true, pressure: true, want: change.ErrPressurePreempt},
		{name: "busy, cause unknown", busy: true, busyOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			src := &causeSource{started: make(chan struct{}, 1)}
			var mu sync.Mutex
			on := false
			read := func() (bool, bool, bool) {
				mu.Lock()
				defer mu.Unlock()
				return on && tc.stop, on && tc.busy, on && tc.pressure
			}
			cfg := Config{Store: r.store, Spare: r.spare, Sources: []Source{src}, Now: r.clk.now, Poll: 10 * time.Millisecond,
				Stopped: func() bool { s, _, _ := read(); return s }}
			if tc.busyOnly {
				cfg.Busy = func() bool { _, b, _ := read(); return b }
			} else {
				cfg.BusyCause = func() (bool, bool) { _, b, p := read(); return b, p }
			}
			s, err := New(cfg)
			must(t, err)
			done := make(chan struct{})
			go func() { s.Tick(context.Background()); close(done) }()
			<-src.started
			mu.Lock()
			on = true
			mu.Unlock()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("work did not yield")
			}
			src.mu.Lock()
			defer src.mu.Unlock()
			owner := errors.Is(src.cause, change.ErrOwnerPreempt)
			switch {
			case tc.want == nil && owner, tc.want != nil && !errors.Is(src.cause, tc.want):
				t.Fatalf("cause %v, want %v", src.cause, tc.want)
			}
			if tc.want != change.ErrOwnerPreempt && owner {
				t.Fatal("a cut a candidate could drive was marked the owner's")
			}
		})
	}
}
