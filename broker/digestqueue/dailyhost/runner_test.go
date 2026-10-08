package dailyhost

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/digestqueue/daily"
	"sync"
	"testing"
	"time"
)

func await(t *testing.T, h *Host, fn func(Status) bool) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if fn(h.Status()) {
			return
		}
		select {
		case <-deadline:
			t.Fatal("status did not progress", h.Status())
		case <-ticker.C:
		}
	}
}
func fakeTicks(h *Host) (chan time.Time, *bool) {
	ticks := make(chan time.Time, 1)
	stopped := new(bool)
	h.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() { *stopped = true } }
	return ticks, stopped
}

// REQ: CH-15, TIM-1, OP-1, OP-2
func TestRunnerDoesNotActivateAndOwnsOneCadence(t *testing.T) {
	r := setup(t)
	ticks, stopped := fakeTicks(r.h)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.h.Run(ctx) }()
	await(t, r.h, func(s Status) bool { return s.Steps == 1 && s.Running })
	if r.m.count() != 0 || !r.h.Status().Held {
		t.Fatal(r.h.Status())
	}
	if err := r.h.Run(t.Context()); !errors.Is(err, ErrRunning) {
		t.Fatal(err)
	}
	if err := r.h.Activate(); err != nil {
		t.Fatal(err)
	}
	ticks <- r.now
	await(t, r.h, func(s Status) bool { return s.Steps == 2 })
	if r.m.count() != 1 {
		t.Fatal(r.m.count())
	}
	ticks <- r.now
	await(t, r.h, func(s Status) bool { return s.Steps == 3 })
	if r.m.count() != 1 {
		t.Fatal("same-day cadence resent", r.m.count())
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !*stopped || r.h.Status().Running || !r.h.Status().Held {
		t.Fatal(r.h.Status())
	}
}

// REQ: CH-2, OP-1
func TestRunnerCancellationReachesActualOwnerContextTransport(t *testing.T) {
	r := setup(t)
	entered := make(chan struct{})
	r.m.hook = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	r.h.Activate()
	_, stopped := fakeTicks(r.h)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.h.Run(ctx) }()
	<-entered
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !*stopped || !r.h.Status().Held || r.m.count() != 1 {
		t.Fatal(r.h.Status())
	}
	// Ordinary cancellation cannot prove non-handoff; the same batch remains
	// Unknown even after fresh trusted activation.
	r.m.hook = nil
	r.h.Activate()
	if _, err := r.h.Step(t.Context()); !errors.Is(err, daily.ErrUncertain) {
		t.Fatal(err)
	}
	if r.m.count() != 1 {
		t.Fatal("unknown retried")
	}
}
func TestRunnerDeadlineDoesNotSpawnOverlappingTransport(t *testing.T) {
	r := setup(t)
	r.h.cfg.StepTimeout = 20 * time.Millisecond
	entered := make(chan struct{})
	r.m.hook = func(ctx context.Context) error { close(entered); <-ctx.Done(); return ctx.Err() }
	r.h.Activate()
	ticks, _ := fakeTicks(r.h)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.h.Run(ctx) }()
	<-entered
	await(t, r.h, func(s Status) bool { return s.Steps == 1 && s.Code == Deadline })
	ticks <- r.now
	await(t, r.h, func(s Status) bool { return s.Steps == 2 && s.Code == Uncertain })
	if r.m.count() != 1 {
		t.Fatal(r.m.count())
	}
	cancel()
	<-done
}
func TestClosedCadenceAndAlreadyCancelledRunStayHeld(t *testing.T) {
	r := setup(t)
	ticks, stopped := fakeTicks(r.h)
	close(ticks)
	if err := r.h.Run(t.Context()); !errors.Is(err, ErrTicker) {
		t.Fatal(err)
	}
	if !*stopped || !r.h.Status().Held || r.h.Status().Running {
		t.Fatal(r.h.Status())
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := r.h.Status()
	if err := r.h.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if r.h.Status() != before {
		t.Fatal("cancelled runner changed state")
	}
}

type checkingEngine struct {
	*engine
	entered, release chan struct{}
	once             sync.Once
}

func (e *checkingEngine) Stopped() bool {
	e.once.Do(func() { close(e.entered); <-e.release })
	return e.engine.Stopped()
}

// REQ: CH-2
func TestStopGenerationInvalidatesAnEarlierHostActivation(t *testing.T) {
	r := setup(t)
	e := &checkingEngine{engine: r.e, entered: make(chan struct{}), release: make(chan struct{})}
	r.cfg.Owner.Engine = e
	h, err := New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.Activate() }()
	<-e.entered
	if err := h.Channel().LocalStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	r.e.Resume()
	close(e.release)
	if err := <-done; !errors.Is(err, daily.ErrHeld) {
		t.Fatal("stale activation survived STOP/resume", err)
	}
	if !h.Status().Held || r.m.count() != 0 {
		t.Fatal(h.Status())
	}
}
func TestHostQuiescenceRefusesActivationAndStaysHeld(t *testing.T) {
	r := setup(t)
	r.h.Activate()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- r.h.Quiesce(t.Context(), func(context.Context) error { close(entered); <-release; return nil })
	}()
	<-entered
	if err := r.h.Activate(); !errors.Is(err, daily.ErrBusy) {
		t.Fatal(err)
	}
	if err := r.h.Quiesce(t.Context(), func(context.Context) error { t.Fatal("overlapping mutation"); return nil }); !errors.Is(err, daily.ErrBusy) {
		t.Fatal(err)
	}
	if !r.h.Status().Held {
		t.Fatal(r.h.Status())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := r.h.Step(t.Context()); !errors.Is(err, daily.ErrHeld) {
		t.Fatal(err)
	}
}
