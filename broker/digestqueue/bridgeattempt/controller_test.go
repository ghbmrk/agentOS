package bridgeattempt

import (
	"context"
	"errors"
	"github.com/ghbmrk/agentos/broker/digestqueue"
	"github.com/ghbmrk/agentos/broker/journal"
	"sync"
	"testing"
	"time"
)

// REQ: CH-2, CH-15, OP-1, OP-2
func TestControllerStartsHeldAndCannotReleaseActiveDispatch(t *testing.T) {
	q, _, b, _, cfg := rig(t, "Fixed notice.")
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.Gate = func(context.Context, digestqueue.Batch) error { close(entered); <-release; return nil }
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(c.Send(t.Context(), b.ID), ErrHeld) {
		t.Fatal("controller starts live")
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Send(t.Context(), b.ID) }()
	<-entered
	if !errors.Is(c.Release(), ErrBusy) {
		t.Fatal("released an active scope")
	}
	c.Hold()
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) && !errors.Is(err, ErrHeld) {
		t.Fatal(err)
	}
	if got := state(t, q, b.ID); got.State != digestqueue.Ready || got.Attempts != 0 {
		t.Fatal(got)
	}
}
func TestControllerQuiesceWaitsForFinishAndStaysHeld(t *testing.T) {
	q, _, b, n, cfg := rig(t, "Fixed notice.")
	entered, release := make(chan struct{}), make(chan struct{})
	n.hook = func() { close(entered); <-release }
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	send := make(chan error, 1)
	go func() { send <- c.Send(t.Context(), b.ID) }()
	<-entered
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	called := false
	if err := c.Quiesce(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if called {
		t.Fatal("cancelled invalidation ran")
	}
	mutated := make(chan struct{})
	finish := make(chan error, 1)
	go func() {
		finish <- c.Quiesce(t.Context(), func(context.Context) error {
			if got := state(t, q, b.ID); got.State != digestqueue.Accepted {
				t.Error("mutation before finish", got)
			}
			close(mutated)
			return nil
		})
	}()
	// Hold is immediate even while the owner ignores cancellation.
	c.Hold()
	if !errors.Is(c.Release(), ErrBusy) {
		t.Fatal("release overlapped send")
	}
	select {
	case <-mutated:
		t.Fatal("invalidation overtook transport")
	default:
	}
	close(release)
	if err := <-send; err != nil {
		t.Fatal(err)
	}
	if err := <-finish; err != nil {
		t.Fatal(err)
	}
	if !c.Held() {
		t.Fatal("invalidation silently released")
	}
}
func TestControllerInvalidationDeadlineRetainsHold(t *testing.T) {
	_, _, b, n, cfg := rig(t, "Fixed notice.")
	entered, release := make(chan struct{}), make(chan struct{})
	n.hook = func() { close(entered); <-release }
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	done := make(chan error, 1)
	go func() { done <- c.Send(t.Context(), b.ID) }()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	called := false
	if err := c.Quiesce(ctx, func(context.Context) error { called = true; return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if called || !c.Held() {
		t.Fatal("deadline allowed mutation/release")
	}
	close(release)
	<-done
}

type containmentEngine struct {
	mu      sync.Mutex
	stopped bool
}

func (e *containmentEngine) Stop(context.Context) (journal.StopReport, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = true
	return journal.StopReport{}, nil
}
func (e *containmentEngine) Resume() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.stopped = false
	return nil
}
func (e *containmentEngine) Stopped() bool          { e.mu.Lock(); defer e.mu.Unlock(); return e.stopped }
func (e *containmentEngine) List() []journal.Status { return nil }
func TestControllerWrappedStopBypassesBlockedPolicyAndResumeDoesNotRelease(t *testing.T) {
	_, _, b, _, cfg := rig(t, "Fixed notice.")
	entered, release := make(chan struct{}), make(chan struct{})
	cfg.Gate = func(context.Context, digestqueue.Batch) error { close(entered); <-release; return nil }
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	raw := &containmentEngine{}
	e, err := c.WrapEngine(raw)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Send(t.Context(), b.ID) }()
	<-entered
	stop := make(chan error, 1)
	go func() { _, err := e.Stop(t.Context()); stop <- err }()
	select {
	case err := <-stop:
		if err != nil || !raw.Stopped() {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("STOP waited for dispatch")
	}
	if err := e.Resume(); err != nil || !c.Held() {
		t.Fatal("engine RESUME released dispatch", err)
	}
	close(release)
	<-done
}

type beginCancelStore struct {
	digestqueue.Store
	saves  int
	cancel context.CancelFunc
}

func (s *beginCancelStore) Save(raw []byte) error {
	s.saves++
	if err := s.Store.Save(raw); err != nil {
		return err
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	return nil
}
func TestCancellationDuringDurableBeginNeverCallsOwner(t *testing.T) {
	q, st, b, n, cfg := rig(t, "Fixed notice.")
	// Reopen using a real queue Store whose next successful Begin save cancels.
	hooked := &beginCancelStore{Store: st}
	var err error
	q, err = digestqueue.New(hooked, digestqueue.Limits{MaxBatches: 8, MaxSources: 8, MaxAttempts: 2, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	hooked.cancel = cancel
	cfg.Queue = q
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Send(ctx, b.ID); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.calls != 0 {
		t.Fatal("cancelled Begin reached owner", n.calls)
	}
	got := state(t, q, b.ID)
	if got.State != digestqueue.Ready || got.Attempts != 1 {
		t.Fatal("local proven-not-sent did not settle", got)
	}
}

type observedWaitContext struct {
	context.Context
	once    sync.Once
	waiting chan struct{}
}

func (c *observedWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}
func TestControllerOldWaiterCannotEnterAfterHoldRelease(t *testing.T) {
	_, _, b, n, cfg := rig(t, "Fixed notice.")
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	c.serial <- struct{}{} // freeze admission before a lease can be registered
	ctx := &observedWaitContext{Context: t.Context(), waiting: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- c.Send(ctx, b.ID) }()
	<-ctx.waiting
	c.Hold()
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	<-c.serial
	if err := <-done; !errors.Is(err, ErrHeld) {
		t.Fatal("stale admission epoch revived", err)
	}
	if n.calls != 0 {
		t.Fatal("old waiter called transport")
	}
	if err := c.Send(t.Context(), b.ID); err != nil || n.calls != 1 {
		t.Fatal("fresh explicit admission failed", err, n.calls)
	}
}
func TestControllerMutationCannotReleaseOrOverlapAnotherMutation(t *testing.T) {
	_, _, _, _, cfg := rig(t, "Fixed notice.")
	c, err := NewController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- c.Quiesce(t.Context(), func(context.Context) error {
			close(entered)
			<-release
			return errors.New("synthetic mutation failure")
		})
	}()
	<-entered
	if !errors.Is(c.Release(), ErrBusy) {
		t.Fatal("released live mutation")
	}
	if err := c.Quiesce(t.Context(), func(context.Context) error { t.Error("overlapping mutation ran"); return nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	c.Hold()
	close(release)
	if err := <-done; err == nil || !c.Held() {
		t.Fatal("mutation failure cleared hold", err)
	}
}
