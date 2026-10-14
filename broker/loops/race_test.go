package loops

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
)

// REQ: LOOP-2, LOOP-1
//
// LOOPS OFF stops work the scheduler picked before OFF applied, and a
// run's watcher acts only on its own run (#1236).

// script is a source that hands out the jobs it holds, one per Next.
type script struct {
	loop   Loop
	picked chan struct{} // signalled when Next picks, if set
	hold   chan struct{} // Next waits on it after picking, if set
	jobs   []Job
}

func (s *script) Loop() Loop { return s.loop }

func (s *script) Next(context.Context, bool) (Job, bool) {
	if len(s.jobs) == 0 {
		return Job{}, false
	}
	j := s.jobs[0]
	s.jobs = s.jobs[1:]
	if s.picked != nil {
		s.picked <- struct{}{}
	}
	if s.hold != nil {
		<-s.hold
	}
	return j, true
}

func TestLoopsOffStopsWorkPickedBeforeIt(t *testing.T) {
	r := newRig(t)
	var ran atomic.Bool
	var cause atomic.Value
	src := &script{loop: Improve, picked: make(chan struct{}, 1), hold: make(chan struct{}),
		jobs: []Job{{Name: "picked", Run: func(ctx context.Context) Result {
			if ctx.Err() != nil {
				cause.Store(context.Cause(ctx))
				return Result{Err: context.Cause(ctx)}
			}
			ran.Store(true)
			return Result{Value: 1}
		}}}}
	r.restart(src)
	done := make(chan struct{})
	go func() { r.s.Tick(context.Background()); close(done) }()
	<-src.picked // tick read the settings (on) and picked the job
	req, _ := ParseText("LOOPS OFF")
	must(t, r.s.Set(context.Background(), req))
	close(src.hold)
	<-done
	if ran.Load() {
		t.Fatal("work picked before LOOPS OFF ran after it applied")
	}
	if c, _ := cause.Load().(error); !errors.Is(c, change.ErrOwnerStop) {
		t.Fatalf("picked work cancelled with %v, want the owner's stop", c)
	}
	r.s.mu.Lock()
	runs := r.s.loops[Improve].runs
	r.s.mu.Unlock()
	if runs != 0 {
		t.Fatalf("cancelled work was measured (%d runs)", runs)
	}
}

func TestStaleWatcherLeavesTheNextRunAlone(t *testing.T) {
	r := newRig(t)
	var armed atomic.Bool
	held, release, caused := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	busy := func() bool {
		if armed.CompareAndSwap(true, false) {
			close(held) // job A's watcher is reading Busy
			<-release
			return true
		}
		return false
	}
	busyCause := func() (bool, bool, bool) {
		select {
		case caused <- struct{}{}:
		default:
		}
		return false, false, false
	}
	started, finish := make(chan struct{}), make(chan struct{})
	var cancelled atomic.Bool
	src := &script{loop: Improve, jobs: []Job{
		{Name: "a", Run: func(context.Context) Result {
			armed.Store(true)
			<-held // A ends while its watcher is still in Busy
			return Result{Value: 1}
		}},
		{Name: "b", Run: func(ctx context.Context) Result {
			close(started)
			<-finish
			if ctx.Err() != nil {
				cancelled.Store(true)
				return Result{Err: context.Cause(ctx)}
			}
			return Result{Value: 1}
		}},
	}}
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: []Source{src}, Now: r.clk.now,
		Busy: busy, BusyCause: busyCause, Poll: time.Millisecond,
		YieldTarget: 200 * time.Millisecond, Idle: time.Hour, Retry: time.Minute})
	must(t, err)
	if ran, _ := s.Tick(context.Background()); !ran {
		t.Fatal("job A did not run")
	}
	done := make(chan struct{})
	go func() { s.Tick(context.Background()); close(done) }()
	<-started
	close(release) // A's watcher now sees the box busy
	<-caused       // and asks why: only a watcher acting on a cancel does
	s.mu.Lock()    // its cancel runs under mu
	s.mu.Unlock()
	close(finish)
	<-done
	if cancelled.Load() {
		t.Fatal("job A's watcher cancelled job B")
	}
	s.mu.Lock()
	runs := s.loops[Improve].runs
	s.mu.Unlock()
	if runs != 2 {
		t.Fatalf("job B marked preempted: %d runs measured, want 2", runs)
	}
}
