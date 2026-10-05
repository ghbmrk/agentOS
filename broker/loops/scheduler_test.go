package loops

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/meter"
)

// REQ: LOOP-1, LOOP-2, LOOP-3, RES-1
//
// The scheduler runs loop work only in spare capacity, yields to
// foreground work within the preemption target, keeps loop model use
// inside its own budget, and shares spare time by measured return,
// sleeping when nothing is worth doing.

// source is a fake loop: queue units of work, each worth value and taking
// took of compute time. A blocking unit waits for its context and is then
// offered again.
type source struct {
	loop  Loop
	clk   *clock
	mu    sync.Mutex
	queue int // -1: endless
	value float64
	took  time.Duration
	model bool
	// block makes the next unit wait for cancellation; stubborn makes it
	// ignore cancellation for that long.
	block    bool
	stubborn time.Duration
	started  chan struct{}
	runs     int
	asked    int
}

func (s *source) Loop() Loop { return s.loop }

func (s *source) Next(_ context.Context, modelOK bool) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.asked++
	if s.queue == 0 || (s.model && !modelOK) {
		return Job{}, false
	}
	return Job{Name: "unit", UsesModel: s.model, Run: func(ctx context.Context) Result {
		s.mu.Lock()
		s.runs++
		block, stubborn, started := s.block, s.stubborn, s.started
		s.mu.Unlock()
		if started != nil {
			started <- struct{}{}
		}
		if stubborn > 0 {
			time.Sleep(stubborn)
			return Result{}
		}
		if block {
			<-ctx.Done()
			return Result{Err: ctx.Err()} // still queued: offered again
		}
		s.clk.add(s.took)
		s.mu.Lock()
		if s.queue > 0 {
			s.queue--
		}
		s.mu.Unlock()
		return Result{Value: s.value}
	}}, true
}

func (s *source) count() int { s.mu.Lock(); defer s.mu.Unlock(); return s.runs }

func TestLoopWorkRunsOnlyInSpareCapacity(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Improve, clk: r.clk, queue: -1, value: 1}
	busy, stopped := false, false
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: []Source{src}, Now: r.clk.now,
		Busy: func() bool { return busy }, Stopped: func() bool { return stopped }})
	must(t, err)
	busy = true
	if ran, wait := s.Tick(context.Background()); ran || wait != time.Minute {
		t.Fatalf("ran while foreground work needs the box (%v, %v)", ran, wait)
	}
	busy, stopped = false, true
	if ran, _ := s.Tick(context.Background()); ran {
		t.Fatal("ran during STOP")
	}
	stopped = false
	if ran, _ := s.Tick(context.Background()); !ran || src.count() != 1 {
		t.Fatal("did not run on an idle box")
	}
}

func TestForegroundPreemptsLoopWorkWithinTheTarget(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Improve, clk: r.clk, queue: 1, value: 2, block: true, started: make(chan struct{}, 1)}
	r.restart(src)
	done := make(chan struct{})
	go func() { r.s.Tick(context.Background()); close(done) }()
	<-src.started
	start := time.Now()
	if err := r.s.Preempt(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("yield took %v, target 200ms", d)
	}
	<-done
	if sh := r.s.Share()[Improve]; sh != 1 {
		t.Fatalf("a preempted unit was measured: share %v", sh)
	}
	// The unit is offered again once the box is spare.
	src.mu.Lock()
	src.block, src.started = false, nil
	src.mu.Unlock()
	if ran, _ := r.s.Tick(context.Background()); !ran || src.count() != 2 {
		t.Fatalf("preempted work not re-run (runs %d)", src.count())
	}
}

func TestSlowYieldIsReported(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Secure, clk: r.clk, queue: 1, stubborn: 3 * time.Second, started: make(chan struct{}, 1)}
	r.restart(src)
	go r.s.Tick(context.Background())
	<-src.started
	start := time.Now()
	err := r.s.Preempt()
	if !errors.Is(err, ErrSlowYield) {
		t.Fatalf("Preempt = %v, want ErrSlowYield", err)
	}
	// Preempt gave up at the target, long before the stubborn work
	// returned; the bound leaves room for a loaded -race run.
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Preempt waited %v; target 200ms, the work runs 3s", d)
	}
}

func TestSpareTimeFollowsMeasuredReturn(t *testing.T) {
	r := newRig(t)
	good := &source{loop: Improve, clk: r.clk, queue: -1, value: 4, took: 10 * time.Second}
	dry := &source{loop: Secure, clk: r.clk, queue: -1, value: 0, took: 10 * time.Second}
	r.restart(good, dry)
	for i := 0; i < 30; i++ {
		if ran, _ := r.s.Tick(context.Background()); !ran {
			t.Fatalf("tick %d ran nothing", i)
		}
	}
	if good.count() < 25 || dry.count() > 4 {
		t.Fatalf("runs: valuable loop %d, dry loop %d", good.count(), dry.count())
	}
	if sh := r.s.Share(); sh[Secure] > 0.05 || sh[Improve] != 1 {
		t.Fatalf("shares %v: the dry loop should get the least", sh)
	}
}

func TestALoopWithNoValueIsParkedAndLookedAtLater(t *testing.T) {
	r := newRig(t)
	dry := &source{loop: Secure, clk: r.clk, queue: -1, value: 0, took: time.Second}
	r.restart(dry)
	for i := 0; i < 3; i++ {
		if ran, _ := r.s.Tick(context.Background()); !ran {
			t.Fatalf("run %d did not happen", i)
		}
	}
	if ran, wait := r.s.Tick(context.Background()); ran || wait != time.Hour || r.s.Share()[Secure] != 0 {
		t.Fatalf("after 3 runs with no value: ran %v, wait %v, share %v", ran, wait, r.s.Share())
	}
	r.clk.add(25 * time.Hour)
	if ran, _ := r.s.Tick(context.Background()); !ran {
		t.Fatal("parked loop never looked at again")
	}
}

func TestNothingWorthwhileSleepsUntilWoken(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Improve, clk: r.clk, queue: 0, value: 1}
	r.restart(src)
	if ran, wait := r.s.Tick(context.Background()); ran || wait != time.Hour {
		t.Fatalf("Tick = %v, %v; want sleep for Idle", ran, wait)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.s.Run(ctx)
	time.Sleep(20 * time.Millisecond)
	asked := func() int { src.mu.Lock(); defer src.mu.Unlock(); return src.asked }
	n := asked()
	time.Sleep(50 * time.Millisecond)
	if asked() != n {
		t.Fatal("a sleeping scheduler kept polling")
	}
	src.mu.Lock()
	src.queue = 1
	src.mu.Unlock()
	r.s.Wake()
	deadline := time.Now().Add(2 * time.Second)
	for src.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if src.count() != 1 {
		t.Fatal("Wake did not start new work")
	}
}

func TestSpareBudgetIsNeverExceeded(t *testing.T) {
	r := newRig(t)
	modelWork := &source{loop: Improve, clk: r.clk, queue: -1, value: 1, model: true}
	localWork := &source{loop: Secure, clk: r.clk, queue: -1, value: 1}
	r.restart(modelWork, localWork)
	req, _ := ParseText("spare budget 2")
	must(t, r.s.Set(context.Background(), req))
	// Two replay calls use the budget up; the third is refused by the
	// spare meter itself, whoever makes it.
	for i := 0; i < 2; i++ {
		c, err := r.spare.Start("eval-1", 10, 10)
		must(t, err)
		c.Done(20)
	}
	if _, err := r.spare.Start("eval-2", 10, 10); !errors.Is(err, meter.ErrExhausted) {
		t.Fatalf("call past the spare budget: %v", err)
	}
	for i := 0; i < 5; i++ {
		r.s.Tick(context.Background())
	}
	if modelWork.count() != 0 || localWork.count() == 0 {
		t.Fatalf("with no budget: model work ran %d, local work %d", modelWork.count(), localWork.count())
	}
	if d := strings.Join(r.s.Digest(), "\n"); !strings.Contains(d, "Spare-time AI use, last 24 hours: 2 of 2 calls") {
		t.Fatalf("digest does not show spare use: %q", d)
	}
}

func TestTurningALoopOffStopsItsWork(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Improve, clk: r.clk, queue: 1, block: true, started: make(chan struct{}, 1)}
	other := &source{loop: Maintain, clk: r.clk, queue: -1, value: 1}
	r.restart(src, other)
	done := make(chan struct{})
	go func() { r.s.Tick(context.Background()); close(done) }()
	<-src.started
	req, _ := ParseText("LOOP 1 OFF")
	must(t, r.s.Set(context.Background(), req))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("LOOP 1 OFF did not stop running loop 1 work")
	}
	r.s.Tick(context.Background())
	if src.count() != 1 || other.count() != 1 {
		t.Fatalf("after LOOP 1 OFF: loop 1 runs %d, loop 3 runs %d", src.count(), other.count())
	}
	req, _ = ParseText("LOOPS OFF")
	must(t, r.s.Set(context.Background(), req))
	if ran, _ := r.s.Tick(context.Background()); ran {
		t.Fatal("work ran with every loop off")
	}
	if d := r.s.Digest(); len(d) == 0 || d[0] != "Spare-time work is off. Reply LOOPS ON to restart it." {
		t.Fatalf("digest %q", d)
	}
}

func TestWorkYieldsWhenTheBoxGetsBusyEvenWithoutPreempt(t *testing.T) {
	r := newRig(t)
	src := &source{loop: Improve, clk: r.clk, queue: 1, block: true, started: make(chan struct{}, 1)}
	var mu sync.Mutex
	busy := false
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: []Source{src}, Now: r.clk.now,
		Poll: 10 * time.Millisecond, Busy: func() bool { mu.Lock(); defer mu.Unlock(); return busy }})
	must(t, err)
	done := make(chan struct{})
	go func() { s.Tick(context.Background()); close(done) }()
	<-src.started
	mu.Lock()
	busy = true
	mu.Unlock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("work did not yield when foreground work arrived")
	}
	if s.Share()[Improve] != 1 {
		t.Fatal("yielded work was measured")
	}
}
