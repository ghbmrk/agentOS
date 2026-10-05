package loops

import (
	"context"
	"errors"
	"strings"
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

// PE5 (arbitrator; security P2, P5): the scheduler tells the change
// pipeline why it preempted. STOP (change.ErrOwnerStop), and the owner's
// work arriving while memory pressure is within its limit
// (change.ErrOwnerWork), are the owner's, so they do not count against a
// candidate. Accepted work that is not the owner's (a loop's or a replay's
// machine) is a cause a candidate might drive and counts, as does
// pressure, which wins when both hold; all are read in one BusyCause call.
// With only Busy configured, every busy preemption counts.
func TestPreemptionCarriesItsCause(t *testing.T) {
	for _, tc := range []struct {
		name                        string
		stop, busy, owner, pressure bool
		busyOnly                    bool
		want                        error
	}{
		{name: "STOP", stop: true, want: change.ErrOwnerStop},
		{name: "owner's work", busy: true, owner: true, want: change.ErrOwnerWork},
		{name: "accepted work not the owner's", busy: true},
		{name: "pressure", busy: true, owner: true, pressure: true, want: change.ErrPressurePreempt},
		{name: "STOP under pressure", stop: true, busy: true, pressure: true, want: change.ErrPressurePreempt},
		{name: "busy, cause unknown", busy: true, busyOnly: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			src := &causeSource{started: make(chan struct{}, 1)}
			var mu sync.Mutex
			on := false
			read := func() (stop, busy, owner, pressure bool) {
				mu.Lock()
				defer mu.Unlock()
				return on && tc.stop, on && tc.busy, on && tc.owner, on && tc.pressure
			}
			cfg := Config{Store: r.store, Spare: r.spare, Sources: []Source{src}, Now: r.clk.now, Poll: 10 * time.Millisecond,
				Stopped: func() bool { s, _, _, _ := read(); return s }}
			if tc.busyOnly {
				cfg.Busy = func() bool { _, b, _, _ := read(); return b }
			} else {
				cfg.BusyCause = func() (bool, bool, bool) { _, b, o, p := read(); return b, o, p }
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
			if !errors.Is(tc.want, change.ErrOwnerPreempt) && owner {
				t.Fatal("a cut a candidate could drive was marked the owner's")
			}
		})
	}
}

// parkSource offers one unit per Next. While the pipeline would park it,
// the unit returns change.ErrParked unless its context marks the
// evaluator idle.
type parkSource struct {
	loop   Loop
	parked bool
	left   int // units to offer; -1 without end
	log    *[]string
	mu     *sync.Mutex
}

func (p *parkSource) Loop() Loop { return p.loop }
func (p *parkSource) Next(context.Context, bool) (Job, bool) {
	if p.left == 0 {
		return Job{}, false
	}
	if p.left > 0 {
		p.left--
	}
	return Job{Name: "unit", Evaluates: true, Run: func(ctx context.Context) Result {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.parked && !change.IsIdle(ctx) {
			*p.log = append(*p.log, string(p.loop)+" parked")
			return Result{Err: change.ErrParked}
		}
		if change.IsIdle(ctx) {
			*p.log = append(*p.log, string(p.loop)+" idle")
		} else {
			*p.log = append(*p.log, string(p.loop)+" ran")
		}
		return Result{Value: 1}
	}}, true
}

// PE5, security P4: a parked candidate yields the evaluator. Its loop goes
// to the back of the order, other work (Loop 3's releases included) runs
// first, and the parked unit runs only in a pass where nothing else
// wanted the evaluator, with the context marked idle.
func TestParkedCandidateWaitsForAnIdleEvaluator(t *testing.T) {
	r := newRig(t)
	var mu sync.Mutex
	var log []string
	improve := &parkSource{loop: Improve, parked: true, left: -1, log: &log, mu: &mu}
	release := &parkSource{loop: Maintain, left: 2, log: &log, mu: &mu}
	s, err := New(Config{Store: r.store, Spare: r.spare, Sources: []Source{improve, release}, Now: r.clk.now})
	must(t, err)
	for i := 0; i < 3; i++ {
		s.Tick(context.Background())
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"improve parked", "maintain ran", "maintain ran", "improve parked", "improve idle"}
	if strings.Join(log, ", ") != strings.Join(want, ", ") {
		t.Fatalf("order %q, want %q", log, want)
	}
}
