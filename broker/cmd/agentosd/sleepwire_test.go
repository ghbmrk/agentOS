package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-1, LOOP-1

// unitSource offers one job, recording whether the agent slept under it.
type unitSource struct {
	evaluates bool
	ran       *bool
	asleep    func() bool
	sawAsleep *bool
}

func (u unitSource) Loop() loops.Loop { return loops.Improve }
func (u unitSource) Digest() []string { return []string{"a digest line"} }
func (u unitSource) Next(context.Context, bool) (loops.Job, bool) {
	return loops.Job{Name: "unit", Evaluates: u.evaluates, Run: func(context.Context) loops.Result {
		*u.ran, *u.sawAsleep = true, u.asleep()
		return loops.Result{Value: 1}
	}}, true
}

// PE7: an evaluating unit runs with the agent asleep and wakes it when it
// ends; one that cannot sleep does not run and is offered again (an
// interruption); other work and the digest are unchanged.
func TestEvaluatingWorkRunsWithTheAgentAsleep(t *testing.T) {
	r := newSleepRig(t)
	var p atomic.Pointer[sleeper]
	p.Store(r.s)
	var ran, saw bool
	src := sleepSource{unitSource{evaluates: true, ran: &ran, asleep: r.s.Asleep, sawAsleep: &saw}, &p}
	if d := src.Digest(); len(d) != 1 {
		t.Fatalf("digest %q", d)
	}
	job, _ := src.Next(context.Background(), true)
	if res := job.Run(context.Background()); res.Err != nil || !ran || !saw {
		t.Fatalf("ran %v asleep %v: %v", ran, saw, res.Err)
	}
	if r.s.Asleep() || r.last().Cause != wakeUnit {
		t.Fatalf("not woken when the unit ended: %+v", r.last())
	}

	ran = false
	r.set(func() { r.now = time.Date(2026, 10, 6, 14, 0, 0, 0, time.Local) })
	job, _ = src.Next(context.Background(), true)
	if res := job.Run(context.Background()); !errors.Is(res.Err, change.ErrInterrupted) || ran {
		t.Fatalf("a unit ran in the day: ran %v, %v", ran, res.Err)
	}

	src = sleepSource{unitSource{ran: &ran, asleep: r.s.Asleep, sawAsleep: &saw}, &p}
	job, _ = src.Next(context.Background(), true)
	if res := job.Run(context.Background()); res.Err != nil || !ran || saw {
		t.Fatalf("other work: ran %v asleep %v: %v", ran, saw, res.Err)
	}
}

// PE7 (conditions 6, 7; UX P2-b): a wake cuts the evaluator's run at once
// as the owner's interruption, which PE5 exempts; the scheduler's own
// cancel passes through unchanged.
func TestWakeCutsTheEvaluatorRunAsTheOwners(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	started := make(chan struct{})
	go func() { <-started; r.s.Wake(wakeOwner) }()
	_, err := sleepGuard(context.Background(), r.s, func(ctx context.Context) ([]byte, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if !errors.Is(err, change.ErrOwnerWork) || !errors.Is(err, change.ErrInterrupted) {
		t.Fatalf("cut %v: want the owner's interruption", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = sleepGuard(ctx, r.s, func(ctx context.Context) ([]byte, error) { return nil, ctx.Err() })
	if errors.Is(err, change.ErrOwnerPreempt) {
		t.Fatalf("the scheduler's cancel read as the owner's: %v", err)
	}
}

// PE7 (conditions 1, 7): on a sleep-mode box loop work waits while the
// agent is awake and may not sleep, and that busy is the owner's, with
// pressure still winning; asleep, admission alone decides.
func TestSleepModeBusyIsTheOwners(t *testing.T) {
	r := newSleepRig(t)
	var l learning
	c, err := admission.New(admission.Config{CapacityMB: 4000, HeadroomMB: 500}, yield{})
	must(t, err)
	l.adm.Store(c)
	l.sleep.Store(r.s)
	if b, o, p := l.busyCause(); b || o || p || l.busy() {
		t.Fatalf("idle night: %v %v %v", b, o, p)
	}
	r.set(func() { r.owner = r.now })
	if b, o, _ := l.busyCause(); !b || !o || !l.busy() {
		t.Fatalf("owner recent: busy %v owner %v", b, o)
	}
	r.set(func() { r.owner = r.now.Add(-time.Hour) })
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.owner = r.now })
	if b, _, _ := l.busyCause(); b {
		t.Fatal("asleep: the sleeper held the box")
	}
}

// PE7: the keeper does not restart an agent its sleeper stopped, and
// STATUS says it sleeps; once awake, the keeper keeps it running again.
func TestKeeperLeavesASleepingAgent(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	f := &fakeMachines{m: map[string]vm.Machine{"agent": {ID: "agent", Spec: testSpec, State: vm.Stopped}}}
	k := &keeper{m: f, id: "agent", spec: testSpec, sleep: r.s}
	must(t, k.ensure(context.Background()))
	if f.resumed != 0 || len(f.created) != 0 {
		t.Fatalf("asleep: resumed %d, created %d", f.resumed, len(f.created))
	}
	if k.Status() != sleepStatus {
		t.Fatalf("asleep: STATUS %q", k.Status())
	}
	r.s.Wake(wakeOwner)
	must(t, k.ensure(context.Background()))
	if f.resumed != 1 || k.Status() == sleepStatus {
		t.Fatalf("awake: resumed %d, STATUS %q", f.resumed, k.Status())
	}
}

// PE7 (condition 13; UX P2-c): an owner message that reaches the agent's
// inbox wakes a sleeping agent, as an owner wake, and counts as the
// owner's latest message.
func TestDeliveredOwnerMessageWakesTheAgent(t *testing.T) {
	r := newSleepRig(t)
	var a lateAgent
	a.sleep.Store(r.s)
	at := r.now
	a.delivered(at) // awake: only noted
	if !a.lastDelivered().Equal(at) || len(r.notes) != 0 {
		t.Fatalf("awake: last %v, notes %v", a.lastDelivered(), r.notes)
	}
	r.set(func() { r.now = r.now.Add(time.Hour) })
	must(t, r.s.Sleep(context.Background()))
	a.delivered(r.clock())
	deadline := time.Now().Add(5 * time.Second)
	for r.s.Asleep() {
		if time.Now().After(deadline) {
			t.Fatal("the agent slept through an owner message")
		}
		time.Sleep(time.Millisecond)
	}
	if n := r.last(); n.Event != journal.SleepAwake || n.Cause != wakeOwner {
		t.Fatalf("journaled %+v", n)
	}
}

// PE7: -sleep-hours sets the quiet hours, wrapping past midnight.
func TestParseSleepHours(t *testing.T) {
	at := func(h, m int) time.Time { return time.Date(2026, 10, 6, h, m, 0, 0, time.Local) }
	for _, tc := range []struct {
		v       string
		in, out []time.Time
	}{
		{"02:30-05:00", []time.Time{at(2, 30), at(4, 59)}, []time.Time{at(2, 29), at(5, 0), at(14, 0)}},
		{"23:00-04:00", []time.Time{at(23, 0), at(0, 0), at(3, 59)}, []time.Time{at(22, 59), at(4, 0), at(12, 0)}},
	} {
		f, err := parseSleepHours(tc.v)
		must(t, err)
		for _, x := range tc.in {
			if !f(x) {
				t.Errorf("%s: %s outside", tc.v, x.Format("15:04"))
			}
		}
		for _, x := range tc.out {
			if f(x) {
				t.Errorf("%s: %s inside", tc.v, x.Format("15:04"))
			}
		}
	}
	if f, err := parseSleepHours(""); f != nil || err != nil {
		t.Fatal("empty: want the default hours")
	}
	for _, bad := range []string{"1-5", "01:00", "25:00-03:00", "02:00-02:00"} {
		if _, err := parseSleepHours(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
