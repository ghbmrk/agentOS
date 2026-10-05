package main

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-1, REV-1

// sleepFake is the vm.Manager part the sleeper uses: one agent machine.
type sleepFake struct {
	mu       sync.Mutex
	state    vm.State
	last     string
	snaps    map[string]vm.Snapshot
	n        int
	wake     vm.Wake // what the next ResumeFromCheckpoint reports
	sleepErr error
	slow     chan struct{} // if set, ResumeFromCheckpoint waits on it
	resumed  []string
	// during, if set, runs inside CheckpointAndStop, unlocked; resumeErr
	// fails ResumeFromCheckpoint, cold fallback included.
	during    func()
	resumeErr error
}

func newSleepFake() *sleepFake {
	return &sleepFake{state: vm.Running, snaps: map[string]vm.Snapshot{}, wake: vm.Wake{Restored: true}}
}

func (f *sleepFake) Get(id string) (vm.Machine, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return vm.Machine{ID: id, State: f.state, Last: f.last}, nil
}

func (f *sleepFake) Snapshot(id string) (vm.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.snaps[id]
	if !ok {
		return vm.Snapshot{}, vm.ErrUnknown
	}
	return s, nil
}

func (f *sleepFake) CheckpointAndStop(_ context.Context, id string) (vm.Snapshot, error) {
	f.mu.Lock()
	during := f.during
	f.mu.Unlock()
	if during != nil {
		during()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sleepErr != nil {
		return vm.Snapshot{}, f.sleepErr
	}
	f.n++
	s := vm.Snapshot{ID: "s" + strconv.Itoa(f.n), Machine: id, Tier: vm.Full, Sleep: true}
	f.snaps[s.ID], f.last, f.state = s, s.ID, vm.Stopped
	return s, nil
}

func (f *sleepFake) ResumeFromCheckpoint(_ context.Context, id, snap string) (vm.Wake, error) {
	f.mu.Lock()
	slow := f.slow
	f.mu.Unlock()
	if slow != nil {
		<-slow
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resumeErr != nil {
		delete(f.snaps, snap)
		return vm.Wake{}, f.resumeErr
	}
	f.resumed = append(f.resumed, snap)
	delete(f.snaps, snap)
	f.state = vm.Running
	return f.wake, nil
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// sleepRig drives a sleeper on a fake clock inside the default window.
type sleepRig struct {
	t       *testing.T
	f       *sleepFake
	s       *sleeper
	mu      sync.Mutex
	now     time.Time
	owner   time.Time
	pending map[string]bool
	stopped bool
	notes   []journal.SleepNote
	holds   int
}

func newSleepRig(t *testing.T) *sleepRig {
	r := &sleepRig{t: t, f: newSleepFake(), pending: map[string]bool{},
		now: time.Date(2026, 10, 6, 2, 0, 0, 0, time.Local)}
	r.owner = r.now.Add(-time.Hour)
	r.s = newSleeper(sleepConfig{
		Machines:  r.f,
		ID:        "agent",
		Now:       r.clock,
		LastOwner: func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.owner },
		Pending: map[string]func() bool{
			"intent": r.pend("intent"), "undo": r.pend("undo"), "gate": r.pend("gate"),
			"question": r.pend("question"), "handed": r.pend("handed"),
		},
		Stopped:   func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.stopped },
		Journal:   func(n journal.SleepNote) error { r.mu.Lock(); r.notes = append(r.notes, n); r.mu.Unlock(); return nil },
		Hold:      func() { r.mu.Lock(); r.holds++; r.mu.Unlock() },
		HoldAfter: 20 * time.Millisecond,
	})
	return r
}

func (r *sleepRig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *sleepRig) set(f func())     { r.mu.Lock(); f(); r.mu.Unlock() }
func (r *sleepRig) pend(k string) func() bool {
	return func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.pending[k] }
}

func (r *sleepRig) last() journal.SleepNote {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.notes) == 0 {
		r.t.Fatal("nothing journaled")
	}
	return r.notes[len(r.notes)-1]
}

// PE7 (conditions 1, 2, 3): the agent sleeps only in its quiet hours, never
// within PreWake of their end, only when the owner has been quiet for
// IdleAfter, and never with work in hand or STOP in force.
func TestSleepOnlyWhenIdleInTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(r *sleepRig)
		ok   bool
	}{
		{name: "idle in the window", ok: true},
		{name: "daytime", edit: func(r *sleepRig) { r.now = time.Date(2026, 10, 6, 14, 0, 0, 0, time.Local) }},
		{name: "before the window", edit: func(r *sleepRig) { r.now = time.Date(2026, 10, 6, 0, 59, 0, 0, time.Local) }},
		{name: "within the pre-wake", edit: func(r *sleepRig) { r.now = time.Date(2026, 10, 6, 5, 51, 0, 0, time.Local) }},
		{name: "owner recent", edit: func(r *sleepRig) { r.owner = r.now.Add(-29 * time.Minute) }},
		{name: "intent", edit: func(r *sleepRig) { r.pending["intent"] = true }},
		{name: "undo window", edit: func(r *sleepRig) { r.pending["undo"] = true }},
		{name: "gate-held", edit: func(r *sleepRig) { r.pending["gate"] = true }},
		{name: "open question", edit: func(r *sleepRig) { r.pending["question"] = true }},
		{name: "handed message", edit: func(r *sleepRig) { r.pending["handed"] = true }},
		{name: "STOP", edit: func(r *sleepRig) { r.stopped = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newSleepRig(t)
			if tc.edit != nil {
				r.set(func() { tc.edit(r) })
			}
			err := r.s.Sleep(context.Background())
			if (err == nil) != tc.ok || r.s.Asleep() != tc.ok {
				t.Fatalf("slept %v (%v), want %v", r.s.Asleep(), err, tc.ok)
			}
			if !tc.ok {
				if !errors.Is(err, errNoSleep) {
					t.Fatalf("refusal %v, want errNoSleep", err)
				}
				return
			}
			if n := r.last(); n.Event != journal.SleepAsleep || n.Machine != "agent" {
				t.Fatalf("journal %+v", n)
			}
			if r.s.Status() != sleepStatus {
				t.Fatalf("STATUS %q", r.s.Status())
			}
		})
	}
}

// PE7 (conditions 4, 6, 7; UX P2-b): an owner message wakes the agent. The
// evaluation running meanwhile is cut at once with change.ErrOwnerWork, so
// PE5 does not count it, and the agent is restored from its checkpoint.
// STOP's wake cuts with change.ErrOwnerStop. The journal line says warm.
func TestWakeCutsTheEvaluationAsTheOwners(t *testing.T) {
	for _, tc := range []struct {
		cause string
		want  error
	}{{wakeOwner, change.ErrOwnerWork}, {wakeStop, change.ErrOwnerStop}} {
		r := newSleepRig(t)
		must(t, r.s.Sleep(context.Background()))
		ctx, done := r.s.guard(context.Background())
		r.s.Wake(tc.cause)
		done()
		if ctx.Err() == nil || !errors.Is(context.Cause(ctx), tc.want) {
			t.Fatalf("%s: evaluation cause %v, want %v", tc.cause, context.Cause(ctx), tc.want)
		}
		if r.s.Asleep() || len(r.f.resumed) != 1 || r.f.resumed[0] != "s1" {
			t.Fatalf("%s: asleep %v, resumed %v", tc.cause, r.s.Asleep(), r.f.resumed)
		}
		if n := r.last(); n.Event != journal.SleepAwake || n.Cause != tc.cause || n.Cold != "" {
			t.Fatalf("%s: journal %+v", tc.cause, n)
		}
		if r.s.Status() != "" {
			t.Fatalf("STATUS %q while awake", r.s.Status())
		}
	}
}

// PE7 (potency R1; UX P2-c): a cold wake is journaled with its reason as a
// code. The owner sees nothing different: no line names warm or cold.
func TestColdWakeIsJournaledWithItsReason(t *testing.T) {
	r := newSleepRig(t)
	r.f.wake = vm.Wake{Cold: vm.ColdStarted}
	must(t, r.s.Sleep(context.Background()))
	r.s.Wake(wakeOwner)
	if n := r.last(); n.Cold != "started_since" {
		t.Fatalf("journal %+v", n)
	}
	for _, line := range []string{sleepStatus, holdLine} {
		for _, w := range []string{"warm", "cold"} {
			if strings.Contains(line, w) {
				t.Fatalf("owner text %q mentions %s", line, w)
			}
		}
	}
}

// PE7 (conditions 3, 6): the window's end (PreWake before it) and the
// maximum sleep wake the agent; a restart does too, since being asleep is
// held in memory only (recover, below).
func TestWatchWakesAtTheWindowEndAndMaxSleep(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.now = time.Date(2026, 10, 6, 5, 50, 0, 0, time.Local) })
	r.s.check()
	if r.s.Asleep() || r.last().Cause != wakeWindow {
		t.Fatalf("not woken by the window's end: %+v", r.last())
	}

	r = newSleepRig(t)
	r.s.cfg.Hours = func(time.Time) bool { return true }
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.now = r.now.Add(defaultMaxSleep + time.Minute) })
	r.s.check()
	if r.s.Asleep() || r.last().Cause != wakeMax {
		t.Fatalf("not woken by the maximum sleep: %+v", r.last())
	}

	r = newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.stopped = true })
	r.s.check()
	if r.s.Asleep() || r.last().Cause != wakeStop {
		t.Fatalf("not woken by STOP: %+v", r.last())
	}
}

// PE7 (condition 14): a wake for an owner message that takes longer than
// HoldAfter sends the holding line, once; a quick one sends none.
func TestHoldingLineOnASlowWake(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.s.OwnerMessage(time.Now())
	if r.holds != 0 {
		t.Fatal("a quick wake sent the holding line")
	}
	must(t, r.s.Sleep(context.Background()))
	slow := make(chan struct{})
	r.f.mu.Lock()
	r.f.slow = slow
	r.f.mu.Unlock()
	go func() { time.Sleep(80 * time.Millisecond); close(slow) }()
	r.s.OwnerMessage(time.Now())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.holds != 1 {
		t.Fatalf("holding line sent %d times, want 1", r.holds)
	}
}

// PE7: a sleep that fails is journaled and leaves the agent awake.
func TestFailedSleepLeavesTheAgentAwake(t *testing.T) {
	r := newSleepRig(t)
	r.f.sleepErr = errors.New("disk full")
	if err := r.s.Sleep(context.Background()); err == nil || r.s.Asleep() {
		t.Fatal("a failed checkpoint left the agent asleep")
	}
	if r.last().Event != journal.SleepFailed {
		t.Fatalf("journal %+v", r.last())
	}
}

// PE7 (security R1 on #147): at startup, a stopped agent whose newest
// snapshot is a sleep checkpoint is woken from it, so no sleep checkpoint
// outlives a restart; a running agent, or one stopped another way, is left
// to the keeper.
func TestRecoverWakesAnAgentLeftAsleep(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r2 := newSleepRig(t)
	r2.f = r.f
	r2.s.cfg.Machines = r.f
	r2.s.recover(context.Background())
	if len(r.f.resumed) != 1 || len(r.f.snaps) != 0 || r2.last().Cause != wakeRestart {
		t.Fatalf("resumed %v, snapshots %v, journal %+v", r.f.resumed, r.f.snaps, r2.notes)
	}
	r2.s.recover(context.Background())
	if len(r.f.resumed) != 1 {
		t.Fatal("a running agent was resumed again")
	}
}

func (r *sleepRig) holdCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.holds }

// PE7 (condition 14, L3 on #149): the holding line's clock runs from the
// owner message's delivery. A message that arrives while the checkpoint is
// still being taken gets the line HoldAfter later, not after the
// checkpoint and then HoldAfter.
func TestHoldingLineClockStartsAtDelivery(t *testing.T) {
	r := newSleepRig(t)
	release := make(chan struct{})
	in := make(chan struct{})
	r.f.during = func() { close(in); <-release }
	slept := make(chan error, 1)
	go func() { slept <- r.s.Sleep(context.Background()) }()
	<-in
	woke := make(chan struct{})
	go func() { r.s.OwnerMessage(time.Now()); close(woke) }()
	deadline := time.Now().Add(5 * time.Second)
	for r.holdCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no holding line while the checkpoint held the wake")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	must(t, <-slept)
	<-woke
	if r.s.Asleep() || r.holdCount() != 1 {
		t.Fatalf("asleep %v, holding lines %d", r.s.Asleep(), r.holdCount())
	}

	// A message delivered a while before its wake begins counts from the
	// delivery too.
	r = newSleepRig(t)
	r.s.cfg.HoldAfter = 300 * time.Millisecond
	must(t, r.s.Sleep(context.Background()))
	slow := make(chan struct{})
	r.f.mu.Lock()
	r.f.slow = slow
	r.f.mu.Unlock()
	go func() { time.Sleep(150 * time.Millisecond); close(slow) }()
	r.s.OwnerMessage(time.Now().Add(-250 * time.Millisecond))
	if r.holdCount() != 1 {
		t.Fatalf("holding lines %d for a wake ending 400 ms after delivery, want 1", r.holdCount())
	}
}

// PE7 (condition 14, L3 on #149): the holding line is for owner messages
// only, never before HoldAfter, and HoldAfter is 15 s unless set.
func TestHoldingLineThreshold(t *testing.T) {
	if got := newSleeper(sleepConfig{}).cfg.HoldAfter; got != 15*time.Second {
		t.Fatalf("default HoldAfter %v", got)
	}
	slowWake := func(r *sleepRig, d time.Duration, wake func()) {
		must(t, r.s.Sleep(context.Background()))
		slow := make(chan struct{})
		r.f.mu.Lock()
		r.f.slow = slow
		r.f.mu.Unlock()
		go func() { time.Sleep(d); close(slow) }()
		wake()
	}
	r := newSleepRig(t)
	slowWake(r, 80*time.Millisecond, func() { r.s.Wake(wakeWindow) })
	if r.holdCount() != 0 {
		t.Fatal("a wake at the window's end sent the holding line")
	}
	r = newSleepRig(t)
	r.s.cfg.HoldAfter = 400 * time.Millisecond
	slowWake(r, 40*time.Millisecond, func() { r.s.OwnerMessage(time.Now()) })
	time.Sleep(450 * time.Millisecond)
	if r.holdCount() != 0 {
		t.Fatal("the holding line went out before HoldAfter")
	}
}

// PE7 (L3 on #149): a wake whose restore and cold fallback both fail
// still marks the agent awake and journals it, so the keeper starts it
// again.
func TestFailedRestoreLeavesTheAgentToTheKeeper(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.f.mu.Lock()
	r.f.resumeErr = errors.New("restore failed")
	r.f.mu.Unlock()
	r.s.Wake(wakeOwner)
	if r.s.Asleep() {
		t.Fatal("the agent stayed asleep after a failed restore")
	}
	if n := r.last(); n.Event != journal.SleepAwake || n.Cold != "restore_failed" {
		t.Fatalf("journal %+v", n)
	}
	f := &fakeMachines{m: map[string]vm.Machine{"agent": {ID: "agent", Spec: testSpec, State: vm.Stopped}}}
	k := &keeper{m: f, id: "agent", spec: testSpec, sleep: r.s}
	must(t, k.ensure(context.Background()))
	if f.resumed != 1 {
		t.Fatalf("keeper resumed %d times, want 1", f.resumed)
	}
}

// PE7 (condition 2, L3 on #149): work that arrives while the checkpoint
// is taken wakes the agent at once, and the unit does not run.
func TestWorkDuringTheCheckpointWakesTheAgent(t *testing.T) {
	r := newSleepRig(t)
	r.f.during = func() { r.set(func() { r.pending["handed"] = true }) }
	if err := r.s.Sleep(context.Background()); !errors.Is(err, errNoSleep) {
		t.Fatalf("sleep with work arrived: %v", err)
	}
	if r.s.Asleep() || len(r.f.resumed) != 1 || r.last().Cause != wakeWork {
		t.Fatalf("asleep %v, resumed %v, journal %+v", r.s.Asleep(), r.f.resumed, r.last())
	}
}

// PE7 (condition 6, L3 on #149): MaxSleep runs from the latest sleep, and
// after a wake at MaxSleep the agent stays awake for IdleAfter.
func TestMaxSleepRunsFromEachSleep(t *testing.T) {
	r := newSleepRig(t)
	r.s.cfg.Hours = func(time.Time) bool { return true }
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.now = r.now.Add(4 * time.Hour) })
	r.s.Wake(wakeUnit)
	must(t, r.s.Sleep(context.Background()))
	r.set(func() { r.now = r.now.Add(2 * time.Hour) })
	r.s.check()
	if !r.s.Asleep() {
		t.Fatalf("woken %+v: MaxSleep counted from the first sleep", r.last())
	}
	r.set(func() { r.now = r.now.Add(3*time.Hour + time.Minute) })
	r.s.check()
	if r.s.Asleep() || r.last().Cause != wakeMax {
		t.Fatalf("not woken at MaxSleep: %+v", r.last())
	}
	if err := r.s.Sleep(context.Background()); !errors.Is(err, errNoSleep) {
		t.Fatalf("slept again straight after its longest sleep: %v", err)
	}
	r.set(func() { r.now = r.now.Add(defaultIdleAfter) })
	must(t, r.s.Sleep(context.Background()))
}

// PE7 (security R1 on #147, L3 on #149): recover restores only this
// machine's sleep checkpoint, and only while the machine is stopped on it.
func TestRecoverLeavesOtherStatesAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(f *sleepFake)
	}{
		{"running", func(f *sleepFake) { f.state = vm.Running }},
		{"not a sleep checkpoint", func(f *sleepFake) { s := f.snaps[f.last]; s.Sleep = false; f.snaps[f.last] = s }},
		{"another machine's", func(f *sleepFake) { s := f.snaps[f.last]; s.Machine = "other"; f.snaps[f.last] = s }},
	} {
		r := newSleepRig(t)
		must(t, r.s.Sleep(context.Background()))
		r.f.mu.Lock()
		tc.set(r.f)
		r.f.mu.Unlock()
		r2 := newSleepRig(t)
		r2.s.cfg.Machines = r.f
		r2.s.recover(context.Background())
		if len(r.f.resumed) != 0 || len(r2.notes) != 0 {
			t.Fatalf("%s: resumed %v, journal %+v", tc.name, r.f.resumed, r2.notes)
		}
	}
}
