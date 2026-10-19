package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/owner"
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
	waits    int           // restores that have waited on slow
	resumed  []string
	// during, if set, runs inside CheckpointAndStop, unlocked; resumeErr
	// fails ResumeFromCheckpoint, cold fallback included.
	during    func()
	resumeErr error
	deadline  time.Time // the last ResumeFromCheckpoint's ctx deadline
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

func (f *sleepFake) ResumeFromCheckpoint(ctx context.Context, id, snap string) (vm.Wake, error) {
	f.mu.Lock()
	f.deadline, _ = ctx.Deadline()
	slow := f.slow
	if slow != nil {
		f.waits++
	}
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
		Stopped: func() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.stopped },
		Journal: func(n journal.SleepNote) error { r.mu.Lock(); r.notes = append(r.notes, n); r.mu.Unlock(); return nil },
	})
	return r
}

// advance moves the rig's clock on by d.
func (r *sleepRig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

// slowly makes the next restore wait until d has passed on the rig's
// clock: a wake that long, whatever the machine's load.
func (r *sleepRig) slowly(d time.Duration) {
	slow := make(chan struct{})
	r.f.mu.Lock()
	r.f.slow = slow
	base := r.f.waits
	r.f.mu.Unlock()
	go func() {
		// Time moves on once the restore is under way: an owner message
		// arms its timer before that.
		for {
			r.f.mu.Lock()
			started := r.f.waits > base
			r.f.mu.Unlock()
			if started {
				break
			}
			time.Sleep(time.Millisecond)
		}
		r.advance(d)
		close(slow)
	}()
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
	for _, line := range []string{sleepStatus, owner.AckText} {
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

// PE7 (condition 14, OWN-4): an owner message wakes the agent, quick wake
// or slow, and the sleeper sends the owner nothing of its own: the owner
// channel's acknowledgement covers a slow wake (owner.AckText).
func TestOwnerMessageWakesASlowWake(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.s.OwnerMessage()
	if r.s.Asleep() || r.last().Cause != wakeOwner {
		t.Fatalf("quick wake: asleep %v, journal %+v", r.s.Asleep(), r.last())
	}
	must(t, r.s.Sleep(context.Background()))
	r.slowly(80 * time.Millisecond)
	r.s.OwnerMessage()
	if r.s.Asleep() || r.last().Cause != wakeOwner || len(r.f.resumed) != 2 {
		t.Fatalf("slow wake: asleep %v, resumed %v, journal %+v", r.s.Asleep(), r.f.resumed, r.last())
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

// PE7 (condition 14, L3 on #149): an owner message that arrives while the
// checkpoint is still being taken waits for it, then wakes the agent.
func TestOwnerMessageDuringTheCheckpointWakes(t *testing.T) {
	r := newSleepRig(t)
	release := make(chan struct{})
	in := make(chan struct{})
	r.f.during = func() { close(in); <-release }
	slept := make(chan error, 1)
	go func() { slept <- r.s.Sleep(context.Background()) }()
	<-in
	woke := make(chan struct{})
	go func() { r.s.OwnerMessage(); close(woke) }()
	close(release)
	must(t, <-slept)
	<-woke
	if r.s.Asleep() || r.last().Cause != wakeOwner {
		t.Fatalf("asleep %v, journal %+v", r.s.Asleep(), r.last())
	}
}

// PE7 (condition 14, OWN-4): only an owner message wakes with the owner's
// cause; the window's end wakes with its own, and neither sends the owner
// a line from the sleeper.
func TestOwnerMessageWakeCause(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	r.slowly(80 * time.Millisecond)
	r.s.Wake(wakeWindow)
	if r.s.Asleep() || r.last().Cause != wakeWindow {
		t.Fatalf("window wake: %+v", r.last())
	}
	r.s.OwnerMessage() // awake: nothing to do
	if n := len(r.f.resumed); n != 1 {
		t.Fatalf("an owner message to a waking agent resumed it again (%d)", n)
	}
}

// REQ: OWN-4

// OWN-4: the owner channel's acknowledgement replaces the sleeper's
// holding line. No agentosd source sends a waking-up line, and the
// sleeper has no hold of its own to configure.
func TestOWN4AckReplacesHoldLine(t *testing.T) {
	files, err := filepath.Glob("*.go")
	must(t, err)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		must(t, err)
		if strings.Contains(strings.ToLower(string(b)), "waking up") {
			t.Errorf("%s still has a waking-up line", f)
		}
	}
	ty := reflect.TypeOf(sleepConfig{})
	for _, name := range []string{"Hold", "HoldAfter", "AfterFunc"} {
		if _, ok := ty.FieldByName(name); ok {
			t.Errorf("sleepConfig still has %s", name)
		}
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

// PE7 (condition 14, L3 MUST-A on #149): owner messages that arrive
// together during one sleep's wake restore the agent once, and the next
// sleep wakes again.
func TestOwnerMessagesWakeOncePerSleep(t *testing.T) {
	r := newSleepRig(t)
	must(t, r.s.Sleep(context.Background()))
	slow := make(chan struct{})
	r.f.mu.Lock()
	r.f.slow = slow
	r.f.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); r.s.OwnerMessage() }()
	}
	for { // one restore waits, the other messages queue or see it awake
		r.f.mu.Lock()
		w := r.f.waits
		r.f.mu.Unlock()
		if w > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(slow)
	wg.Wait()
	if n := len(r.f.resumed); n != 1 || r.s.Asleep() {
		t.Fatalf("%d restores for one wake, asleep %v", n, r.s.Asleep())
	}
	must(t, r.s.Sleep(context.Background()))
	r.s.OwnerMessage()
	if n := len(r.f.resumed); n != 2 || r.s.Asleep() {
		t.Fatalf("%d restores after a second wake, asleep %v", n, r.s.Asleep())
	}
}

// PE7 (L3 on #149): a wake's restore is bounded by RestoreFor, 2 minutes
// unless set.
func TestRestoreIsBounded(t *testing.T) {
	for _, tc := range []struct {
		set, want time.Duration
	}{{0, 2 * time.Minute}, {-time.Second, 2 * time.Minute}, {5 * time.Second, 5 * time.Second}} {
		r := newSleepRig(t)
		r.s = newSleeper(sleepConfig{Machines: r.f, ID: "agent", Now: r.clock, Hours: func(time.Time) bool { return true }, RestoreFor: tc.set})
		must(t, r.s.Sleep(context.Background()))
		start := time.Now()
		r.s.Wake(wakeUnit)
		r.f.mu.Lock()
		got := r.f.deadline.Sub(start)
		r.f.mu.Unlock()
		if got < tc.want-time.Second || got > tc.want+time.Second {
			t.Errorf("RestoreFor %v: restore deadline in %v, want about %v", tc.set, got, tc.want)
		}
	}
}
