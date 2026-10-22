package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-1, REV-1

// sleepRuntime stands in for gVisor: a running set, and memory as a
// checkpointed marker file.
type sleepRuntime struct {
	mu      sync.Mutex
	running map[string]bool
}

func (r *sleepRuntime) Start(_ context.Context, l vm.Launch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running[l.ID] = true
	return nil
}
func (r *sleepRuntime) Restore(ctx context.Context, l vm.Launch, _ string) error {
	return r.Start(ctx, l)
}
func (r *sleepRuntime) Pause(context.Context, string) error  { return nil }
func (r *sleepRuntime) Resume(context.Context, string) error { return nil }
func (r *sleepRuntime) Checkpoint(_ context.Context, _, image string) error {
	return os.WriteFile(filepath.Join(image, "mem"), []byte("m"), 0o600)
}
func (r *sleepRuntime) Kill(_ context.Context, l vm.Launch) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.running, l.ID)
	return nil
}

type lateManager struct{ m **vm.Manager }

func (l lateManager) Preempt(id string) error { return (*l.m).Preempt(id) }

// openManager opens a machine manager on state, as a broker start does.
func openManager(t *testing.T, state, img string) *vm.Manager {
	t.Helper()
	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	m, err = vm.Open(context.Background(), vm.Config{
		StateDir: state, Images: map[string]string{"base": img},
		Runtime: &sleepRuntime{running: map[string]bool{}}, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	})
	must(t, err)
	return m
}

func sleepSnapshots(m *vm.Manager, id string) int {
	n := 0
	for _, s := range m.Snapshots(id) {
		if s.Sleep {
			n++
		}
	}
	return n
}

// PE7 (security R1 on #147, R2 on #149): an agent left asleep, stopped
// on a sleep checkpoint from when the box slept it for replay, wakes when
// agentosd starts again, and no sleep checkpoint remains.
func TestSleepCheckpointDoesNotOutliveARestart(t *testing.T) {
	state, img := filepath.Join(t.TempDir(), "state"), t.TempDir()
	m := openManager(t, state, img)
	spec := vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 1600}
	_, err := m.Create(context.Background(), "agent", spec)
	must(t, err)
	_, err = m.CheckpointAndStop(context.Background(), "agent")
	must(t, err)
	if sleepSnapshots(m, "agent") != 1 {
		t.Fatal("no sleep checkpoint taken")
	}

	m = openManager(t, state, img) // the broker restarts
	var notes []journal.SleepNote
	record := func(n journal.SleepNote) error { notes = append(notes, n); return nil }
	agentKeeper(context.Background(), m, record, "agent", spec)
	mc, err := m.Get("agent")
	must(t, err)
	if mc.State != vm.Running {
		t.Fatalf("agent %s after the restart", mc.State)
	}
	if n := sleepSnapshots(m, "agent"); n != 0 {
		t.Fatalf("%d sleep checkpoints outlived the restart", n)
	}
	if len(notes) != 1 || notes[0].Cause != wakeRestart || notes[0].Cold != "" || notes[0].Machine != "agent" {
		t.Fatalf("journal %+v, want one warm restart wake", notes)
	}
	// A running agent is left to the keeper.
	agentKeeper(context.Background(), m, record, "agent", spec)
	if len(notes) != 1 {
		t.Fatalf("a running agent was woken again: %+v", notes)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// leftoverFake is the vm.Manager part wakeLeftover uses: one machine
// stopped on its newest snapshot.
type leftoverFake struct {
	mc      vm.Machine
	snap    vm.Snapshot
	wake    vm.Wake
	err     error
	resumed []string
}

func (f *leftoverFake) Get(string) (vm.Machine, error) { return f.mc, nil }
func (f *leftoverFake) Snapshot(id string) (vm.Snapshot, error) {
	if id != f.snap.ID {
		return vm.Snapshot{}, vm.ErrUnknown
	}
	return f.snap, nil
}
func (f *leftoverFake) ResumeFromCheckpoint(_ context.Context, _, snap string) (vm.Wake, error) {
	f.resumed = append(f.resumed, snap)
	return f.wake, f.err
}

// PE7 (security R1 on #147, L3 on #149): wakeLeftover restores only this
// machine's own sleep checkpoint, and only while the machine is stopped on
// it; any other state is left to the keeper.
func TestWakeLeftoverLeavesOtherStatesAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(f *leftoverFake)
	}{
		{"running", func(f *leftoverFake) { f.mc.State = vm.Running }},
		{"no snapshot", func(f *leftoverFake) { f.mc.Last = "" }},
		{"not a sleep checkpoint", func(f *leftoverFake) { f.snap.Sleep = false }},
		{"another machine's", func(f *leftoverFake) { f.snap.Machine = "other" }},
		{"unknown snapshot", func(f *leftoverFake) { f.mc.Last = "s9" }},
	} {
		f := &leftoverFake{mc: vm.Machine{ID: "agent", State: vm.Stopped, Last: "s1"}, snap: vm.Snapshot{ID: "s1", Machine: "agent", Sleep: true}}
		tc.set(f)
		var notes []journal.SleepNote
		wakeLeftover(context.Background(), f, "agent", func(n journal.SleepNote) error { notes = append(notes, n); return nil }, t.Logf)
		if len(f.resumed) != 0 || len(notes) != 0 {
			t.Fatalf("%s: resumed %v, journal %+v", tc.name, f.resumed, notes)
		}
	}
}

// PE7 (condition 12, potency R1 on #147): a cold wake is journaled with
// its reason as a fixed code; a warm one with none, and a failed restore
// as restore_failed's code or unknown.
func TestWakeLeftoverJournalsTheColdReason(t *testing.T) {
	for _, tc := range []struct {
		wake vm.Wake
		err  error
		want string
	}{
		{vm.Wake{Restored: true}, nil, ""},
		{vm.Wake{Cold: vm.ColdNewer}, nil, "newer_snapshot"},
		{vm.Wake{Cold: vm.ColdChanged}, nil, "checkpoint_changed"},
		{vm.Wake{Cold: vm.ColdFailed}, errors.New("restore failed"), "restore_failed"},
		{vm.Wake{Cold: "something new"}, nil, "unknown"},
	} {
		f := &leftoverFake{mc: vm.Machine{ID: "agent", State: vm.Stopped, Last: "s1"}, snap: vm.Snapshot{ID: "s1", Machine: "agent", Sleep: true}, wake: tc.wake, err: tc.err}
		var notes []journal.SleepNote
		wakeLeftover(context.Background(), f, "agent", func(n journal.SleepNote) error { notes = append(notes, n); return nil }, t.Logf)
		if len(f.resumed) != 1 || len(notes) != 1 || notes[0].Event != journal.SleepAwake || notes[0].Cause != wakeRestart || notes[0].Cold != tc.want || notes[0].Machine != "agent" {
			t.Fatalf("%+v: resumed %v, journal %+v, want cold %q", tc.wake, f.resumed, notes, tc.want)
		}
	}
}
