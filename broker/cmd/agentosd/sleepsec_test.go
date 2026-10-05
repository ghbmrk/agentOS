package main

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/clock"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/question"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: RES-1, REV-1, TIM-1

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

// PE7 (security R1 on #147, R2 on #149): an agent asleep when the broker
// stops wakes when it starts again, on a sleep-mode box (the sleeper's
// recover) and on a box no longer in sleep mode (agentKeeper), and no
// sleep checkpoint remains either way.
func TestSleepCheckpointDoesNotOutliveARestart(t *testing.T) {
	for _, mode := range []string{"sleep mode", "no longer sleep mode"} {
		t.Run(mode, func(t *testing.T) {
			state, img := filepath.Join(t.TempDir(), "state"), t.TempDir()
			m := openManager(t, state, img)
			spec := vm.Spec{Image: "base", Class: admission.Foreground, MemMB: 1600}
			_, err := m.Create(context.Background(), "agent", spec)
			must(t, err)
			s := newSleeper(sleepConfig{Machines: m, ID: "agent", Hours: func(time.Time) bool { return true }})
			must(t, s.Sleep(context.Background()))
			if sleepSnapshots(m, "agent") != 1 {
				t.Fatal("no sleep checkpoint taken")
			}

			m = openManager(t, state, img) // the broker restarts
			var notes []journal.SleepNote
			record := func(n journal.SleepNote) error { notes = append(notes, n); return nil }
			if mode == "sleep mode" {
				newSleeper(sleepConfig{Machines: m, ID: "agent", Journal: record}).recover(context.Background())
			} else {
				agentKeeper(context.Background(), m, record, "agent", spec, nil)
			}
			mc, err := m.Get("agent")
			must(t, err)
			if mc.State != vm.Running {
				t.Fatalf("agent %s after the restart", mc.State)
			}
			if n := sleepSnapshots(m, "agent"); n != 0 {
				t.Fatalf("%d sleep checkpoints outlived the restart", n)
			}
			if len(notes) != 1 || notes[0].Cause != wakeRestart || notes[0].Cold != "" {
				t.Fatalf("journal %+v, want one warm restart wake", notes)
			}
		})
	}
}

// PE7 (condition 2; security R1 and L3 on #149): the sleeper's checks read
// an open question, a box clock the check restricts (TIM-1), and a worker
// call in flight.
func TestSleepWorkChecks(t *testing.T) {
	no := func() bool { return false }
	var q questions
	w := sleepWork{intent: no, undo: no, gate: no, handed: no, qs: &q}
	checks := w.checks()
	for n, f := range checks {
		if f() {
			t.Fatalf("%s holds with nothing in hand", n)
		}
	}
	if _, ok := checks["worker"]; ok {
		t.Fatal("a worker check with no worker tools")
	}

	now := time.Date(2026, 10, 6, 2, 0, 0, 0, time.UTC)
	g, err := clock.New(clock.Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return now.Add(time.Hour), nil },
		Now:     func() time.Time { return now },
		Elapsed: func() time.Duration { return time.Hour },
		BootID:  func() string { return "boot" },
	})
	must(t, err)
	if !g.Check(context.Background()).Restricted() {
		t.Fatal("an hour's disagreement did not restrict")
	}
	q.g.Store(g)
	if !w.checks()["clock"]() {
		t.Fatal("a restricted clock did not keep the agent awake")
	}

	b, err := question.New(question.Config{
		Send: func(string) error { return nil },
		Now:  func(context.Context) (time.Time, error) { return now, nil },
	})
	must(t, err)
	q.b.Store(b)
	if w.checks()["question"]() {
		t.Fatal("an empty book holds the agent")
	}
	_, err = b.Ask(context.Background(), "lin1", "q1", question.Spec{Text: "Book the 9:00 or the 9:30 slot?", Default: "9:30", Wait: 30 * time.Minute})
	must(t, err)
	if !w.checks()["question"]() {
		t.Fatal("an open question did not keep the agent awake")
	}

	busy := true
	w.worker = func() bool { return busy }
	if !w.checks()["worker"]() {
		t.Fatal("a worker call in flight did not keep the agent awake")
	}
	if workerBusy(nil, "agent") != nil {
		t.Fatal("a worker check with no worker tools")
	}
}
