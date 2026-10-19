package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/change"
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/meter"
	"github.com/ghbmrk/agentos/broker/vm"
)

// REQ: OP-6

// faultStore is the journal's store until fail is set; from then on every
// append fails, as a full or failing disk does.
type faultStore struct {
	*journal.MemStore
	fail atomic.Bool
}

func (s *faultStore) Append(line []byte) error {
	if s.fail.Load() {
		return errors.New("disk failed")
	}
	return s.MemStore.Append(line)
}

// inertRuntime runs no code: each command is counted, and "sleep" holds
// until it is ended.
type inertRuntime struct {
	sleepRuntime
	runs atomic.Int32
}

func (r *inertRuntime) Exec(ctx context.Context, _ string, c vm.Command) (vm.ExecResult, error) {
	r.runs.Add(1)
	if len(c.Argv) > 0 && c.Argv[0] == "sleep" {
		<-ctx.Done()
		return vm.ExecResult{}, ctx.Err()
	}
	return vm.ExecResult{}, nil
}

// A STOP whose record fails to write breaks the engine without putting
// STOP in force. The worker tools, as main wires them (boxGates and
// startReaper), still treat it as STOP: the command in flight ends, the
// command queued behind it never runs, and no fresh command or worker
// starts (SEC-failed-stop-latch, #2458).
func TestOP6FailedStopAdmitsNoWorkerCommand(t *testing.T) {
	store := &faultStore{MemStore: &journal.MemStore{}}
	eng, err := journal.Open(store, allowAll{}, map[string]journal.Executor{}, func(string) string { return daemon.Redacted })
	must(t, err)

	var m *vm.Manager
	adm, err := admission.New(admission.Config{CapacityMB: 8000}, lateManager{&m})
	must(t, err)
	rt := &inertRuntime{sleepRuntime: sleepRuntime{running: map[string]bool{}}}
	m, err = vm.Open(context.Background(), vm.Config{
		StateDir: filepath.Join(t.TempDir(), "state"), Images: map[string]string{"base": t.TempDir()},
		Runtime: rt, Admit: adm, NoCgroups: true, NoQuota: true,
		FreeBytes: func(string) (int64, error) { return 1 << 50, nil },
	})
	must(t, err)
	meminfo := filepath.Join(t.TempDir(), "meminfo")
	must(t, os.WriteFile(meminfo, []byte("MemAvailable: 8388608 kB\n"), 0o644))
	wt := workerTools(m, images{"base": ""}, "base", "idle", 2048, boxGates(eng, adm, meminfo, 0))
	if wt == nil {
		t.Fatal("worker tools off")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startReaper(ctx, wt, m, 5*time.Millisecond)

	agent, err := m.Create(ctx, "agent", vm.Spec{Image: "base", Class: admission.Experiment, MemMB: 500, Label: vm.Public})
	must(t, err)
	call := func(tool string, args any) error {
		b, _ := json.Marshal(args)
		_, handled, err := wt.Call(ctx, "agent", agent.Lineage, tool, b)
		if !handled {
			t.Fatalf("%s not handled", tool)
		}
		return err
	}
	must(t, call("worker_create", map[string]any{"name": "w"}))

	first := make(chan error, 1)
	go func() {
		first <- call("worker_exec", map[string]any{"name": "w", "argv": []string{"sleep"}, "timeout_seconds": 600})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for rt.runs.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the first command never ran")
		}
		time.Sleep(time.Millisecond)
	}
	queued := make(chan error, 1)
	go func() {
		queued <- call("worker_write_file", map[string]any{"name": "w", "path": "/f", "content": "after stop"})
	}()
	time.Sleep(20 * time.Millisecond) // the queued command waits on the worker

	store.fail.Store(true)
	if _, err := eng.Stop(ctx); !errors.Is(err, journal.ErrBroken) {
		t.Fatalf("STOP on a failing disk: %v, want ErrBroken", err)
	}
	if eng.Stopped() {
		t.Fatal("a STOP that failed to record reads as recorded")
	}

	select {
	case err := <-first:
		if err == nil {
			t.Fatal("the command in flight finished despite the failed STOP")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper did not end the command in flight after a failed STOP")
	}
	if err := <-queued; err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("queued command after a failed STOP: %v", err)
	}
	if err := call("worker_exec", map[string]any{"name": "w", "argv": []string{"echo"}}); err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("fresh command after a failed STOP: %v", err)
	}
	if err := call("worker_create", map[string]any{"name": "v"}); err == nil || !strings.Contains(err.Error(), "STOP") {
		t.Fatalf("fresh worker after a failed STOP: %v", err)
	}
	if n := rt.runs.Load(); n != 1 {
		t.Fatalf("%d commands ran; want only the one in flight before STOP", n)
	}
}

// A STOP that failed to record holds loop work as a recorded one does:
// the scheduler starts no job, since loop machines call the model through
// the vault's socket, which is not journaled (SEC-failed-stop-latch, #2458).
func TestOP6FailedStopStartsNoLoopWork(t *testing.T) {
	dir := t.TempDir()
	cfg := daemon.Config{
		JournalPath: filepath.Join(dir, "journal.log"), SocketDir: filepath.Join(dir, "run"),
		OwnerNumber: ownerNum, ModemUID: os.Getuid(), Admission: admission.Config{CapacityMB: 4500, HeadroomMB: 600},
		OwnerState: filepath.Join(dir, "owner.json"),
	}
	lp, err := openLearning(learnPaths{Dir: dir, Spare: filepath.Join(dir, "spare.json")}, false, &cfg)
	must(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d, err := daemon.Run(ctx, cfg)
	must(t, err)
	store := &faultStore{MemStore: &journal.MemStore{}}
	eng, err := journal.Open(store, allowAll{}, map[string]journal.Executor{}, func(string) string { return daemon.Redacted })
	must(t, err)
	lp.adm.Store(d.Admission())
	lp.eng.Store(eng)
	if lp.busy() || lp.stopped() {
		t.Fatal("an idle box reads busy or stopped")
	}
	// A source that always has model-free work, behind the same gates: on a
	// running box it gets its turn.
	spare, err := meter.Open(meter.Config{
		Path:       filepath.Join(dir, "probe-spare.json"),
		MachineCap: meter.Limits{Calls: 50, Tokens: 500_000},
		OverallCap: loops.SpareLimits(loops.NoSpareBudget),
	})
	must(t, err)
	src := &readySource{}
	probe, err := loops.New(loops.Config{Store: &change.MemStore{}, Spare: spare, Sources: []loops.Source{src},
		Busy: lp.busy, Stopped: lp.stopped})
	must(t, err)
	if ran, _ := probe.Tick(ctx); !ran || src.asked.Load() != 1 || src.ran.Load() != 1 {
		t.Fatalf("a ready source on a running box: ran %v, asked %d, run %d", ran, src.asked.Load(), src.ran.Load())
	}

	// The STOP fails while the source is looking: the job it offered does
	// not run.
	var stopErr error
	src.onNext = func() {
		store.fail.Store(true)
		_, stopErr = eng.Stop(ctx)
	}
	if ran, wait := probe.Tick(ctx); ran || wait != time.Minute || src.ran.Load() != 1 {
		t.Fatalf("work offered as STOP failed: ran %v, wait %v, run %d", ran, wait, src.ran.Load())
	}
	src.onNext = nil
	if !errors.Is(stopErr, journal.ErrBroken) {
		t.Fatalf("STOP on a failing disk: %v, want ErrBroken", stopErr)
	}
	if lp.busy() || !lp.stopped() {
		t.Fatal("a STOP that failed to record does not hold loop work")
	}
	// Halted, the scheduler offers no source a turn and looks again later.
	if ran, wait := lp.sched.Tick(ctx); ran || wait != time.Minute {
		t.Fatalf("loop tick after a failed STOP: ran %v, wait %v", ran, wait)
	}
	// The ready source is not even asked for work, so nothing it would look
	// at or start happens either.
	if ran, wait := probe.Tick(ctx); ran || wait != time.Minute || src.asked.Load() != 2 || src.ran.Load() != 1 {
		t.Fatalf("ready source after a failed STOP: ran %v, wait %v, asked %d, run %d", ran, wait, src.asked.Load(), src.ran.Load())
	}
}

// readySource always offers one unit of model-free work and counts how
// often it is asked and how often its work runs. onNext, if set, runs while
// it is asked.
type readySource struct {
	asked, ran atomic.Int32
	onNext     func()
}

func (s *readySource) Loop() loops.Loop { return loops.Maintain }

func (s *readySource) Next(context.Context, bool) (loops.Job, bool) {
	s.asked.Add(1)
	if s.onNext != nil {
		s.onNext()
	}
	return loops.Job{Name: "probe", Run: func(context.Context) loops.Result {
		s.ran.Add(1)
		return loops.Result{}
	}}, true
}
