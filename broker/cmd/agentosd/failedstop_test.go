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
	"github.com/ghbmrk/agentos/broker/daemon"
	"github.com/ghbmrk/agentos/broker/journal"
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

type allowAll struct{}

func (allowAll) Check(context.Context, journal.Phase, journal.Intent) error { return nil }
