package vm

// REQ: CAP-8, REV-5, CAP-3

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

func workerSpec(l Label) Spec {
	return Spec{Image: "base", Class: admission.Experiment, MemMB: 200, Argv: []string{"idle"}, Label: l}
}

// A worker joins its creator's lineage, gets no guest services, and runs
// commands; agent machines take none.
func TestCAP8WorkerJoinsTheLineageAndRunsCommandsWithoutServices(t *testing.T) {
	e := newEnv(t, 4096)
	svc := &recServices{root: t.TempDir(), open: map[string]bool{}}
	e.cfg.Services = svc
	e.open()
	agent := e.create("agent", admission.Experiment, 500)

	w, err := e.m.CreateWorker(bg, "wk-a1", agent.Lineage, workerSpec(Private))
	must(t, err)
	if w.Lineage != agent.Lineage || w.Label != Private {
		t.Fatalf("worker = %+v, want lineage %s, private", w, agent.Lineage)
	}
	if svc.open["wk-a1"] {
		t.Fatal("a worker got guest services")
	}
	for _, l := range e.rt.launches {
		if l.ID == "wk-a1" && l.Services != "" {
			t.Fatal("a worker was launched with a services directory")
		}
	}

	_, err = e.m.Exec(bg, "wk-a1", Command{Argv: []string{"write", "out/result"}, Stdin: []byte("42")}, time.Second)
	must(t, err)
	r, err := e.m.Exec(bg, "wk-a1", Command{Argv: []string{"cat", "out/result"}}, time.Second)
	must(t, err)
	if string(r.Stdout) != "42" || r.ExitCode != 0 {
		t.Fatalf("cat = %+v", r)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{Argv: []string{"exit", "3"}}, time.Second)
	if err != nil || r.ExitCode != 3 {
		t.Fatalf("exit 3 = %+v, %v; want a result with code 3", r, err)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{Argv: []string{"echo", strings.Repeat("x", 100)}, MaxOutput: 10}, time.Second)
	if err != nil || len(r.Stdout) != 10 || !r.Truncated {
		t.Fatalf("capped output = %d bytes, truncated %v, %v", len(r.Stdout), r.Truncated, err)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{Argv: []string{"sleep"}}, 20*time.Millisecond)
	if err != nil || !r.TimedOut {
		t.Fatalf("sleep past timeout = %+v, %v; want timed out", r, err)
	}
	if _, err := e.m.Exec(bg, "agent", Command{Argv: []string{"echo"}}, time.Second); err == nil {
		t.Fatal("broker ran a command in an agent machine")
	}
}

func TestCAP8WorkerIDsAndLineagesAreChecked(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	if _, err := e.m.Create(bg, "wk-x", workerSpec(Public)); err == nil {
		t.Fatal("Create made a worker-prefixed machine")
	}
	if _, err := e.m.CreateSeeded(bg, "wk-x", workerSpec(Private), nil); err == nil {
		t.Fatal("CreateSeeded made a worker-prefixed machine")
	}
	if _, err := e.m.CreateWorker(bg, "plain", agent.Lineage, workerSpec(Public)); err == nil {
		t.Fatal("CreateWorker made a machine without the worker prefix")
	}
	if _, err := e.m.CreateWorker(bg, "wk-x", "nobody.000000", workerSpec(Public)); !errors.Is(err, ErrUnknown) {
		t.Fatalf("worker in a lineage no machine holds: %v", err)
	}
	// A worker's lineage alone does not keep a lineage open for workers.
	w, err := e.m.CreateWorker(bg, "wk-1", agent.Lineage, workerSpec(Public))
	must(t, err)
	must(t, e.m.Destroy(bg, "agent"))
	if _, err := e.m.CreateWorker(bg, "wk-2", w.Lineage, workerSpec(Public)); !errors.Is(err, ErrUnknown) {
		t.Fatalf("worker made in a lineage only workers hold: %v", err)
	}
}

// Workers fork into workers only, nothing else forks into one, and workers
// are never merged.
func TestCAP8WorkerForkAndMergeStayAmongWorkers(t *testing.T) {
	e := newEnv(t, 8000)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	if _, err := e.m.Fork(bg, "agent", []string{"wk-b"}); err == nil {
		t.Fatal("an agent forked into a worker")
	}
	if _, err := e.m.Fork(bg, "wk-a", []string{"plain"}); err == nil {
		t.Fatal("a worker forked into a non-worker")
	}
	if _, err := e.m.Fork(bg, "wk-a", []string{"wk-b", "wk-c"}); err != nil {
		t.Fatal(err)
	}
	b, err := e.m.Get("wk-b")
	must(t, err)
	if b.Lineage != agent.Lineage {
		t.Fatalf("fork of a worker left the lineage: %s", b.Lineage)
	}
	if _, err := e.m.Merge(bg, "wk-a", "wk-b"); err == nil {
		t.Fatal("workers merged")
	}
}

// Deletion reach (CAP-3) takes back a lineage's workers with its agent.
func TestCAP3ForgetSinceReachesTheLineagesWorkers(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Private))
	must(t, err)
	_, err = e.m.Checkpoint(bg, "wk-a")
	must(t, err)
	since := time.Now()
	time.Sleep(5 * time.Millisecond)
	_, err = e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "secret"}, Stdin: []byte("deleted record")}, time.Second)
	must(t, err)
	_, err = e.m.Step(bg, "wk-a")
	must(t, err)
	must(t, e.m.ForgetSince(context.Background(), agent.Lineage, since))
	if got := e.guestRead("wk-a", "secret"); got != "" {
		t.Fatalf("worker still holds %q after ForgetSince", got)
	}
}
