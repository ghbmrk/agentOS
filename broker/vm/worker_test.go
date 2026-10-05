package vm

// REQ: CAP-8, REV-5, CAP-3, OP-6, RES-4

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

	_, err = e.m.Exec(bg, "wk-a1", Command{As: Private, Argv: []string{"write", "out/result"}, Stdin: []byte("42")}, time.Second)
	must(t, err)
	r, err := e.m.Exec(bg, "wk-a1", Command{As: Private, Argv: []string{"cat", "out/result"}}, time.Second)
	must(t, err)
	if string(r.Stdout) != "42" || r.ExitCode != 0 {
		t.Fatalf("cat = %+v", r)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{As: Private, Argv: []string{"exit", "3"}}, time.Second)
	if err != nil || r.ExitCode != 3 {
		t.Fatalf("exit 3 = %+v, %v; want a result with code 3", r, err)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{As: Private, Argv: []string{"echo", strings.Repeat("x", 100)}, MaxOutput: 10}, time.Second)
	if err != nil || len(r.Stdout) != 10 || !r.Truncated {
		t.Fatalf("capped output = %d bytes, truncated %v, %v", len(r.Stdout), r.Truncated, err)
	}
	r, err = e.m.Exec(bg, "wk-a1", Command{As: Private, Argv: []string{"sleep"}}, 20*time.Millisecond)
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
	_, err = e.m.Exec(bg, "wk-a", Command{As: Private, Argv: []string{"write", "secret"}, Stdin: []byte("deleted record")}, time.Second)
	must(t, err)
	_, err = e.m.Step(bg, "wk-a")
	must(t, err)
	must(t, e.m.ForgetSince(context.Background(), agent.Lineage, since))
	if got := e.guestRead("wk-a", "secret"); got != "" {
		t.Fatalf("worker still holds %q after ForgetSince", got)
	}
}

// Erasure, rollback and destroy never wait behind a worker's command
// (security F1 on #146): a 10-minute command ends, and ForgetSince
// finishes with the data gone.
func TestCAP3ForgetSinceDoesNotWaitForAWorkersCommand(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Private))
	must(t, err)
	since := time.Now()
	time.Sleep(5 * time.Millisecond)
	_, err = e.m.Exec(bg, "wk-a", Command{As: Private, Argv: []string{"write", "secret"}, Stdin: []byte("deleted record")}, time.Second)
	must(t, err)
	for _, op := range []struct {
		name string
		run  func() error
	}{
		{"ForgetSince", func() error { return e.m.ForgetSince(bg, agent.Lineage, since) }},
		{"Destroy", func() error { return e.m.Destroy(bg, "wk-a") }},
	} {
		done := make(chan error, 1)
		go func() {
			_, err := e.m.Exec(bg, "wk-a", Command{As: Private, Argv: []string{"sleep"}}, 10*time.Minute)
			done <- err
		}()
		time.Sleep(20 * time.Millisecond) // the command holds the worker
		start := time.Now()
		must(t, op.run())
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("%s waited %v behind a command", op.name, d)
		}
		if err := <-done; err == nil {
			t.Fatalf("%s: the command in flight reported success", op.name)
		}
		if op.name == "ForgetSince" {
			if got := e.guestRead("wk-a", "secret"); got != "" {
				t.Fatalf("worker still holds %q", got)
			}
		}
	}
}

// A worker made after since has no restore point before it: ForgetSince
// gives it a fresh layer from its image (security R4 on #146).
func TestCAP3WorkerMadeAfterSinceComesBackEmpty(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	since := time.Now()
	time.Sleep(5 * time.Millisecond)
	_, err := e.m.CreateWorker(bg, "wk-new", agent.Lineage, workerSpec(Private))
	must(t, err)
	_, err = e.m.Exec(bg, "wk-new", Command{Argv: []string{"write", "secret"}, Stdin: []byte("deleted record"), As: Private}, time.Second)
	must(t, err)
	must(t, e.m.ForgetSince(bg, agent.Lineage, since))
	if got := e.guestRead("wk-new", "secret"); got != "" {
		t.Fatalf("worker made after since still holds %q", got)
	}
}

// A parked worker frees its admission and comes back, memory included,
// by rolling back to its parking checkpoint (UX-146-1).
func TestCAP8ParkedWorkerFreesMemoryAndRevivesByRollback(t *testing.T) {
	e := newEnv(t, 1000)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	e.rt.work("wk-a", 7)
	_, err = e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "f"}, Stdin: []byte("kept")}, time.Second)
	must(t, err)
	s, err := e.m.Park(bg, "wk-a")
	must(t, err)
	w, err := e.m.Get("wk-a")
	must(t, err)
	if w.State != Stopped || w.Last != s.ID {
		t.Fatalf("parked worker = %+v", w)
	}
	if _, ok := e.rt.memOf("wk-a"); ok {
		t.Fatal("parked worker still running")
	}
	for _, r := range e.adm.Snapshot().Running {
		if r.ID == "wk-a" {
			t.Fatal("parked worker still admitted")
		}
	}
	if _, err := e.m.Park(bg, "agent"); err == nil {
		t.Fatal("parked an agent machine")
	}
	must(t, e.m.Rollback(bg, "wk-a", s.ID))
	if n, ok := e.rt.memOf("wk-a"); !ok || n != 7 {
		t.Fatalf("revived worker memory = %d (running %v), want 7", n, ok)
	}
	if got := e.guestRead("wk-a", "f"); got != "kept" {
		t.Fatalf("revived worker file = %q", got)
	}
}

// REV-5 and A14 under the worker's lock: a command raises the worker to its
// caller's label before it runs, and a caller labelled below the worker is
// refused before the runtime runs anything (L3 MUST-2 on #146).
func TestREV5ExecRaisesAndChecksUnderTheWorkersLock(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	_, err = e.m.Exec(bg, "wk-a", Command{As: Private, Argv: []string{"write", "secret"}, Stdin: []byte("owner data")}, time.Second)
	must(t, err)
	if l, _ := e.m.Label("wk-a"); l != Private {
		t.Fatalf("worker written for a private machine is %v", l)
	}
	if _, err := e.m.Exec(bg, "wk-a", Command{As: Public, Argv: []string{"write", "probe"}}, time.Second); !errors.Is(err, ErrLabel) {
		t.Fatalf("public caller on a private worker: %v, want ErrLabel", err)
	}
	if got := e.guestRead("wk-a", "probe"); got != "" {
		t.Fatal("the refused command ran")
	}
	// The raise is recorded: it survives a reopen.
	e.open()
	if l, _ := e.m.Label("wk-a"); l != Private {
		t.Fatalf("after reopen the worker is %v", l)
	}
}

// A runtime that ignores cancellation holds the worker for at most
// ExecGrace past the timeout, and erasure gets the worker after it (L3
// MUST-1 on #146; F1).
func TestCAP8ExecReturnsWhenTheRuntimeIgnoresCancellation(t *testing.T) {
	old := ExecGrace
	ExecGrace = 50 * time.Millisecond
	t.Cleanup(func() { ExecGrace = old })
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	start := time.Now()
	r, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"hang"}}, 20*time.Millisecond)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("exec returned after %v", d)
	}
	if err != nil || !r.TimedOut {
		t.Fatalf("exec = %+v, %v; want a timed-out result", r, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"hang"}}, time.Minute)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond)
	start = time.Now()
	must(t, e.m.ForgetSince(bg, agent.Lineage, start.Add(-time.Hour)))
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("ForgetSince waited %v behind a hung runtime", d)
	}
	if err := <-done; err == nil {
		t.Fatal("the abandoned command reported success")
	}
}

// A worker that is not running takes no command (M33).
func TestCAP8ExecNeedsARunningWorker(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	_, err = e.m.Park(bg, "wk-a")
	must(t, err)
	if _, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"echo"}}, time.Second); !errors.Is(err, ErrState) {
		t.Fatalf("exec on a parked worker: %v, want ErrState", err)
	}
}

// A worker over its layer cap takes no command and no snapshot until it
// shrinks (security R3 on #146); other machines keep the general cap.
func TestCAP8WorkerLayerCap(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.WorkerLayerBytes = 16 << 10
	e.open()
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	_, err = e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "big"}, Stdin: make([]byte, 64<<10)}, time.Second)
	must(t, err) // under the cap when it started
	if _, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"echo"}}, time.Second); !errors.Is(err, ErrQuota) {
		t.Fatalf("command in a worker over its cap: %v", err)
	}
	if _, err := e.m.Step(bg, "wk-a"); !errors.Is(err, ErrQuota) {
		t.Fatalf("snapshot of a worker over its cap: %v", err)
	}
	e.guestWrite("agent", "big", string(make([]byte, 64<<10)))
	if _, err := e.m.Step(bg, "agent"); err != nil {
		t.Fatalf("the worker cap applied to an agent: %v", err)
	}
}

func TestCAP8EndCommandsEndsWhatIsInFlight(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"sleep"}}, 10*time.Minute)
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for e.m.EndCommands() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no command in flight to end")
		}
		time.Sleep(5 * time.Millisecond)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an ended command reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("EndCommands did not end the command")
	}
	w, err := e.m.Get("wk-a")
	must(t, err)
	if w.State != Running {
		t.Fatalf("worker is %s after its command ended", w.State)
	}
}

// Parking does not wait out a command: a busy worker is refused at once
// (L3 SHOULD on #146).
func TestCAP8ParkRefusesABusyWorker(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"sleep"}}, 10*time.Minute)
		done <- err
	}()
	time.Sleep(20 * time.Millisecond) // the command holds the worker
	start := time.Now()
	if _, err := e.m.Park(bg, "wk-a"); !errors.Is(err, ErrBusy) {
		t.Fatalf("park of a busy worker: %v, want ErrBusy", err)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("park waited %v", d)
	}
	must(t, e.m.Destroy(bg, "wk-a"))
	<-done
}

// A worker over its layer cap can take no checkpoint, but parking still
// stops it and hands back its memory; rollback to an earlier snapshot
// revives it under the cap (L3 MUST-1 on #150).
func TestCAP8FullWorkerParksWithoutACheckpoint(t *testing.T) {
	e := newEnv(t, 4096)
	e.cfg.WorkerLayerBytes = 16 << 10
	e.open()
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	early, err := e.m.Step(bg, "wk-a")
	must(t, err)
	_, err = e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "big"}, Stdin: make([]byte, 64<<10)}, time.Second)
	must(t, err)
	before := len(e.m.Snapshots("wk-a"))
	s, err := e.m.Park(bg, "wk-a")
	if err != nil || s.ID != "" {
		t.Fatalf("park of a full worker = %+v, %v; want stopped without a snapshot", s, err)
	}
	if w, _ := e.m.Get("wk-a"); w.State != Stopped {
		t.Fatalf("full worker is %s after park", w.State)
	}
	for _, r := range e.adm.Snapshot().Running {
		if r.ID == "wk-a" {
			t.Fatal("parked full worker still admitted")
		}
	}
	if n := len(e.m.Snapshots("wk-a")); n != before {
		t.Fatalf("park left %d snapshots, had %d", n, before)
	}
	must(t, e.m.Rollback(bg, "wk-a", early.ID))
	if _, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"echo"}}, time.Second); err != nil {
		t.Fatalf("revived worker: %v", err)
	}
}

// Hold is asked under the worker's lock: a command that took the lock
// after the owner's STOP does not start (L3 MUST-2 on #150).
func TestOP6HeldCommandDoesNotStart(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	held := true
	if _, err := e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "f"}, Stdin: []byte("ran"), Hold: func() bool { return held }}, time.Second); !errors.Is(err, ErrHeld) {
		t.Fatalf("held command: %v, want ErrHeld", err)
	}
	if got := e.guestRead("wk-a", "f"); got != "" {
		t.Fatal("the held command ran")
	}
}
