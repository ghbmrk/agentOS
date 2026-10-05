package vm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-1

// slowRuntime blocks Checkpoint or Restore until released, standing in for
// a 2-4.5 s checkpoint or restore of an OpenClaw-sized guest (S3).
type slowRuntime struct {
	*fakeRuntime
	block   chan struct{} // closed to release
	entered chan string   // receives the blocked call's name
	what    string        // "checkpoint" or "restore"
}

func (s *slowRuntime) wait(what string) {
	if s.what == what {
		s.entered <- what
		<-s.block
	}
}

func (s *slowRuntime) Checkpoint(ctx context.Context, id, image string) error {
	s.wait("checkpoint")
	return s.fakeRuntime.Checkpoint(ctx, id, image)
}

func (s *slowRuntime) Restore(ctx context.Context, l Launch, image string) error {
	s.wait("restore")
	return s.fakeRuntime.Restore(ctx, l, image)
}

func slowEnv(t *testing.T, what string) (*env, *slowRuntime) {
	e := newEnv(t, 2000)
	s := &slowRuntime{fakeRuntime: e.rt, block: make(chan struct{}), entered: make(chan string, 1), what: what}
	e.cfg.Runtime = s
	e.open()
	return e, s
}

// The frozen target (RES-1) is shorter than a full checkpoint, so
// preemption must not wait for an operation already holding the
// experiment: it kills the sandbox under it.
func TestRES1PreemptionDoesNotWaitForACheckpointInProgress(t *testing.T) {
	e, s := slowEnv(t, "checkpoint")
	e.create("exp", admission.Experiment, 1500)
	ckpt := make(chan error, 1)
	go func() { _, err := e.m.Checkpoint(bg, "exp"); ckpt <- err }()
	<-s.entered // the checkpoint holds the machine now

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := e.m.Create(bg, "call", Spec{Image: "base", Class: admission.Foreground, MemMB: 1000})
		done <- err
	}()
	select {
	case err := <-done:
		must(t, err)
	case <-time.After(2 * time.Second):
		close(s.block)
		t.Fatal("foreground admission waited for the experiment's checkpoint")
	}
	t.Logf("preemption under a running checkpoint took %v (fake runtime)", time.Since(start))
	if _, ok := e.rt.memOf("exp"); ok {
		t.Fatal("experiment still running after preemption returned")
	}
	close(s.block)
	if err := <-ckpt; err == nil {
		t.Fatal("checkpoint of a killed machine reported success")
	}
	waitState(t, e, "exp", Preempted)
	if _, ok := e.rt.memOf("exp"); ok {
		t.Fatal("experiment running again after its checkpoint unwound")
	}
	// It resumes as usual once there is room.
	must(t, e.m.Destroy(bg, "call"))
	must(t, e.m.Resume(bg, "exp"))
}

// A rollback that was already restoring when preemption hit must not bring
// the machine back to life on memory admission has handed to someone else.
func TestRES1InterruptedRollbackDoesNotRestartThePreemptedMachine(t *testing.T) {
	e, s := slowEnv(t, "")
	e.create("exp", admission.Experiment, 1500)
	snap, err := e.m.Checkpoint(bg, "exp")
	must(t, err)
	s.what = "restore"
	rb := make(chan error, 1)
	go func() { rb <- e.m.Rollback(bg, "exp", snap.ID) }()
	<-s.entered // the rollback is restoring memory now

	done := make(chan error, 1)
	go func() {
		_, err := e.m.Create(bg, "call", Spec{Image: "base", Class: admission.Foreground, MemMB: 1000})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			close(s.block)
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(s.block)
		t.Fatal("foreground admission waited for the experiment's rollback")
	}
	close(s.block)
	if err := <-rb; !errors.Is(err, ErrRevoked) {
		t.Fatalf("rollback after preemption: %v, want ErrRevoked", err)
	}
	if _, ok := e.rt.memOf("exp"); ok {
		t.Fatal("the interrupted rollback restarted the preempted machine")
	}
	if got := e.adm.Snapshot().Running; len(got) != 1 {
		t.Fatalf("admitted: %v, want only the call", got)
	}
	mc, err := e.m.Get("exp")
	must(t, err)
	if mc.State == Running {
		t.Fatal("experiment recorded as running")
	}
}

func waitState(t *testing.T, e *env, id string, want State) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		mc, err := e.m.Get(id)
		must(t, err)
		if mc.State == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is %s, want %s", id, mc.State, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// REQ: RES-1, REV-4

// cutShortRuntime's checkpoint blocks, then reports success even though the
// sandbox was killed under it, leaving a truncated image: a runtime need
// not report the kill as an error.
type cutShortRuntime struct {
	*slowRuntime
}

func (c *cutShortRuntime) Checkpoint(_ context.Context, id, image string) error {
	c.wait("checkpoint")
	return os.WriteFile(filepath.Join(image, "mem"), []byte("trunc"), 0o600)
}

// A checkpoint cut short by the lock-free preemption publishes no snapshot,
// even when the runtime reports success (Security R2 on #124): a later
// rollback must never restore a truncated image.
func TestRES1CheckpointCutShortByPreemptionPublishesNoSnapshot(t *testing.T) {
	e := newEnv(t, 2000)
	s := &slowRuntime{fakeRuntime: e.rt, block: make(chan struct{}), entered: make(chan string, 1), what: "checkpoint"}
	e.cfg.Runtime = &cutShortRuntime{s}
	e.open()
	e.create("exp", admission.Experiment, 1500)
	before := len(e.m.Snapshots("exp"))
	ckpt := make(chan error, 1)
	go func() { _, err := e.m.Checkpoint(bg, "exp"); ckpt <- err }()
	<-s.entered

	_, err := e.m.Create(bg, "call", Spec{Image: "base", Class: admission.Foreground, MemMB: 1000})
	if err != nil {
		close(s.block)
		t.Fatal(err)
	}
	close(s.block)
	if err := <-ckpt; !errors.Is(err, ErrPreempted) {
		t.Fatalf("checkpoint cut short: %v, want ErrPreempted", err)
	}
	if got := e.m.Snapshots("exp"); len(got) != before {
		t.Fatalf("snapshots %v published by a checkpoint cut short", ids(got))
	}
	entries, err := os.ReadDir(filepath.Join(e.cfg.StateDir, "snapshots"))
	must(t, err)
	if len(entries) != before {
		t.Fatalf("%d snapshot directories on disk, want %d", len(entries), before)
	}
	waitState(t, e, "exp", Preempted)
	// Nothing survives a restart either.
	must(t, e.m.Destroy(bg, "call"))
	e.open()
	if got := e.m.Snapshots("exp"); len(got) != before {
		t.Fatalf("after restart: %v", ids(got))
	}
}
