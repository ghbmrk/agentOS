package vm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// REQ: RES-4, REV-1

// shapes are the layers the broker cannot copy, so cannot snapshot: nested
// deeper than overlay.MaxTreeDepth (security R4 on #166), and shallow but
// with paths past the host's PATH_MAX (L3 MUST-1 on #174). Each makes the
// layer of machine id so.
var shapes = map[string]func(e *env, id string){
	"too deep": func(e *env, id string) {
		e.guestWrite(id, filepath.Join(strings.Repeat("a/", overlay.MaxTreeDepth+1), "f"), "x")
	},
	"too long": func(e *env, id string) { e.nest(id, strings.Repeat("n", 200), 25) },
}

// nest makes a chain of depth directories named name in id's layer,
// through handles, so it can pass PATH_MAX.
func (e *env) nest(id, name string, depth int) {
	e.t.Helper()
	fd, err := syscall.Open(filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper"), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	must(e.t, err)
	for range depth {
		must(e.t, syscall.Mkdirat(fd, name, 0o755))
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		must(e.t, err)
		fd = next
	}
	syscall.Close(fd)
}

// noHostPath fails the test if err names the state directory.
func (e *env) noHostPath(err error) {
	e.t.Helper()
	if err != nil && strings.Contains(err.Error(), e.cfg.StateDir) {
		e.t.Fatalf("error names a host path: %v", err)
	}
}

// Such a layer is over the cap: the snapshot is refused with the disk-budget
// text the guest can act on, naming no host path, never taken as no use,
// and the machine keeps running; flattened, it snapshots again.
func TestATooDeepLayerIsOverTheCap(t *testing.T) {
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 8192)
			e.open()
			e.create("m1", admission.Accepted, 100)
			shape(e, "m1")
			_, err := e.m.Step(bg, "m1")
			if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "flatten") {
				t.Fatalf("snapshot: %v", err)
			}
			e.noHostPath(err)
			if mc, _ := e.m.Get("m1"); mc.State != Running {
				t.Fatalf("machine %s after the refusal", mc.State)
			}
			upper := filepath.Join(e.cfg.StateDir, "machines", "m1", "disk", "upper")
			for _, d := range []string{"a", strings.Repeat("n", 200)} {
				must(t, os.RemoveAll(filepath.Join(upper, d)))
			}
			if _, err := e.m.Step(bg, "m1"); err != nil {
				t.Fatalf("snapshot once flattened: %v", err)
			}
		})
	}
}

// Security M4 on SR2-3i: what must checkpoint first (a fork, PE7 sleep) is
// refused while the layer cannot be copied, never run unchecked, and
// leaves nothing behind.
func TestATooDeepLayerRefusesWhatNeedsACheckpoint(t *testing.T) {
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 8192)
			e.open()
			e.create("m1", admission.Accepted, 100)
			shape(e, "m1")
			_, err := e.m.Fork(bg, "m1", []string{"m2"})
			if !errors.Is(err, ErrQuota) {
				t.Fatalf("fork: %v", err)
			}
			e.noHostPath(err)
			if _, err := e.m.Get("m2"); err == nil {
				t.Fatal("refused fork left a machine")
			}
			_, err = e.m.CheckpointAndStop(bg, "m1")
			if !errors.Is(err, ErrQuota) {
				t.Fatalf("sleep: %v", err)
			}
			e.noHostPath(err)
			if mc, _ := e.m.Get("m1"); mc.State != Running || len(e.m.Snapshots("m1")) != 0 {
				t.Fatalf("after refusals: %s, %d snapshots", mc.State, len(e.m.Snapshots("m1")))
			}
		})
	}
}

// What undoes or ends a machine (rollback, erasure, destroy) never measures
// the live layer, so such a machine can always be undone.
func TestATooDeepMachineCanStillBeUndone(t *testing.T) {
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 8192)
			e.open()
			mc := e.create("m1", admission.Accepted, 100)
			s, err := e.m.Step(bg, "m1")
			must(t, err)
			shape(e, "m1")
			must(t, e.m.Rollback(bg, "m1", s.ID))
			if _, err := e.m.Step(bg, "m1"); err != nil {
				t.Fatalf("snapshot after the rollback: %v", err)
			}
			shape(e, "m1")
			must(t, e.m.ForgetSince(bg, mc.Lineage, s.Taken))
			shape(e, "m1")
			must(t, e.m.Destroy(bg, "m1"))
		})
	}
}

// Such a worker is parked as one over its cap is: stopped without a
// snapshot, its memory back, revived by a rollback.
func TestATooDeepWorkerStillParks(t *testing.T) {
	for name, shape := range shapes {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 8192)
			e.open()
			a := e.create("agent", admission.Accepted, 100)
			id := WorkerPrefix + "1"
			_, err := e.m.CreateWorker(bg, id, a.Lineage, Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
			must(t, err)
			shape(e, id)
			if _, err := e.m.Park(bg, id); err != nil {
				t.Fatalf("park: %v", err)
			}
			if w, _ := e.m.Get(id); w.State == Running {
				t.Fatal("still running after park")
			}
		})
	}
}
