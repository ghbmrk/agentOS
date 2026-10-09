package vm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

// chainTo makes a chain of directories in id's layer whose deepest path,
// "/"-led and relative to the layer, is exactly n bytes long.
func (e *env) chainTo(id string, n int) {
	e.t.Helper()
	fd, err := syscall.Open(filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper"), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	must(e.t, err)
	for n > 0 {
		l := min(n-1, 200)
		if r := n - 1 - l; r > 0 && r < 2 { // leave room for one more "/x"
			l--
		}
		name := strings.Repeat("c", l)
		must(e.t, syscall.Mkdirat(fd, name, 0o755))
		next, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		syscall.Close(fd)
		must(e.t, err)
		fd = next
		n -= 1 + l
	}
	syscall.Close(fd)
}

// L3 MUST-A on #174: the path limit is set by the longest root any copy of
// a layer can have, never by the measured layer's own root, so a layer a
// short-ID machine snapshots at the limit restores and forks (into the
// longest ID) too; one byte past it is refused at the snapshot.
func TestThePathLimitIsTheSameForEveryCopy(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	longest := max(len(filepath.Join(e.m.diskDir(strings.Repeat("x", maxIDLen)), "upper")),
		len(filepath.Join(e.m.snapDir(snapName(0)), "fs")))
	room := 4095 - longest

	e.create("m", admission.Accepted, 100)
	e.chainTo("m", room)
	s, err := e.m.Step(bg, "m")
	if err != nil {
		t.Fatalf("snapshot at the limit: %v", err)
	}
	must(t, e.m.Rollback(bg, "m", s.ID))
	if _, err := e.m.Fork(bg, "m", []string{strings.Repeat("f", maxIDLen)}); err != nil {
		t.Fatalf("fork at the limit: %v", err)
	}

	e.create("n", admission.Accepted, 100)
	e.chainTo("n", room+1)
	_, err = e.m.Step(bg, "n")
	if !errors.Is(err, ErrQuota) {
		t.Fatalf("snapshot past the limit: %v", err)
	}
	e.noHostPath(err)
}

// mountIn mounts a tmpfs inside id's layer, a layer measure refuses
// without it being too deep or too long; the test skips without root.
func (e *env) mountIn(id string) {
	e.t.Helper()
	if os.Getuid() != 0 {
		e.t.Skip("mounting needs root (CI machines job)")
	}
	mnt := filepath.Join(e.cfg.StateDir, "machines", id, "disk", "upper", "mnt")
	must(e.t, os.Mkdir(mnt, 0o755))
	if err := syscall.Mount("tmpfs", mnt, "tmpfs", 0, "size=1m"); err != nil {
		e.t.Skip(err)
	}
	e.t.Cleanup(func() { syscall.Unmount(mnt, syscall.MNT_DETACH) })
}

// A worker whose snapshot fails for any other reason is still parked:
// stopped, its memory back, never left running (L3 SHOULD on #174).
func TestAWorkerThatCannotBeSnapshottedStillParks(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	a := e.create("agent", admission.Accepted, 100)
	id := WorkerPrefix + "1"
	_, err := e.m.CreateWorker(bg, id, a.Lineage, Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
	must(t, err)
	e.mountIn(id)
	if _, err := e.m.Step(bg, id); err == nil || errors.Is(err, ErrQuota) {
		t.Fatalf("snapshot across a mount: %v", err)
	}
	if _, err := e.m.Park(bg, id); err != nil {
		t.Fatalf("park: %v", err)
	}
	if w, _ := e.m.Get(id); w.State == Running {
		t.Fatal("still running after park")
	}
}

// A deletion after which the layer cannot be measured for any reason
// counts as over the cap: it stands, and the worker stays stopped (L3
// SHOULD K2 on #174).
func TestCAP8cDeleteStandsWhenMeasuringFails(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	_, err = e.m.Exec(bg, "wk-a", Command{Argv: []string{"write", "f"}}, time.Second)
	must(t, err)
	e.mountIn("wk-a")
	rep, err := e.m.DeleteFiles(bg, "wk-a", Deletion{Paths: []string{"/f"}})
	must(t, err)
	if rep.Codes[0] != "removed" || !rep.Over || rep.Restarted {
		t.Fatalf("delete in a layer that cannot be measured = %+v", rep)
	}
	if w, _ := e.m.Get("wk-a"); w.State != Stopped {
		t.Fatalf("worker is %s, want stopped", w.State)
	}
}
