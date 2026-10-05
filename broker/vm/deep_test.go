package vm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// REQ: RES-4, REV-1

// Security R4 on #166: a layer nested deeper than overlay.MaxTreeDepth cannot
// be measured, so it is over the cap: the snapshot is refused with the
// disk-budget text the guest can act on, never taken as no use, and the
// machine keeps running; flattened, it snapshots again.
func TestATooDeepLayerIsOverTheCap(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	e.create("m1", admission.Accepted, 100)
	deep := filepath.Join(strings.Repeat("a/", overlay.MaxTreeDepth+1), "f")
	e.guestWrite("m1", deep, "x")
	_, err := e.m.Step(bg, "m1")
	if !errors.Is(err, ErrQuota) || !strings.Contains(err.Error(), "nest") || strings.Contains(err.Error(), e.cfg.StateDir) {
		t.Fatalf("snapshot of a too-deep layer: %v", err)
	}
	if mc, _ := e.m.Get("m1"); mc.State != Running {
		t.Fatalf("machine %s after the refusal", mc.State)
	}
	must(t, os.RemoveAll(filepath.Join(e.cfg.StateDir, "machines", "m1", "disk", "upper", "a")))
	if _, err := e.m.Step(bg, "m1"); err != nil {
		t.Fatalf("snapshot once flattened: %v", err)
	}
}

// makeDeep nests a file past overlay.MaxTreeDepth in id's layer.
func (e *env) makeDeep(id string) {
	e.t.Helper()
	e.guestWrite(id, filepath.Join(strings.Repeat("a/", overlay.MaxTreeDepth+1), "f"), "x")
}

// Security M4 on SR2-3i: what must checkpoint first (a fork, PE7 sleep, a
// merge's snapshot) is refused while the layer is too deep, never run
// unchecked; what undoes or ends a machine (rollback, erasure, destroy)
// never measures the live layer, so a too-deep machine can always be
// rolled back, erased or destroyed.
func TestATooDeepLayerRefusesWhatNeedsACheckpoint(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	e.create("m1", admission.Accepted, 100)
	e.makeDeep("m1")
	if _, err := e.m.Fork(bg, "m1", []string{"m2"}); !errors.Is(err, ErrQuota) {
		t.Fatalf("fork of a too-deep machine: %v", err)
	}
	if _, err := e.m.Get("m2"); err == nil {
		t.Fatal("refused fork left a machine")
	}
	if _, err := e.m.CheckpointAndStop(bg, "m1"); !errors.Is(err, ErrQuota) {
		t.Fatalf("sleep of a too-deep machine: %v", err)
	}
	if mc, _ := e.m.Get("m1"); mc.State != Running || len(e.m.Snapshots("m1")) != 0 {
		t.Fatalf("after refusals: %s, %d snapshots", mc.State, len(e.m.Snapshots("m1")))
	}
}

func TestATooDeepMachineCanStillBeUndone(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	mc := e.create("m1", admission.Accepted, 100)
	s, err := e.m.Step(bg, "m1")
	must(t, err)
	e.makeDeep("m1")
	must(t, e.m.Rollback(bg, "m1", s.ID))
	if got, _ := e.m.Get("m1"); got.State != Running || e.guestRead("m1", strings.Repeat("a/", overlay.MaxTreeDepth+1)+"f") != "" {
		t.Fatalf("rollback of a too-deep machine: %s", got.State)
	}
	e.makeDeep("m1")
	must(t, e.m.ForgetSince(bg, mc.Lineage, s.Taken))
	e.makeDeep("m1")
	must(t, e.m.Destroy(bg, "m1"))
}

// A too-deep worker is parked as one over its cap is: stopped without a
// snapshot, its memory back, revived by a rollback.
func TestATooDeepWorkerStillParks(t *testing.T) {
	e := newEnv(t, 8192)
	e.open()
	a := e.create("agent", admission.Accepted, 100)
	id := WorkerPrefix + "1"
	_, err := e.m.CreateWorker(bg, id, a.Lineage, Spec{Image: "base", Class: admission.Accepted, MemMB: 100})
	must(t, err)
	e.makeDeep(id)
	if _, err := e.m.Park(bg, id); err != nil {
		t.Fatalf("park of a too-deep worker: %v", err)
	}
	if w, _ := e.m.Get(id); w.State == Running {
		t.Fatal("too-deep worker still running after park")
	}
}
