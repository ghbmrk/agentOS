package vm

import (
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-2

// A same-ID successor started between admission's victim choice and its
// Preempt keeps running and is not marked preempted: admission preempts
// the life it picked, and the successor is another life (#2144).
func TestRES2PreemptSparesASameIDSuccessorStartedAfterThePick(t *testing.T) {
	e := newEnv(t, 2500)
	e.create("y", admission.Experiment, 1000)
	old := e.create("v", admission.Experiment, 1000)
	var successor Machine
	e.beforePreempt = func(id string) {
		if id != "v" {
			return
		}
		e.beforePreempt = nil
		must(t, e.m.Destroy(bg, "v"))
		successor = e.create("v", admission.Experiment, 500)
	}
	e.create("x", admission.Foreground, 1000) // picks v, the newest experiment
	if successor.Instance == "" || successor.Instance == old.Instance {
		t.Fatalf("no successor life: old %q, successor %q", old.Instance, successor.Instance)
	}
	w, err := e.m.Get("v")
	if err != nil || w.State != Running || w.Instance != successor.Instance {
		t.Fatalf("successor v: %+v (%v), want running", w, err)
	}
	if _, live := e.rt.memOf("v"); !live {
		t.Error("the successor's guest was killed")
	}
	got, ok := e.adm.Snapshot().Running["v"]
	if !ok || got.MemMB != 500 || got.Instance != successor.Instance {
		t.Errorf("successor v not counted: %+v", e.adm.Snapshot().Running)
	}
}

// PreemptInstance preempts the life it names, and refuses any other with
// ErrUnknown, leaving that machine running and free to be operated on.
func TestRES2PreemptInstanceChecksTheLife(t *testing.T) {
	e := newEnv(t, 4000)
	v := e.create("v", admission.Experiment, 1000)
	if err := e.m.PreemptInstance("v", "not-"+v.Instance); !errors.Is(err, ErrUnknown) {
		t.Fatalf("stale life: %v, want ErrUnknown", err)
	}
	mc, err := e.m.get("v")
	must(t, err)
	if mc.preempting.Load() {
		t.Error("a refused preemption left v preempting")
	}
	if w, _ := e.m.Get("v"); w.State != Running {
		t.Fatalf("v after a stale preemption: %v", w.State)
	}
	must(t, e.m.PreemptInstance("v", v.Instance))
	if w, _ := e.m.Get("v"); w.State != Preempted {
		t.Fatalf("v after its own preemption: %v", w.State)
	}
	if err := e.m.PreemptInstance("gone", "x"); err != nil {
		t.Errorf("unknown machine: %v, want nil (nothing holds memory)", err)
	}
}
