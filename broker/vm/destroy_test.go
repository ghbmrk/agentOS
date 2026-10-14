package vm

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-2, A2

// gatedAdmit holds one machine's Admit at a gate, so a test can run
// Destroy while a restart waits for admission.
type gatedAdmit struct {
	*admission.Controller
	id      string
	entered chan struct{}
	gate    chan struct{}
}

func (g *gatedAdmit) Admit(r admission.Request) (admission.Decision, error) {
	if r.ID == g.id {
		g.entered <- struct{}{}
		<-g.gate
	}
	return g.Controller.Admit(r)
}

// A restart of a stopped machine that races its destroy must not bring
// the machine back: not running, not admitted, not in the table (#1561).
func TestRES2DestroyDuringRestartAdmissionLeavesNothingRunning(t *testing.T) {
	ops := map[string]func(m *Manager, snap string) error{
		"rollback": func(m *Manager, snap string) error { return m.Rollback(bg, "exp", snap) },
		"resume":   func(m *Manager, _ string) error { return m.Resume(bg, "exp") },
		"rebuild":  func(m *Manager, _ string) error { return m.Rebuild(bg, "exp") },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 2000)
			g := &gatedAdmit{Controller: e.adm, entered: make(chan struct{}, 1), gate: make(chan struct{})}
			e.cfg.Admit = g
			e.open()
			e.create("exp", admission.Experiment, 1000)
			snap, err := e.m.Checkpoint(bg, "exp")
			must(t, err)
			// Stopped as admission preempts it: killed, then let go.
			must(t, e.m.Preempt("exp"))
			e.adm.Release("exp")
			waitState(t, e, "exp", Preempted)

			g.id = "exp"
			opErr := make(chan error, 1)
			go func() { opErr <- op(e.m, snap.ID) }()
			<-g.entered // the restart is waiting for admission
			destroyed := make(chan error, 1)
			go func() { destroyed <- e.m.Destroy(bg, "exp") }()
			select {
			case err := <-destroyed:
				must(t, err)
				destroyed <- nil
			case <-time.After(300 * time.Millisecond):
				// Destroy may wait for the admission in flight; it must
				// finish once that admission does.
			}
			close(g.gate)
			if err := <-opErr; !errors.Is(err, ErrUnknown) {
				t.Errorf("%s racing destroy: %v, want ErrUnknown", name, err)
			}
			select {
			case err := <-destroyed:
				must(t, err)
			case <-time.After(5 * time.Second):
				t.Fatal("destroy did not finish")
			}
			if _, ok := e.rt.memOf("exp"); ok {
				t.Errorf("%s brought the destroyed machine back", name)
			}
			if got := e.adm.Snapshot().Running; len(got) != 0 {
				t.Errorf("admitted after destroy: %v, want nothing", got)
			}
			if _, err := e.m.Get("exp"); !errors.Is(err, ErrUnknown) {
				t.Errorf("destroyed machine still listed: %v", err)
			}
		})
	}
}

// A handle kept across a destroy cannot admit, start, release or
// unreserve anything, even once a new machine took the same ID (#1561).
func TestRES2StaleHandleAfterDestroyTouchesNothing(t *testing.T) {
	e := newEnv(t, 2000)
	e.create("exp", admission.Experiment, 1000)
	old, err := e.m.get("exp")
	must(t, err)
	must(t, e.m.Destroy(bg, "exp"))
	if err := e.m.admit(old); !errors.Is(err, ErrUnknown) {
		t.Fatalf("admit after destroy: %v, want ErrUnknown", err)
	}
	if got := e.adm.Snapshot().Running; len(got) != 0 {
		t.Fatalf("admitted after destroy: %v", got)
	}
	if err := e.m.Destroy(bg, "exp"); !errors.Is(err, ErrUnknown) {
		t.Fatalf("second destroy: %v, want ErrUnknown", err)
	}
	e.create("exp", admission.Experiment, 1000)
	old.mu.Lock()
	err = e.m.restartLocked(context.Background(), old, keepLayer)
	old.mu.Unlock()
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("restart of the destroyed machine: %v, want ErrUnknown", err)
	}
	e.m.release(old)
	e.m.unreserve(old)
	if got := e.adm.Snapshot().Running; len(got) != 1 {
		t.Fatalf("the new machine's admission went with the old handle: %v", got)
	}
	if _, err := e.m.Get("exp"); err != nil {
		t.Fatalf("the new machine left the table with the old handle: %v", err)
	}
	if _, ok := e.rt.memOf("exp"); !ok {
		t.Fatal("the new machine stopped")
	}
}
