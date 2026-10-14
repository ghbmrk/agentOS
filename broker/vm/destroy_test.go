package vm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
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
// Rollback (with and without a label raise) and Rebuild revived the
// machine before the fix. Resume never did: by the time its admission is
// granted the destroy has removed the layer it restarts on, so it fails
// anyway; it is kept as a guard on that path.
func TestRES2DestroyRacingRestartAdmissionLeavesNothing(t *testing.T) {
	ops := map[string]func(m *Manager, snap string) error{
		"rollback":       func(m *Manager, snap string) error { return m.Rollback(bg, "exp", snap) },
		"rollback-raise": func(m *Manager, snap string) error { return m.Rollback(bg, "exp", snap) },
		"resume-guard":   func(m *Manager, _ string) error { return m.Resume(bg, "exp") },
		"rebuild":        func(m *Manager, _ string) error { return m.Rebuild(bg, "exp") },
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
			if name == "rollback-raise" {
				// A snapshot labelled above the machine: Rollback raises
				// the label (raiseLocked) after claiming the machine.
				e.m.mu.Lock()
				s := e.m.snaps[snap.ID]
				s.Label = Private
				e.m.snaps[snap.ID] = s
				e.m.mu.Unlock()
			}
			// Stopped as admission preempts it: killed, then let go.
			must(t, e.m.Preempt("exp"))
			e.adm.Release("exp")
			waitState(t, e, "exp", Preempted)
			mc, err := e.m.get("exp")
			must(t, err)

			g.id = "exp"
			opErr := make(chan error, 1)
			go func() { opErr <- op(e.m, snap.ID) }()
			<-g.entered // the restart is waiting for admission
			destroyed := make(chan error, 1)
			go func() { destroyed <- e.m.Destroy(bg, "exp") }()
			// The order pinned: the admission is asked before the destroy
			// and granted after Destroy holds the machine's lock. Destroy
			// waits on it (admitMu), retires the machine, and only then
			// can the restart take the lock, which it must refuse.
			for mc.mu.TryLock() {
				mc.mu.Unlock()
				time.Sleep(time.Millisecond)
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

// An operation whose lookup found a machine that is destroyed and replaced
// under the same ID before it takes the lock acts on neither: the new
// machine's layer, record and label stay as they were (security B1 on
// #1575). The old worker was private and of one lineage; the new one is
// public and of another, so a write through the old handle would show.
func TestRES2StaleHandleLeavesSameIDSuccessorAlone(t *testing.T) {
	const id = "wk-a"
	ops := map[string]func(e *env, old *machine) error{
		"destroy": func(e *env, _ *machine) error { return e.m.Destroy(bg, id) },
		"raise":   func(e *env, _ *machine) error { return e.m.RaiseLabel(id, Private) },
		"delete": func(e *env, _ *machine) error {
			_, err := e.m.DeleteFiles(bg, id, Deletion{Paths: []string{"/keep"}, As: Private})
			return err
		},
		"exec": func(e *env, _ *machine) error {
			_, err := e.m.Exec(bg, id, Command{Argv: []string{"true"}, As: Private}, time.Second)
			return err
		},
		"checkpoint": func(e *env, _ *machine) error { _, err := e.m.Checkpoint(bg, id); return err },
		"sleep":      func(e *env, _ *machine) error { _, err := e.m.CheckpointAndStop(bg, id); return err },
		"park":       func(e *env, _ *machine) error { _, err := e.m.Park(bg, id); return err },
		// ForgetSince listed the old machine before the destroy.
		"forget": func(e *env, old *machine) error { return e.m.forgetMachine(bg, old, time.Time{}) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 4096)
			a1 := e.create("a1", admission.Experiment, 500)
			a2 := e.create("a2", admission.Experiment, 500)
			_, err := e.m.CreateWorker(bg, id, a1.Lineage, workerSpec(Private))
			must(t, err)
			_, err = e.m.Checkpoint(bg, id)
			must(t, err)
			old, err := e.m.get(id)
			must(t, err)
			meta := filepath.Join(e.cfg.StateDir, "machines", id, "meta.json")
			var before []byte
			replace := func() {
				must(t, e.m.Destroy(bg, id))
				_, err := e.m.CreateWorker(bg, id, a2.Lineage, workerSpec(Public))
				must(t, err)
				e.guestWrite(id, "keep", "successor's")
				b, err := os.ReadFile(meta)
				must(t, err)
				before = b
			}
			if name == "forget" {
				replace()
			} else {
				e.m.afterGet = func(string) {
					e.m.afterGet = nil
					replace()
				}
			}
			if err := op(e, old); name != "forget" && !errors.Is(err, ErrUnknown) {
				t.Errorf("%s through the old handle: %v, want ErrUnknown", name, err)
			}
			if before == nil {
				t.Fatal("the operation never looked the machine up")
			}
			if after, err := os.ReadFile(meta); err != nil || !bytes.Equal(after, before) {
				t.Errorf("%s rewrote the new machine's record: %s (%v)", name, after, err)
			}
			if got := e.guestRead(id, "keep"); got != "successor's" {
				t.Errorf("%s reached the new machine's layer: keep = %q", name, got)
			}
			if l, err := e.m.Label(id); err != nil || l != Public {
				t.Errorf("new machine's label %v (%v), want public", l, err)
			}
			if _, ok := e.rt.memOf(id); !ok {
				t.Errorf("%s stopped the new machine", name)
			}
			if _, ok := e.adm.Snapshot().Running[id]; !ok {
				t.Errorf("%s took the new machine's admission", name)
			}
			if w, err := e.m.Get(id); err != nil || w.Lineage != a2.Lineage {
				t.Errorf("new machine's record %+v (%v)", w, err)
			}
		})
	}
}
