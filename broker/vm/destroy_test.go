package vm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
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
			// and granted only once Destroy holds the machine's lock and
			// has either returned or stayed blocked a while. Destroy waits
			// on it (admitMu), retires the machine, and only then can the
			// restart take the lock, which it must refuse. Without
			// admitMu, Destroy returns first and the late grant stays
			// counted (L3 B1, potency P1 on #1575).
			var derr error
			done := false
			for !done && mc.mu.TryLock() {
				mc.mu.Unlock()
				select {
				case derr = <-destroyed:
					done = true
				case <-time.After(time.Millisecond):
				}
			}
			if !done {
				select {
				case derr = <-destroyed:
					done = true
				case <-time.After(300 * time.Millisecond):
				}
			}
			close(g.gate)
			if err := <-opErr; !errors.Is(err, ErrUnknown) {
				t.Errorf("%s racing destroy: %v, want ErrUnknown", name, err)
			}
			if !done {
				select {
				case derr = <-destroyed:
				case <-time.After(5 * time.Second):
					t.Fatal("destroy did not finish")
				}
			}
			must(t, derr)
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
	// Each guard on its own: the record, the claim and the start refuse
	// the old handle, and Resume's fallback to a rebuild (the ID's layer
	// gone) goes through the handle, not the ID.
	meta := filepath.Join(e.cfg.StateDir, "machines", "exp", "meta.json")
	before, err := os.ReadFile(meta)
	must(t, err)
	old.mu.Lock()
	if err := e.m.saveMachine(old); !errors.Is(err, ErrUnknown) {
		t.Errorf("saving the destroyed machine's record: %v, want ErrUnknown", err)
	}
	if err := claimLocked(old); !errors.Is(err, ErrUnknown) {
		t.Errorf("claiming the destroyed machine: %v, want ErrUnknown", err)
	}
	if err := e.m.startFrom(context.Background(), old, keepLayer); !errors.Is(err, ErrUnknown) {
		t.Errorf("starting the destroyed machine: %v, want ErrUnknown", err)
	}
	old.mu.Unlock()
	if after, err := os.ReadFile(meta); err != nil || !bytes.Equal(after, before) {
		t.Errorf("the new machine's record was rewritten: %s (%v)", after, err)
	}
	upper := e.m.launch(old).Upper
	must(t, os.Rename(upper, upper+".aside"))
	if err := e.m.resumeOf(context.Background(), old); !errors.Is(err, ErrUnknown) {
		t.Errorf("resume of the destroyed machine with no layer: %v, want ErrUnknown", err)
	}
	must(t, os.Rename(upper+".aside", upper))
	if w, err := e.m.Get("exp"); err != nil || w.Starts != 1 {
		t.Errorf("the new machine was restarted: %+v (%v)", w, err)
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
// machine's layer, record, label, admission and guest stay as they were
// (security B1 and S1 on #1575). The old worker was private and of one
// lineage; the new one is public and of another, so a write through the
// old handle would show. ForgetSince and a dropped snapshot reach the old
// handle without a lookup, so they run it after the replacement directly.
func TestRES2StaleHandleLeavesSameIDSuccessorAlone(t *testing.T) {
	const id = "wk-a"
	type op struct {
		// sleep puts the old machine to sleep first, for a wake.
		sleep bool
		// direct: the handle is held from before the replacement, not
		// looked up across it.
		direct bool
		// stale holds the old handle's lock across the call, as Prune's
		// read does, so Preempt cannot take it.
		stale bool
		want  error // nil: no error
		run   func(t *testing.T, e *env, old *machine, snap Snapshot) error
	}
	ops := map[string]op{
		"destroy": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { return e.m.Destroy(bg, id) }},
		"raise":   {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { return e.m.RaiseLabel(id, Private) }},
		"delete": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error {
			_, err := e.m.DeleteFiles(bg, id, Deletion{Paths: []string{"/keep"}, As: Private})
			return err
		}},
		"exec": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error {
			_, err := e.m.Exec(bg, id, Command{Argv: []string{"true"}, As: Private}, time.Second)
			return err
		}},
		"checkpoint": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { _, err := e.m.Checkpoint(bg, id); return err }},
		"sleep": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error {
			_, err := e.m.CheckpointAndStop(bg, id)
			return err
		}},
		"park": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { _, err := e.m.Park(bg, id); return err }},
		// Reads: a retired record is not answered as the ID's.
		"get":   {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { _, err := e.m.Get(id); return err }},
		"label": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { _, err := e.m.Label(id); return err }},
		"tryget": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error {
			if w, ok := e.m.TryGet(id); ok {
				return fmt.Errorf("answered the retired record %+v", w)
			}
			return ErrUnknown
		}},
		"rollback": {want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, s Snapshot) error { return e.m.Rollback(bg, id, s.ID) }},
		// Preempt's kill goes without the lock, by the ID's cgroup or
		// sandbox: it must not reach the new machine (S1a).
		"preempt": {stale: true, want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, _ Snapshot) error { return e.m.Preempt(id) }},
		// A wake through the old handle neither restores the predecessor's
		// checkpoint nor drops it: it is the destroyed machine's, kept
		// until pruned (S1b).
		"wake": {sleep: true, want: ErrUnknown, run: func(t *testing.T, e *env, _ *machine, s Snapshot) error {
			w, err := e.m.ResumeFromCheckpoint(bg, id, s.ID)
			if w != (Wake{}) {
				t.Errorf("wake through the old handle: %+v", w)
			}
			if _, serr := e.m.Snapshot(s.ID); serr != nil {
				t.Errorf("the destroyed machine's sleep checkpoint went with a stale wake: %v", serr)
			}
			return err
		}},
		// ForgetSince listed the old machine before the destroy.
		"forget": {direct: true, run: func(t *testing.T, e *env, old *machine, _ Snapshot) error {
			return e.m.forgetMachine(bg, old, time.Time{})
		}},
		// ResumeFromCheckpoint's or Fork's drop of a snapshot it took.
		"drop": {direct: true, run: func(t *testing.T, e *env, old *machine, s Snapshot) error {
			e.m.dropSnapshot(old, s.ID, "")
			return nil
		}},
	}
	for name, o := range ops {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 4096)
			a1 := e.create("a1", admission.Experiment, 500)
			a2 := e.create("a2", admission.Experiment, 500)
			_, err := e.m.CreateWorker(bg, id, a1.Lineage, workerSpec(Private))
			must(t, err)
			snap, err := e.m.Checkpoint(bg, id)
			must(t, err)
			if o.sleep {
				snap, err = e.m.CheckpointAndStop(bg, id)
				must(t, err)
			}
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
				if o.stale {
					old.mu.Lock()
					go func() { time.Sleep(50 * time.Millisecond); old.mu.Unlock() }()
				}
			}
			if o.direct {
				replace()
			} else {
				e.m.afterGet = func(string) {
					e.m.afterGet = nil
					replace()
				}
			}
			err = o.run(t, e, old, snap)
			if o.want == nil && err != nil || o.want != nil && !errors.Is(err, o.want) {
				t.Errorf("%s through the old handle: %v, want %v", name, err, o.want)
			}
			if before == nil {
				t.Fatal("the operation never looked the machine up")
			}
			if o.stale {
				old.mu.Lock() // the stale holder let go
				old.mu.Unlock()
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
			if w, err := e.m.Get(id); err != nil || w.Lineage != a2.Lineage || w.State != Running {
				t.Errorf("new machine's record %+v (%v)", w, err)
			}
		})
	}
}

// A machine given a destroyed machine's ID cannot roll back to, or merge
// against, the old machine's snapshots: they are of another life, even
// when the lineage is the same, as for a worker recreated for one agent
// (#1561, security S1b on #1575). Before, any snapshot with the ID passed.
func TestRES2SuccessorCannotUseAPredecessorsSnapshots(t *testing.T) {
	t.Run("agent", func(t *testing.T) {
		e := newEnv(t, 4096)
		e.create("exp", admission.Experiment, 500)
		e.guestWrite("exp", "who", "predecessor")
		s, err := e.m.Checkpoint(bg, "exp")
		must(t, err)
		must(t, e.m.Destroy(bg, "exp"))
		e.create("exp", admission.Experiment, 500)
		e.guestWrite("exp", "who", "successor")
		if err := e.m.Rollback(bg, "exp", s.ID); !errors.Is(err, ErrLineage) {
			t.Errorf("rollback to the predecessor's snapshot: %v, want ErrLineage", err)
		}
		if got := e.guestRead("exp", "who"); got != "successor" {
			t.Errorf("who = %q, want the successor's", got)
		}
	})
	t.Run("worker-same-lineage", func(t *testing.T) {
		e := newEnv(t, 4096)
		a1 := e.create("a1", admission.Experiment, 500)
		_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
		must(t, err)
		e.guestWrite("wk-a", "who", "predecessor")
		s, err := e.m.Checkpoint(bg, "wk-a")
		must(t, err)
		must(t, e.m.Destroy(bg, "wk-a"))
		_, err = e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
		must(t, err)
		e.guestWrite("wk-a", "who", "successor")
		if err := e.m.Rollback(bg, "wk-a", s.ID); !errors.Is(err, ErrLineage) {
			t.Errorf("rollback to the predecessor's snapshot in the same lineage: %v, want ErrLineage", err)
		}
		if got := e.guestRead("wk-a", "who"); got != "successor" {
			t.Errorf("who = %q, want the successor's", got)
		}
	})
	t.Run("worker-recorded-before-instance", func(t *testing.T) {
		// A snapshot and machine recorded before Instance (security S-N1
		// on #1575): after the upgrade the snapshot is the machine's own,
		// and no successor's.
		e := newEnv(t, 4096)
		a1 := e.create("a1", admission.Experiment, 500)
		_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
		must(t, err)
		e.guestWrite("wk-a", "who", "predecessor")
		s, err := e.m.Checkpoint(bg, "wk-a")
		must(t, err)
		s.Instance = ""
		must(t, writeJSON(filepath.Join(e.m.snapDir(s.ID), "meta.json"), s))
		mc, err := e.m.get("wk-a")
		must(t, err)
		mc.mu.Lock()
		mc.Instance = ""
		must(t, writeJSON(filepath.Join(e.m.machineDir("wk-a"), "meta.json"), mc.Machine))
		mc.mu.Unlock()
		e.adm.Release("wk-a")
		e.open() // the upgrade
		e.guestWrite("wk-a", "who", "later")
		must(t, e.m.Rollback(bg, "wk-a", s.ID))
		if got := e.guestRead("wk-a", "who"); got != "predecessor" {
			t.Errorf("rollback to its own snapshot after the upgrade: who = %q", got)
		}
		must(t, e.m.Destroy(bg, "wk-a"))
		_, err = e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
		must(t, err)
		e.guestWrite("wk-a", "who", "successor")
		e.adm.Release("wk-a")
		e.open() // stamped at the first load, on disk: not the successor's now
		if err := e.m.Rollback(bg, "wk-a", s.ID); !errors.Is(err, ErrLineage) {
			t.Errorf("successor's rollback to the predecessor's pre-upgrade snapshot: %v, want ErrLineage", err)
		}
		if got := e.guestRead("wk-a", "who"); got != "successor" {
			t.Errorf("who = %q, want the successor's", got)
		}
	})
	t.Run("recorded-before-instance-other-lineage", func(t *testing.T) {
		// Recorded before Instance in another lineage than the machine of
		// its ID at the upgrade: it is no machine's.
		e := newEnv(t, 4096)
		e.create("exp", admission.Experiment, 500)
		s, err := e.m.Checkpoint(bg, "exp")
		must(t, err)
		s.Instance, s.Lineage = "", "elsewhere"
		must(t, writeJSON(filepath.Join(e.m.snapDir(s.ID), "meta.json"), s))
		e.adm.Release("exp")
		e.open()
		if err := e.m.Rollback(bg, "exp", s.ID); !errors.Is(err, ErrLineage) {
			t.Errorf("rollback to another lineage's pre-upgrade snapshot: %v, want ErrLineage", err)
		}
	})
	t.Run("merge", func(t *testing.T) {
		e := newEnv(t, 4096)
		e.create("a1", admission.Experiment, 500)
		_, err := e.m.Fork(bg, "a1", []string{"b1"})
		must(t, err)
		e.guestWrite("b1", "f", "fork's")
		must(t, e.m.Destroy(bg, "a1"))
		e.create("a1", admission.Experiment, 500)
		e.guestWrite("a1", "who", "successor")
		if _, err := e.m.Merge(bg, "a1", "b1"); !errors.Is(err, ErrLineage) {
			t.Errorf("merge of the predecessor's fork into the successor: %v, want ErrLineage", err)
		}
		if got := e.guestRead("a1", "f"); got != "" {
			t.Errorf("the predecessor's fork merged into the successor: f = %q", got)
		}
		if w, err := e.m.Get("a1"); err != nil || w.State != Running {
			t.Errorf("successor %+v (%v), want running", w, err)
		}
	})
	t.Run("wake", func(t *testing.T) {
		// A wake of the successor with its predecessor's sleep checkpoint
		// is cold, and leaves that checkpoint for Prune: it is another
		// machine's.
		e := newEnv(t, 4096)
		e.create("exp", admission.Experiment, 500)
		s, err := e.m.CheckpointAndStop(bg, "exp")
		must(t, err)
		must(t, e.m.Destroy(bg, "exp"))
		e.create("exp", admission.Experiment, 500)
		_, err = e.m.CheckpointAndStop(bg, "exp")
		must(t, err)
		w, err := e.m.ResumeFromCheckpoint(bg, "exp", s.ID)
		must(t, err)
		if w != (Wake{Cold: ColdNotSleep}) {
			t.Errorf("wake with the predecessor's checkpoint: %+v, want cold: %s", w, ColdNotSleep)
		}
		if _, err := e.m.Snapshot(s.ID); err != nil {
			t.Errorf("the predecessor's sleep checkpoint was dropped: %v", err)
		}
	})
	t.Run("merge-stale-destination", func(t *testing.T) {
		// Merge looked dst up, then dst was destroyed and replaced: the old
		// handle is refused as gone, before its state is even read.
		e := newEnv(t, 4096)
		e.create("a1", admission.Experiment, 500)
		_, err := e.m.Fork(bg, "a1", []string{"b1"})
		must(t, err)
		e.guestWrite("b1", "f", "fork's")
		e.m.afterGet = func(id string) {
			if id != "a1" {
				return
			}
			e.m.afterGet = nil
			must(t, e.m.Destroy(bg, "a1"))
			e.create("a1", admission.Experiment, 500)
		}
		if _, err := e.m.Merge(bg, "a1", "b1"); !errors.Is(err, ErrUnknown) {
			t.Errorf("merge into a destination destroyed after its lookup: %v, want ErrUnknown", err)
		}
		if got := e.guestRead("a1", "f"); got != "" {
			t.Errorf("merged into the successor: f = %q", got)
		}
	})
}

// Preempt has passed killLive's retired check and is killing when Destroy
// retires the machine and a successor is created under its ID. killMu
// holds the retire off until the kill is done, so no successor exists for
// the ID-named kill to reach (security S1a, potency P-B2 on #1575).
func TestRES2PreemptKillHoldsOffDestroy(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("exp", admission.Experiment, 500)
	old, err := e.m.get("exp")
	must(t, err)
	old.mu.Lock() // Preempt cannot take it: the lock-free kill
	fired := false
	e.rt.onKill = func(id string) {
		if fired || id != "exp" {
			return
		}
		fired = true
		made := make(chan struct{})
		go func() {
			must(t, e.m.Destroy(bg, "exp"))
			e.create("exp", admission.Experiment, 500)
			close(made)
		}()
		old.mu.Unlock()
		select {
		case <-made: // without killMu: the successor exists now
		case <-time.After(200 * time.Millisecond):
		}
	}
	_ = e.m.Preempt("exp")
	deadline := time.Now().Add(5 * time.Second)
	for {
		if w, err := e.m.Get("exp"); err == nil && w.State == Running && w.Instance != old.Instance {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no successor")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !fired {
		t.Fatal("the kill never ran")
	}
	if _, ok := e.rt.memOf("exp"); !ok {
		t.Error("Preempt's kill reached the successor")
	}
}

// ForgetSince of one lineage resets a machine whose ID an earlier machine
// of another lineage had, and deletes only that machine's own snapshots
// taken since: the earlier machine's stay its lineage's, a surviving
// fork's base among them (#1575).
func TestRES2ForgetSinceLeavesAnEarlierMachinesSnapshotsOfAnotherLineage(t *testing.T) {
	e := newEnv(t, 4096)
	a1 := e.create("a1", admission.Experiment, 500)
	a2 := e.create("a2", admission.Experiment, 500)
	since := time.Now()
	_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
	must(t, err)
	_, err = e.m.Fork(bg, "wk-a", []string{"wk-b"})
	must(t, err)
	wb, err := e.m.Get("wk-b")
	must(t, err)
	prev, err := e.m.Checkpoint(bg, "wk-a")
	must(t, err)
	must(t, e.m.Destroy(bg, "wk-a"))
	_, err = e.m.CreateWorker(bg, "wk-a", a2.Lineage, workerSpec(Public))
	must(t, err)
	own, err := e.m.Checkpoint(bg, "wk-a")
	must(t, err)
	must(t, e.m.ForgetSince(bg, a2.Lineage, since))
	for _, id := range []string{prev.ID, wb.ForkBase} {
		if _, err := e.m.Snapshot(id); err != nil {
			t.Errorf("snapshot %s of the earlier wk-a, of lineage %s, was deleted: %v", id, a1.Lineage, err)
		}
	}
	if _, err := e.m.Snapshot(own.ID); err == nil {
		t.Errorf("the reset wk-a's own snapshot %s, taken since, was kept", own.ID)
	}
}

// A wake that checked the old machine, which is then destroyed and
// replaced under its ID by a preempted machine, neither restores nor
// resumes the new one: the restore and the cold resume go through the
// handle it checked (security S1b on #1575).
func TestRES2WakeActsOnlyOnTheMachineItChecked(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("exp", admission.Experiment, 500)
	s, err := e.m.CheckpointAndStop(bg, "exp")
	must(t, err)
	e.m.afterCheck = func(string) {
		e.m.afterCheck = nil
		must(t, e.m.Destroy(bg, "exp"))
		e.create("exp", admission.Experiment, 500)
		must(t, e.m.Preempt("exp"))
		e.adm.Release("exp")
		waitState(t, e, "exp", Preempted)
		e.guestWrite("exp", "who", "successor")
	}
	w, err := e.m.ResumeFromCheckpoint(bg, "exp", s.ID)
	if w.Restored || !errors.Is(err, ErrUnknown) {
		t.Errorf("wake after the checks: %+v, %v; want not restored, ErrUnknown", w, err)
	}
	if got, err := e.m.Get("exp"); err != nil || got.State != Preempted {
		t.Errorf("successor %+v (%v), want left preempted", got, err)
	}
	if _, ok := e.rt.memOf("exp"); ok {
		t.Error("the successor was started")
	}
	if got := e.guestRead("exp", "who"); got != "successor" {
		t.Errorf("who = %q, want the successor's", got)
	}
}

// A fork reserved, then destroyed and replaced under its ID while the
// source is paused for the fork's checkpoint: the fork fails, and its
// cleanup leaves the new machine alone (security P-B1 on #1575).
func TestRES2ForkCleanupLeavesASameIDSuccessorAlone(t *testing.T) {
	e := newEnv(t, 4096)
	a1 := e.create("a1", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
	must(t, err)
	replaced := make(chan error, 1)
	fired := false
	e.rt.onPause = func(id string) {
		if fired || id != "wk-a" {
			return
		}
		fired = true
		go func() {
			if err := e.m.Destroy(bg, "wk-b"); err != nil {
				replaced <- err
				return
			}
			_, err := e.m.CreateWorker(bg, "wk-b", a1.Lineage, workerSpec(Public))
			replaced <- err
		}()
		time.Sleep(200 * time.Millisecond) // the replacement runs as far as the runtime's lock
	}
	if _, err := e.m.Fork(bg, "wk-a", []string{"wk-b"}); !errors.Is(err, ErrUnknown) {
		t.Errorf("fork whose new machine was destroyed: %v, want ErrUnknown", err)
	}
	must(t, <-replaced)
	e.guestWrite("wk-b", "keep", "successor's")
	if _, ok := e.rt.memOf("wk-b"); !ok {
		t.Error("the fork's cleanup stopped the successor")
	}
	if w, err := e.m.Get("wk-b"); err != nil || w.State != Running || w.ForkBase != "" {
		t.Errorf("successor %+v (%v), want running, not a fork", w, err)
	}
	if _, ok := e.adm.Snapshot().Running["wk-b"]; !ok {
		t.Error("the fork's cleanup took the successor's admission")
	}
}

// ForgetSince keeps track of the machines it reset by instance, not ID: a
// machine destroyed and replaced under one ID of the lineage while the
// reset runs is a new machine, and is reset in its own right (security B1
// on #1575). Keyed by ID, the replacement passed as already done and kept
// what it wrote.
func TestRES2ForgetSinceResetsASameIDSuccessorInItsOwnRight(t *testing.T) {
	e := newEnv(t, 4096)
	a1 := e.create("a1", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
	must(t, err)
	since := time.Now()
	replaced := false
	e.rt.onStart = func(id string) {
		// a1 restarting from its image, under its lock, as it is reset.
		if replaced || id != "a1" {
			return
		}
		replaced = true
		must(t, e.m.Destroy(bg, "wk-a"))
		_, err := e.m.CreateWorker(bg, "wk-a", a1.Lineage, workerSpec(Public))
		must(t, err)
		e.guestWrite("wk-a", "since", "written after since")
	}
	must(t, e.m.ForgetSince(bg, a1.Lineage, since))
	if !replaced {
		t.Fatal("a1 was never restarted")
	}
	if got := e.guestRead("wk-a", "since"); got != "" {
		t.Errorf("the replacement kept what it wrote after since: %q", got)
	}
	if _, ok := e.rt.memOf("wk-a"); !ok {
		t.Error("the replacement is not running")
	}
}

// hookAdmit runs hook as each admission is asked for, before admission.
type hookAdmit struct {
	*admission.Controller
	hook func(id string)
}

func (h *hookAdmit) Admit(r admission.Request) (admission.Decision, error) {
	if h.hook != nil {
		h.hook(r.ID)
	}
	return h.Controller.Admit(r)
}

// Fork and Merge take their checkpoint of the handle they checked, and
// Fork's rollback destroys the forks it started by handle, so a machine
// destroyed and replaced under one of those IDs part-way is never
// snapshotted, merged from or destroyed in their place (security P-L1 on
// #1575).
func TestRES2ForkAndMergeActOnlyOnTheMachinesTheyChecked(t *testing.T) {
	t.Run("fork-source", func(t *testing.T) {
		e := newEnv(t, 4096)
		h := &hookAdmit{Controller: e.adm}
		e.cfg.Admit = h
		e.open()
		e.create("a1", admission.Experiment, 500)
		h.hook = func(id string) {
			// The fork is being admitted: its source was checked already.
			if id != "b1" {
				return
			}
			h.hook = nil
			must(t, e.m.Destroy(bg, "a1"))
			e.create("a1", admission.Experiment, 500)
		}
		if _, err := e.m.Fork(bg, "a1", []string{"b1"}); !errors.Is(err, ErrUnknown) {
			t.Errorf("fork of a source destroyed after its checks: %v, want ErrUnknown", err)
		}
		if w, err := e.m.Get("a1"); err != nil || w.Last != "" {
			t.Errorf("the successor was checkpointed for the fork: %+v (%v)", w, err)
		}
		if _, err := e.m.Get("b1"); !errors.Is(err, ErrUnknown) {
			t.Errorf("a fork was left: %v", err)
		}
	})
	t.Run("fork-rollback", func(t *testing.T) {
		e := newEnv(t, 4096)
		e.create("a1", admission.Experiment, 500)
		fired := false
		e.rt.onStart = func(id string) {
			// b1 started; b2 is starting. b1 is destroyed and replaced,
			// then b2's start fails, so the fork rolls back what it started.
			if fired || id != "b2" {
				return
			}
			fired = true
			must(t, e.m.Destroy(bg, "b1"))
			e.create("b1", admission.Experiment, 500)
			e.rt.mu.Lock()
			e.rt.failNext = errors.New("synthetic start failure")
			e.rt.mu.Unlock()
		}
		if _, err := e.m.Fork(bg, "a1", []string{"b1", "b2"}); err == nil {
			t.Fatal("fork whose second start failed reported success")
		}
		if !fired {
			t.Fatal("b2 never started")
		}
		if w, err := e.m.Get("b1"); err != nil || w.State != Running || w.ForkBase != "" {
			t.Errorf("the fork's rollback reached the successor b1: %+v (%v)", w, err)
		}
		if _, ok := e.rt.memOf("b1"); !ok {
			t.Error("the fork's rollback stopped the successor b1")
		}
	})
	t.Run("merge-source", func(t *testing.T) {
		e := newEnv(t, 4096)
		e.create("a1", admission.Experiment, 500)
		_, err := e.m.Fork(bg, "a1", []string{"b1"})
		must(t, err)
		e.m.afterCheck = func(id string) {
			// Merge checked b1's containment and fork point.
			e.m.afterCheck = nil
			must(t, e.m.Destroy(bg, id))
			e.create(id, admission.Experiment, 500)
			e.guestWrite(id, "f", "not a fork of a1")
		}
		if _, err := e.m.Merge(bg, "a1", "b1"); !errors.Is(err, ErrUnknown) {
			t.Errorf("merge from a source destroyed after its checks: %v, want ErrUnknown", err)
		}
		if got := e.guestRead("a1", "f"); got != "" {
			t.Errorf("a machine that is not a1's fork merged into it: f = %q", got)
		}
	})
}

// Admission picked a victim by ID, and Preempt looked it up; then the
// victim was destroyed and a new machine admitted under its ID. Preempt
// must not report the destroyed machine as preempted, or admission drops
// the successor's entry and it runs uncounted (security B1 on #1575). In
// "held" the old handle's lock is held, so Preempt kills without it.
func TestRES2PreemptOfADestroyedVictimKeepsTheSuccessorCounted(t *testing.T) {
	for _, held := range []bool{false, true} {
		name := "trylock"
		if held {
			name = "held"
		}
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, 2500)
			e.create("y", admission.Experiment, 1000)
			e.create("v", admission.Experiment, 1000)
			old, err := e.m.get("v")
			must(t, err)
			replaced := false
			e.m.afterGet = func(id string) {
				if id != "v" {
					return
				}
				e.m.afterGet = nil
				must(t, e.m.Destroy(bg, "v"))
				e.create("v", admission.Experiment, 500)
				replaced = true
				if held {
					old.mu.Lock()
					go func() { time.Sleep(50 * time.Millisecond); old.mu.Unlock() }()
				}
			}
			e.create("x", admission.Foreground, 1000) // preempts v, the newest experiment
			if !replaced {
				t.Fatal("admission never preempted v")
			}
			old.mu.Lock() // the stale holder let go
			old.mu.Unlock()
			if _, ok := e.adm.Snapshot().Running["v"]; !ok {
				t.Errorf("the successor v runs uncounted: admission %v", e.adm.Snapshot().Running)
			}
			if w, err := e.m.Get("v"); err != nil || w.State != Running {
				t.Errorf("successor v: %+v (%v), want running", w, err)
			}
		})
	}
}

// DeleteFiles restarts the worker it deleted from through its handle: a
// worker destroyed and recreated under the same name meanwhile is left as
// it is (L3 B2 on #1575, V38 rule 2).
func TestRES2DeleteFilesLeavesASameIDSuccessorAlone(t *testing.T) {
	const id = "wk-a"
	e := newEnv(t, 4096)
	a1 := e.create("a1", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, id, a1.Lineage, workerSpec(Private))
	must(t, err)
	_, err = e.m.Park(bg, id)
	must(t, err)
	e.guestWrite(id, "f", "old")
	replaced := false
	e.m.afterCheck = func(string) {
		e.m.afterCheck = nil
		must(t, e.m.Destroy(bg, id))
		_, err := e.m.CreateWorker(bg, id, a1.Lineage, workerSpec(Private))
		must(t, err)
		_, err = e.m.Park(bg, id)
		must(t, err)
		replaced = true
	}
	rep, err := e.m.DeleteFiles(bg, id, Deletion{Paths: []string{"/f"}, As: Private})
	if !replaced {
		t.Fatal("DeleteFiles never reached the check")
	}
	if rep.Restarted {
		t.Errorf("DeleteFiles reports restarting the successor (err %v)", err)
	}
	if w, err := e.m.Get(id); err != nil || w.State == Running {
		t.Errorf("successor %+v (%v), want it left stopped", w, err)
	}
	if _, ok := e.rt.memOf(id); ok {
		t.Error("DeleteFiles started the successor")
	}
	if _, ok := e.adm.Snapshot().Running[id]; ok {
		t.Error("DeleteFiles admitted the successor")
	}
}

// A create that fails returns its admission before it leaves the table
// (#1712, Potency P3 on #1575). A destroy and a same-ID create run between
// the two steps make a successor, which must keep its admission and its
// table entry. With the steps swapped, the destroy finds nothing and the
// successor's admit is refused, because the failed machine is still
// admitted.
func TestRES2CreateFailureTailLeavesASameIDSuccessorAlone(t *testing.T) {
	e := newEnv(t, 4096)
	ran := false
	var succErr error
	createTailGap = func(id string) {
		if ran || id != "a1" {
			return
		}
		ran = true
		// With the steps swapped the failing machine is already out of
		// the table; the successor's create still decides the test.
		if err := e.m.Destroy(bg, id); err != nil && !errors.Is(err, ErrUnknown) {
			succErr = fmt.Errorf("destroy of the failing machine: %w", err)
			return
		}
		_, succErr = e.m.Create(bg, id, Spec{Image: "base", Class: admission.Experiment, MemMB: 500})
	}
	t.Cleanup(func() { createTailGap = func(string) {} })
	e.rt.failNext = errors.New("start fails")
	if _, err := e.m.Create(bg, "a1", Spec{Image: "base", Class: admission.Experiment, MemMB: 500}); err == nil {
		t.Fatal("create with a failing start succeeded")
	}
	if !ran {
		t.Fatal("the failure tail did not reach the seam")
	}
	if succErr != nil {
		t.Fatalf("successor between release and unreserve: %v", succErr)
	}
	if w, err := e.m.Get("a1"); err != nil || w.State != Running {
		t.Errorf("successor %+v (%v), want listed and running", w, err)
	}
	if _, ok := e.rt.memOf("a1"); !ok {
		t.Error("the failure tail stopped the successor")
	}
	if _, ok := e.adm.Snapshot().Running["a1"]; !ok {
		t.Error("the failure tail took the successor's admission")
	}
}
