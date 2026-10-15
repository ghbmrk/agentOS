package vm

// REQ: REV-5

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// LABEL-durable: every way a label rises saves it before the higher-label
// work goes ahead. A failed save leaves the label where it was in memory
// too, so the retry saves again rather than finding the raise done, and a
// restart never finds higher-label content under a lower saved label.

func (e *env) failMeta(id string) func() {
	return failSave(filepath.Join(e.cfg.StateDir, "machines", id, "meta.json"))
}

func (e *env) labelOf(id string) Label {
	e.t.Helper()
	l, err := e.m.Label(id)
	must(e.t, err)
	return l
}

func TestLabelDurableRaiseLabelRestoresOnFailedSave(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Accepted, 500)
	unblock := e.failMeta("agent")
	if err := e.m.RaiseLabel("agent", Private); err == nil {
		t.Fatal("a raise whose save failed reported success")
	}
	unblock()
	if l := e.labelOf("agent"); l != Public {
		t.Fatalf("label %s in memory after a failed save, want the saved public", l)
	}
	must(t, e.m.RaiseLabel("agent", Private))
	e.open()
	if l := e.labelOf("agent"); l != Private {
		t.Fatalf("label %s after a restart, want private", l)
	}
}

func TestLabelDurableWorkerExecRetrySavesTheLabel(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a1", agent.Lineage, workerSpec(Public))
	must(t, err)
	cmd := Command{As: Private, Argv: []string{"write", "out/result"}, Stdin: []byte("canary-private")}
	unblock := e.failMeta("wk-a1")
	if _, err := e.m.Exec(bg, "wk-a1", cmd, time.Second); err == nil {
		t.Fatal("a private command ran although the private label failed to save")
	}
	unblock()
	if l := e.labelOf("wk-a1"); l != Public {
		t.Fatalf("worker label %s in memory after a failed save, want the saved public", l)
	}
	_, err = e.m.Exec(bg, "wk-a1", cmd, time.Second)
	must(t, err)
	e.open()
	if l := e.labelOf("wk-a1"); l != Private {
		t.Fatalf("worker holding private output is %s after a restart", l)
	}
}

func TestLabelDurableWorkerDeleteRetrySavesTheLabel(t *testing.T) {
	e := newEnv(t, 4096)
	agent := e.create("agent", admission.Experiment, 500)
	_, err := e.m.CreateWorker(bg, "wk-a", agent.Lineage, workerSpec(Public))
	must(t, err)
	d := Deletion{Paths: []string{"/nothing"}, As: Private}
	unblock := e.failMeta("wk-a")
	if _, err := e.m.DeleteFiles(bg, "wk-a", d); err == nil {
		t.Fatal("a private deletion ran although the private label failed to save")
	}
	unblock()
	if l := e.labelOf("wk-a"); l != Public {
		t.Fatalf("worker label %s in memory after a failed save, want the saved public", l)
	}
	_, err = e.m.DeleteFiles(bg, "wk-a", d)
	must(t, err)
	e.open()
	if l := e.labelOf("wk-a"); l != Private {
		t.Fatalf("worker label %s after a restart, want private", l)
	}
}

// failPrivateSave fails each save of machine id's record that would
// record it private, as a disk error at that moment would.
func (e *env) failPrivateSave(id string) func() {
	path := filepath.Join(e.cfg.StateDir, "machines", id, "meta.json")
	real := writeFile
	writeFile = func(p string, b []byte, perm os.FileMode) error {
		if p == path && bytes.Contains(b, []byte(`"Label": 1`)) {
			return errors.New("synthetic save failure")
		}
		return real(p, b, perm)
	}
	return func() { writeFile = real }
}

// A public machine merging a private fork's work saves its private label
// before the merged files land in its layer, so a failed save leaves
// neither the files nor a label in memory only.
func TestLabelDurableMergeSavesTheLabelFirst(t *testing.T) {
	e := newEnv(t, 8192)
	e.create("p", admission.Accepted, 500)
	_, err := e.m.Fork(bg, "p", []string{"q"})
	must(t, err)
	must(t, e.m.RaiseLabel("q", Private))
	e.guestWrite("q", "x", "canary-private")
	unblock := e.failPrivateSave("p")
	if _, err := e.m.Merge(bg, "p", "q"); err == nil {
		t.Fatal("a merge whose private label failed to save reported success")
	}
	unblock()
	if l := e.labelOf("p"); l != Public {
		t.Fatalf("label %s in memory after a failed save, want the saved public", l)
	}
	if got := e.guestRead("p", "x"); got != "" {
		t.Fatalf("p holds the private fork's file %q under its public label", got)
	}
	e.open()
	if got := e.guestRead("p", "x"); got != "" && e.labelOf("p") != Private {
		t.Fatal("after a restart p holds private content under a public label")
	}
}

// privateSnapOfDestroyed leaves a private snapshot of a destroyed machine
// "a" holding file x, and a new public machine created under the same ID.
// Destroy keeps snapshots. A snapshot of this release names its machine's
// life (Instance), and no other machine may use it (#1561). One recorded
// before lineages and Instance were, of a machine replaced before the
// upgrade, is stamped at load with the machine then of its ID, which may
// use it from then on (stampLegacy). So the snapshot is made one of those,
// and the broker reopened: the one way left for a machine to reach a
// snapshot labelled above it.
func (e *env) privateSnapOfDestroyed() Snapshot {
	e.create("a", admission.Accepted, 500)
	must(e.t, e.m.RaiseLabel("a", Private))
	e.guestWrite("a", "x", "canary-private")
	s, err := e.m.Checkpoint(bg, "a")
	must(e.t, err)
	must(e.t, e.m.Destroy(bg, "a"))
	s.Lineage, s.Instance = "", ""
	must(e.t, writeJSON(filepath.Join(e.m.snapDir(s.ID), "meta.json"), s))
	e.create("a", admission.Accepted, 500)
	e.adm.Release("a")
	e.open() // the upgrade
	if l := e.labelOf("a"); l != Public {
		e.t.Fatalf("re-created machine is %s, want public", l)
	}
	s, err = e.m.Snapshot(s.ID)
	must(e.t, err)
	return s
}

// noPrivateUnderPublic checks a's label stayed public, in memory and after
// a restart, with none of the private snapshot's content in its layer.
func (e *env) noPrivateUnderPublic() {
	e.t.Helper()
	if l := e.labelOf("a"); l != Public {
		e.t.Fatalf("label %s in memory after a failed save, want the saved public", l)
	}
	if got := e.guestRead("a", "x"); got != "" {
		e.t.Fatalf("a's layer holds the private snapshot's file %q under its public label", got)
	}
	e.open()
	if l := e.labelOf("a"); l != Public {
		e.t.Fatalf("label %s after a restart, want public", l)
	}
	if got := e.guestRead("a", "x"); got != "" {
		e.t.Fatal("after a restart a holds private content under a public label")
	}
}

func TestLabelDurableRollbackSavesTheLabelFirst(t *testing.T) {
	e := newEnv(t, 8192)
	s := e.privateSnapOfDestroyed()
	unblock := e.failPrivateSave("a")
	if err := e.m.Rollback(bg, "a", s.ID); err == nil {
		t.Fatal("a rollback whose private label failed to save reported success")
	}
	unblock()
	e.noPrivateUnderPublic()
}

func TestLabelDurableForgetSinceSavesTheLabelFirst(t *testing.T) {
	e := newEnv(t, 8192)
	s := e.privateSnapOfDestroyed()
	mc, err := e.m.Get("a")
	must(t, err)
	unblock := e.failPrivateSave("a")
	if err := e.m.ForgetSince(bg, mc.Lineage, s.Taken.Add(time.Second)); err == nil {
		t.Fatal("a reset whose private label failed to save reported success")
	}
	unblock()
	e.noPrivateUnderPublic()
}
