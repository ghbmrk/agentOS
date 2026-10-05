package vm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: REV-1, REV-5, RES-1

// sleep is the sleeper's first half: a full checkpoint, then the machine
// stops and its memory goes back to admission.
func sleep(t *testing.T, e *env, id string) Snapshot {
	t.Helper()
	cp, err := e.m.CheckpointAndStop(bg, id)
	must(t, err)
	if mc, _ := e.m.Get(id); mc.State == Running {
		t.Fatal("still running after CheckpointAndStop")
	}
	if _, ok := e.adm.Snapshot().Running[id]; ok {
		t.Fatal("admission still holds the stopped machine")
	}
	return cp
}

// PE7 (condition 10): a sleeping machine restores from its checkpoint
// with memory and files, once; the checkpoint is then deleted.
func TestPE7ResumeFromCheckpointRestoresOnce(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	e.rt.work("agent", 7)
	e.guestWrite("agent", "notes", "kept")
	cp := sleep(t, e, "agent")
	if cp.Tier != Full || cp.Hash == "" {
		t.Fatalf("checkpoint %+v: want full, hashed", cp)
	}
	restored, err := e.m.ResumeFromCheckpoint(bg, "agent", cp.ID)
	if err != nil || !restored {
		t.Fatalf("restore: %v %v", restored, err)
	}
	if mem, ok := e.rt.memOf("agent"); !ok || mem != 7 {
		t.Fatalf("memory %d running %v, want 7", mem, ok)
	}
	if e.guestRead("agent", "notes") != "kept" {
		t.Fatal("files not restored")
	}
	if _, err := e.m.Snapshot(cp.ID); err == nil {
		t.Fatal("the checkpoint was kept after its restore")
	}
	if _, err := os.Stat(e.m.snapDir(cp.ID)); !os.IsNotExist(err) {
		t.Fatal("the checkpoint's files were kept")
	}
	if _, err := e.m.ResumeFromCheckpoint(bg, "agent", cp.ID); err == nil {
		t.Fatal("a running machine was restored again")
	}
}

// PE7 (conditions 8, 9, 10, 11): a checkpoint that may not be the
// machine's state as it went to sleep is never restored. The machine
// cold-resumes on its layer instead, and the checkpoint is deleted. A
// restore never lowers the machine's label.
func TestPE7ResumeFromCheckpointRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(e *env, cp Snapshot) string // returns the snapshot ID to restore
		kept  bool                             // the snapshot is another machine's: not deleted
	}{
		{name: "started since", after: func(e *env, cp Snapshot) string {
			must(e.t, e.m.Resume(bg, "agent"))
			must(e.t, e.m.Preempt("agent"))
			e.adm.Release("agent")
			return cp.ID
		}},
		{name: "files tampered", after: func(e *env, cp Snapshot) string {
			write(e.t, filepath.Join(e.m.snapDir(cp.ID), "fs"), "notes", "evil")
			return cp.ID
		}},
		{name: "memory tampered", after: func(e *env, cp Snapshot) string {
			must(e.t, os.WriteFile(filepath.Join(e.m.snapDir(cp.ID), "mem", "mem"), []byte("666"), 0o600))
			return cp.ID
		}},
		{name: "file added", after: func(e *env, cp Snapshot) string {
			write(e.t, filepath.Join(e.m.snapDir(cp.ID), "fs"), "extra", "x")
			return cp.ID
		}},
		{name: "another machine's checkpoint", kept: true, after: func(e *env, cp Snapshot) string {
			e.create("other", admission.Accepted, 500)
			o, err := e.m.Checkpoint(bg, "other")
			must(e.t, err)
			return o.ID
		}},
		{name: "unknown snapshot", after: func(e *env, cp Snapshot) string { return "s9999999999" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, 4096)
			e.create("agent", admission.Foreground, 1600)
			e.rt.work("agent", 7)
			e.guestWrite("agent", "notes", "kept")
			cp := sleep(t, e, "agent")
			id := tc.after(e, cp)
			must(t, e.m.RaiseLabel("agent", Private))
			restored, err := e.m.ResumeFromCheckpoint(bg, "agent", id)
			if err != nil || restored {
				t.Fatalf("restored %v, %v: want a cold resume", restored, err)
			}
			if mem, ok := e.rt.memOf("agent"); !ok || mem != 0 {
				t.Fatalf("memory %d running %v: want a cold start", mem, ok)
			}
			if l, _ := e.m.Label("agent"); l != Private {
				t.Fatalf("label %v after the resume", l)
			}
			_, err = e.m.Snapshot(id)
			if gone := err != nil; gone == tc.kept {
				t.Fatalf("snapshot %s gone %v, want kept %v", id, gone, tc.kept)
			}
			if !tc.kept && id == cp.ID {
				if _, err := os.Stat(e.m.snapDir(cp.ID)); !os.IsNotExist(err) {
					t.Fatal("a refused checkpoint's files were kept")
				}
			}
		})
	}
}

// PE7 (condition 8): only CheckpointAndStop's own checkpoint restores.
// A checkpoint or step the owner took (REV-1) is refused and kept, since
// it may be wanted for a rollback; so is a sleep checkpoint that is no
// longer the machine's newest snapshot.
func TestPE7ResumeFromCheckpointOnlyItsOwn(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	e.rt.work("agent", 7)
	old, err := e.m.Checkpoint(bg, "agent")
	must(t, err)
	step, err := e.m.Step(bg, "agent")
	must(t, err)
	must(t, e.m.Preempt("agent"))
	e.adm.Release("agent")
	for _, id := range []string{old.ID, step.ID} {
		restored, err := e.m.ResumeFromCheckpoint(bg, "agent", id)
		if err != nil || restored {
			t.Fatalf("%s: restored %v, %v", id, restored, err)
		}
		if _, err := e.m.Snapshot(id); err != nil {
			t.Fatalf("the owner's snapshot %s was deleted", id)
		}
		must(t, e.m.Preempt("agent"))
		e.adm.Release("agent")
	}
}

// PE7: CheckpointAndStop refuses a machine that is not running, and a
// replay machine.
func TestPE7CheckpointAndStopRefuses(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	sleep(t, e, "agent")
	if _, err := e.m.CheckpointAndStop(bg, "agent"); !errors.Is(err, ErrState) {
		t.Fatalf("a stopped machine: %v", err)
	}
	if _, err := e.m.CheckpointAndStop(bg, EvalPrefix+"x"); err == nil {
		t.Fatal("a replay machine was put to sleep")
	}
}

// PE7: a sleep checkpoint outlives a broker restart, hash and start count
// included, so the restarted broker can still restore it once.
func TestPE7SleepCheckpointSurvivesARestart(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	e.rt.work("agent", 7)
	cp := sleep(t, e, "agent")
	e.open()
	restored, err := e.m.ResumeFromCheckpoint(bg, "agent", cp.ID)
	if err != nil || !restored {
		t.Fatalf("after a restart: %v %v", restored, err)
	}
	if mem, _ := e.rt.memOf("agent"); mem != 7 {
		t.Fatalf("memory %d, want 7", mem)
	}
}

// PE7, as #137 for Checkpoint: a sleep checkpoint published just before
// its machine record fails to save is withdrawn, and the machine runs on,
// so a failed sleep leaves nothing a later wake could restore.
func TestPE7FailedSleepLeavesNoCheckpoint(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	block := filepath.Join(e.cfg.StateDir, "machines", "agent", "meta.json.tmp")
	must(t, os.MkdirAll(filepath.Join(block, "x"), 0o700))
	if _, err := e.m.CheckpointAndStop(bg, "agent"); err == nil {
		t.Fatal("a sleep whose machine record failed to save reported success")
	}
	must(t, os.RemoveAll(block))
	if got := e.m.Snapshots("agent"); len(got) != 0 {
		t.Fatalf("snapshots %v left by a failed sleep", ids(got))
	}
	entries, err := os.ReadDir(filepath.Join(e.cfg.StateDir, "snapshots"))
	must(t, err)
	if len(entries) != 0 {
		t.Fatalf("%d snapshot directories on disk, want 0", len(entries))
	}
	mc, err := e.m.Get("agent")
	must(t, err)
	if mc.Last != "" || mc.State != Running {
		t.Fatalf("after a failed sleep: Last %q, state %s", mc.Last, mc.State)
	}
}

// PE7: a sleep whose stop fails withdraws its checkpoint too, so the wake
// that follows resumes cold rather than restoring beside a guest that
// may still run.
func TestPE7SleepFailingToStopLeavesNoCheckpoint(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("agent", admission.Foreground, 1600)
	e.rt.mu.Lock()
	e.rt.failKill = errors.New("kill failed")
	e.rt.mu.Unlock()
	if _, err := e.m.CheckpointAndStop(bg, "agent"); err == nil {
		t.Fatal("a sleep whose stop failed reported success")
	}
	if got := e.m.Snapshots("agent"); len(got) != 0 {
		t.Fatalf("snapshots %v left by a failed stop", ids(got))
	}
	if mc, _ := e.m.Get("agent"); mc.Last != "" {
		t.Fatalf("Last %q after a failed stop", mc.Last)
	}
}
