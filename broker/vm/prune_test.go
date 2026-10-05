package vm

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
)

// REQ: RES-4

func ids(ss []Snapshot) []string {
	var out []string
	for _, s := range ss {
		out = append(out, s.ID)
	}
	return out
}

func has(ss []Snapshot, id string) bool {
	for _, s := range ss {
		if s.ID == id {
			return true
		}
	}
	return false
}

// pruneEnv ages every snapshot past MinAge so the policy alone decides.
func pruneEnv(t *testing.T) *env {
	e := newEnv(t, 8000)
	e.m.now = func() time.Time { return time.Now().Add(time.Hour) }
	return e
}

func TestRES4PrunePolicyKeepsNewestAndTemplatesAndDropsTheRest(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	tmpl, err := e.m.Checkpoint(bg, "m") // warm template
	must(t, err)
	var steps []Snapshot
	for i := 0; i < 6; i++ {
		s, err := e.m.Step(bg, "m")
		must(t, err)
		steps = append(steps, s)
	}
	mid, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	last, err := e.m.Checkpoint(bg, "m")
	must(t, err)

	gone, err := e.m.Prune(PrunePolicy{KeepFS: 2, KeepFull: 1})
	must(t, err)
	left := e.m.Snapshots("m")
	for _, keep := range []string{tmpl.ID, last.ID, steps[4].ID, steps[5].ID} {
		if !has(left, keep) {
			t.Errorf("pruned %s; left %v", keep, ids(left))
		}
	}
	for _, drop := range []string{steps[0].ID, steps[3].ID, mid.ID} {
		if has(left, drop) {
			t.Errorf("kept %s beyond policy", drop)
		}
		if _, err := os.Stat(filepath.Join(e.cfg.StateDir, "snapshots", drop)); !os.IsNotExist(err) {
			t.Errorf("%s still on disk", drop)
		}
	}
	if len(gone) != 5 {
		t.Errorf("pruned %v, want 5", gone)
	}
	// The machine still rolls back to what was kept.
	must(t, e.m.Rollback(bg, "m", tmpl.ID))
	// Pruned snapshots stay gone across a broker restart.
	e.open()
	if got := e.m.Snapshots("m"); len(got) != len(left) {
		t.Fatalf("after restart: %v, want %v", ids(got), ids(left))
	}
}

func TestRES4ForkBasesAndFreshSnapshotsAreNeverPruned(t *testing.T) {
	e := newEnv(t, 8000)
	e.create("src", admission.Accepted, 100)
	_, err := e.m.Checkpoint(bg, "src") // warm template
	must(t, err)
	base, err := e.m.Fork(bg, "src", []string{"f1"})
	must(t, err)
	for i := 0; i < 3; i++ {
		_, err := e.m.Step(bg, "src")
		must(t, err)
	}
	_, err = e.m.Checkpoint(bg, "src") // newest full: base is neither end
	must(t, err)
	// Everything is fresh: nothing goes, whatever the policy.
	if gone, _ := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1}); len(gone) != 0 {
		t.Fatalf("pruned fresh snapshots %v", gone)
	}
	e.m.now = func() time.Time { return time.Now().Add(time.Hour) }
	if _, err := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Snapshot(base.ID); err != nil {
		t.Fatal("pruned the snapshot a live fork was made from (merge needs it)")
	}
	// Once the fork is gone, its base is ordinary history again.
	must(t, e.m.Destroy(bg, "f1"))
	if _, err := e.m.Prune(PrunePolicy{KeepFS: 1, KeepFull: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.Snapshot(base.ID); err == nil {
		t.Fatal("kept a fork base no machine uses")
	}
}

func TestRES4DestroyedMachinesSnapshotsArePruned(t *testing.T) {
	e := pruneEnv(t)
	e.create("tmp", admission.Experiment, 100)
	_, err := e.m.Checkpoint(bg, "tmp")
	must(t, err)
	_, err = e.m.Step(bg, "tmp")
	must(t, err)
	must(t, e.m.Destroy(bg, "tmp"))
	if _, err := e.m.Prune(PrunePolicy{}); err != nil {
		t.Fatal(err)
	}
	if left := e.m.Snapshots("tmp"); len(left) != 0 {
		t.Fatalf("destroyed machine's snapshots kept: %v", ids(left))
	}
}

// Under disk pressure the policy tightens to each machine's newest
// snapshot and its templates, before the reserve is touched.
func TestRES4PressurePrunesDownToTheEssentials(t *testing.T) {
	e := pruneEnv(t)
	e.create("m", admission.Accepted, 100)
	tmpl, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	var last Snapshot
	for i := 0; i < 4; i++ {
		last, err = e.m.Step(bg, "m")
		must(t, err)
	}
	e.m.cfg.DiskReserveBytes = 1 << 30
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 1<<30 + 10, nil } // under the low water
	if _, err := e.m.Prune(PrunePolicy{KeepFS: 50, KeepFull: 5, LowWaterBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	left := e.m.Snapshots("m")
	if len(left) != 2 || !has(left, tmpl.ID) || !has(left, last.ID) {
		t.Fatalf("under pressure kept %v, want the template and the newest", ids(left))
	}
}

// A symlink inside a pruned snapshot is removed, never followed: what it
// points at outside the state directory survives.
func TestRES4PruneDoesNotFollowSymlinks(t *testing.T) {
	e := pruneEnv(t)
	e.create("tmp", admission.Experiment, 100)
	s, err := e.m.Step(bg, "tmp")
	must(t, err)
	outside := filepath.Join(t.TempDir(), "keep")
	must(t, os.MkdirAll(outside, 0o755))
	must(t, os.WriteFile(filepath.Join(outside, "f"), []byte("x"), 0o644))
	must(t, os.Symlink(outside, filepath.Join(e.cfg.StateDir, "snapshots", s.ID, "link")))
	must(t, e.m.Destroy(bg, "tmp"))
	gone, err := e.m.Prune(PrunePolicy{})
	must(t, err)
	if len(gone) != 1 {
		t.Fatalf("pruned %v, want %s", gone, s.ID)
	}
	if _, err := os.Stat(filepath.Join(outside, "f")); err != nil {
		t.Fatalf("prune followed a symlink: %v", err)
	}
}
