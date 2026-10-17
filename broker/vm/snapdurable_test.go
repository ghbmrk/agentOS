package vm

// REQ: CAP-3, OP-4

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/admission"
	"github.com/ghbmrk/agentos/broker/durable"
	"github.com/ghbmrk/agentos/broker/vm/overlay"
)

// restart is a broker restart with machine id admitted before it.
func (e *env) restart(id string) {
	e.t.Helper()
	e.adm.Release(id)
	e.rt = newFake()
	e.cfg.Runtime = e.rt
	e.open()
}

// setPublish swaps the snapshot publisher for the test.
func setPublish(t *testing.T, f func(dir string, perm os.FileMode, fill func(string) error) error) {
	t.Helper()
	old := publishDir
	publishDir = f
	t.Cleanup(func() { publishDir = old })
}

// CAP-3 restore points (#1240): a snapshot is never under its name, where
// load would take it, before all of it is written and synced; a publish
// that fails, before the rename or in the parent's sync after it, leaves
// no snapshot listed, none on disk, no stage and none after a restart.
func TestCAP3SnapshotPublishedOnlyWhole(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "notes", "a")
	seen, real := false, publishDir
	setPublish(t, func(dir string, perm os.FileMode, fill func(string) error) error {
		return real(dir, perm, func(stage string) error {
			err := fill(stage)
			if _, serr := os.Lstat(dir); !os.IsNotExist(serr) {
				t.Errorf("%s exists while its snapshot is written: %v", dir, serr)
			}
			if _, serr := os.Stat(filepath.Join(stage, "meta.json")); serr != nil {
				t.Errorf("meta.json not written into the stage: %v", serr)
			}
			seen = true
			return err
		})
	})
	for _, take := range []func() (Snapshot, error){
		func() (Snapshot, error) { return e.m.Step(bg, "m") },
		func() (Snapshot, error) { return e.m.Checkpoint(bg, "m") },
	} {
		s, err := take()
		must(t, err)
		if _, err := os.Stat(filepath.Join(e.m.snapDir(s.ID), "meta.json")); err != nil {
			t.Fatalf("published snapshot has no meta: %v", err)
		}
	}
	if !seen {
		t.Fatal("snapshots not published through publishDir")
	}

	fails := map[string]error{
		"before the rename": errors.New("injected"),
		"after the rename":  fmt.Errorf("%w: injected", durable.ErrDirSync),
	}
	for name, ferr := range fails {
		setPublish(t, func(dir string, perm os.FileMode, fill func(string) error) error {
			err := real(dir, perm, fill)
			if err != nil {
				return err
			}
			if errors.Is(ferr, durable.ErrDirSync) {
				return ferr // the rename is done: dir is whole
			}
			// Undo, as a failure before the rename leaves things.
			must(t, os.RemoveAll(dir))
			return ferr
		})
		before := len(e.m.Snapshots("m"))
		if _, err := e.m.Step(bg, "m"); !errors.Is(err, ferr) {
			t.Fatalf("%s: Step = %v", name, err)
		}
		if got := len(e.m.Snapshots("m")); got != before {
			t.Fatalf("%s: %d snapshots listed, want %d", name, got, before)
		}
		ents, err := os.ReadDir(filepath.Join(e.cfg.StateDir, "snapshots"))
		must(t, err)
		if len(ents) != before {
			t.Fatalf("%s: %d entries on disk, want %d: %v", name, len(ents), before, ents)
		}
	}
	e.restart("m")
	if got := len(e.m.Snapshots("m")); got != 2 {
		t.Fatalf("after restart %d snapshots, want 2", got)
	}
}

// A stage a crash left before the rename is not a snapshot after a restart,
// and does not stay on disk.
func TestCAP3CrashedStageNotLoaded(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	s, err := e.m.Step(bg, "m")
	must(t, err)
	stage := durable.StageDir(e.m.snapDir(snapName(99)))
	must(t, overlay.Copy(e.m.snapDir(s.ID), stage))
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("snapshots after restart: %+v", got)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage left on disk: %v", err)
	}
}

// The snapshot keeps what overlay.Copy keeps when it is written to a stage:
// hard links, holes and extended attributes.
func TestCAP3SnapshotKeepsLinksHolesXattrs(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "a", "linked")
	must(t, os.Link(e.upper("m", "a"), e.upper("m", "b")))
	f, err := os.Create(e.upper("m", "sparse"))
	must(t, err)
	_, err = f.WriteAt([]byte("x"), 64<<20)
	must(t, err)
	must(t, f.Close())
	if err := syscall.Setxattr(e.upper("m", "a"), "user.k", []byte("v"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	s, err := e.m.Step(bg, "m")
	must(t, err)
	fs := filepath.Join(e.m.snapDir(s.ID), "fs")
	var a, b, sp syscall.Stat_t
	must(t, syscall.Stat(filepath.Join(fs, "a"), &a))
	must(t, syscall.Stat(filepath.Join(fs, "b"), &b))
	must(t, syscall.Stat(filepath.Join(fs, "sparse"), &sp))
	if a.Ino != b.Ino {
		t.Error("hard link not kept")
	}
	if sp.Size != 64<<20+1 || sp.Blocks*512 > 1<<20 {
		t.Errorf("sparse file: size %d, %d bytes allocated", sp.Size, sp.Blocks*512)
	}
	buf := make([]byte, 8)
	if n, err := syscall.Getxattr(filepath.Join(fs, "a"), "user.k", buf); err != nil || string(buf[:n]) != "v" {
		t.Errorf("xattr = %q, %v", buf[:n], err)
	}
}

// CAP-3 deletion reach (#1240): a snapshot is reported deleted only once
// the unlink of its meta.json is durable. A crash after that, before the
// rest of it is removed, leaves a directory a restart does not load; a
// failed sync fails the deletion, so the caller retries before recording
// the reset.
func TestCAP3RetiredSnapshotStaysGone(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	since := time.Now().UTC()
	time.Sleep(5 * time.Millisecond)
	e.guestWrite("m", "notes", "secret")
	s, err := e.m.Step(bg, "m")
	must(t, err)
	dir := e.m.snapDir(s.ID)
	mc, _ := e.m.Get("m")

	old := syncSnapDir
	t.Cleanup(func() { syncSnapDir = old })
	syncSnapDir = func(string) error { return errors.New("injected") }
	if err := e.m.ForgetSince(bg, mc.Lineage, since); err == nil {
		t.Fatal("ForgetSince succeeded with the unlink not synced")
	}

	// What the disk holds at the crash point: the meta unlink synced, the
	// rest not yet removed.
	crashed := filepath.Join(t.TempDir(), "crashed")
	var synced []string
	syncSnapDir = func(d string) error {
		if _, err := os.Stat(filepath.Join(d, "meta.json")); !os.IsNotExist(err) {
			t.Errorf("sync before the meta unlink: %v", err)
		}
		synced = append(synced, d)
		if err := old(d); err != nil {
			return err
		}
		return overlay.Copy(d, crashed)
	}
	must(t, e.m.ForgetSince(bg, mc.Lineage, since))
	if len(synced) != 1 || synced[0] != dir {
		t.Fatalf("synced %v, want [%s]", synced, dir)
	}
	must(t, os.Rename(crashed, dir)) // durable:exempt test puts the crash state back
	e.restart("m")
	if _, err := e.m.Snapshot(s.ID); err == nil {
		t.Fatal("retired snapshot loaded after a crash")
	}
}
