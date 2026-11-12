package vm

// REQ: CAP-3, OP-4

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
		// The removal after the rename drops meta.json, durably, before
		// the rest, so a power cut part-way through leaves nothing load
		// takes.
		synced := 0
		oldSync := syncSnapDir
		syncSnapDir = func(d string) error {
			if _, err := os.Stat(filepath.Join(d, "meta.json")); !os.IsNotExist(err) {
				t.Errorf("%s: snapshot dir synced with meta.json still there: %v", name, err)
			}
			if _, err := os.Stat(filepath.Join(d, "fs")); err != nil {
				t.Errorf("%s: layer removed before meta.json: %v", name, err)
			}
			synced++
			return oldSync(d)
		}
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
		syncSnapDir = oldSync
		if want := map[bool]int{true: 1}[errors.Is(ferr, durable.ErrDirSync)]; synced != want {
			t.Fatalf("%s: snapshot dir synced %d times, want %d", name, synced, want)
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

// CAP-3 (#5452, #5461): a published snapshot whose metadata fails to read
// for a reason other than absence is kept on disk, unread and not offered,
// and the open succeeds, so a persistent fault does not fail every
// restart; no new snapshot takes its ID. Once the metadata reads again a
// restart takes it back. A snapshot with no metadata was never published
// and is still dropped.
func TestCAP3SnapshotKeptOnMetadataReadError(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "notes", "kept")
	s, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	meta := filepath.Join(e.m.snapDir(s.ID), "meta.json")
	saved, err := os.ReadFile(meta)
	must(t, err)
	// A directory where the file was: the read fails with EISDIR, not absence.
	must(t, os.Remove(meta))
	must(t, os.Mkdir(meta, 0o700))
	for range 2 { // persistent: every restart opens
		e.restart("m")
		if got := e.m.Snapshots("m"); len(got) != 0 {
			t.Fatalf("an unread snapshot offered: %+v", got)
		}
		if got := e.m.Unread(); len(got) != 1 || got[0] != s.ID {
			t.Fatalf("unread = %v, want [%s]", got, s.ID)
		}
		if _, err := os.Stat(e.m.snapDir(s.ID)); err != nil {
			t.Fatalf("snapshot removed after a read error: %v", err)
		}
	}
	must(t, e.m.Resume(bg, "m"))
	later, err := e.m.Step(bg, "m")
	must(t, err)
	if later.ID <= s.ID {
		t.Fatalf("new snapshot %s not after the kept %s", later.ID, s.ID)
	}
	must(t, os.Remove(meta))
	must(t, os.WriteFile(meta, saved, 0o600))
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 2 || got[0].ID != s.ID {
		t.Fatalf("snapshots after the record reads again: %+v", got)
	}
	if got := e.m.Unread(); len(got) != 0 {
		t.Fatalf("unread after the record reads again: %v", got)
	}
	must(t, e.m.Resume(bg, "m"))
	e.guestWrite("m", "notes", "later")
	must(t, e.m.Rollback(bg, "m", s.ID))
	if got := e.guestRead("m", "notes"); got != "kept" {
		t.Fatalf("rollback after the reopen: notes = %q, want kept", got)
	}
	// Absent metadata: never published, dropped.
	must(t, os.Remove(meta))
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 1 || got[0].ID != later.ID {
		t.Fatalf("unpublished snapshot loaded: %+v", got)
	}
	if _, err := os.Lstat(e.m.snapDir(s.ID)); !os.IsNotExist(err) {
		t.Fatalf("unpublished snapshot left on disk: %v", err)
	}
}

// CAP-3 (#5461): a snapshot kept unread has no lineage or time to read, so
// any ForgetSince deletes it; it never comes back at a later open.
func TestCAP3ForgetDeletesUnreadSnapshot(t *testing.T) {
	e := newEnv(t, 4096)
	mc := e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "notes", "secret")
	s, err := e.m.Step(bg, "m")
	must(t, err)
	meta := filepath.Join(e.m.snapDir(s.ID), "meta.json")
	saved, err := os.ReadFile(meta)
	must(t, err)
	must(t, os.Remove(meta))
	must(t, os.Mkdir(meta, 0o700))
	must(t, os.WriteFile(filepath.Join(meta, "x"), saved, 0o600)) // not empty: os.Remove fails
	e.restart("m")
	must(t, e.m.ForgetSince(bg, mc.Lineage, time.Now().Add(time.Hour)))
	if got := e.m.Unread(); len(got) != 0 {
		t.Fatalf("unread after a forget: %v", got)
	}
	if _, err := os.Lstat(e.m.snapDir(s.ID)); !os.IsNotExist(err) {
		t.Fatalf("unread snapshot left on disk after a forget: %v", err)
	}
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 0 {
		t.Fatalf("a forgotten snapshot came back: %+v", got)
	}
}

// CAP-3 (#5461): a forget that cannot delete an unread snapshot fails,
// so the erase stays retryable, and the snapshot stays listed unread.
func TestCAP3ForgetFailsWhenUnreadSnapshotStays(t *testing.T) {
	e := newEnv(t, 4096)
	mc := e.create("m", admission.Accepted, 500)
	id := snapName(9)
	must(t, os.MkdirAll(filepath.Join(e.cfg.StateDir, "snapshots", id, "meta.json"), 0o700))
	e.restart("m")
	real := syncSnapDir
	syncSnapDir = func(string) error { return errors.New("sync failed") }
	t.Cleanup(func() { syncSnapDir = real })
	if err := e.m.ForgetSince(bg, mc.Lineage, time.Now()); err == nil {
		t.Fatal("forget succeeded with an unread snapshot left")
	}
	if got := e.m.Unread(); len(got) != 1 || got[0] != id {
		t.Fatalf("unread after a failed forget = %v, want [%s]", got, id)
	}
}

// CAP-3 (#5461): an entry under snapshots/ that is not a directory is not
// a snapshot: the open succeeds, nothing is loaded from it, and it is left
// alone; no new snapshot takes its name.
func TestCAP3StrayFileUnderSnapshots(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	stray := filepath.Join(e.cfg.StateDir, "snapshots", snapName(5))
	must(t, os.WriteFile(stray, []byte("{}"), 0o600))
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 0 {
		t.Fatalf("a stray file loaded: %+v", got)
	}
	if got := e.m.Unread(); len(got) != 0 {
		t.Fatalf("a stray file kept as unread: %v", got)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Fatalf("stray file: %v", err)
	}
	must(t, e.m.Resume(bg, "m"))
	s, err := e.m.Step(bg, "m")
	must(t, err)
	if s.ID <= snapName(5) {
		t.Fatalf("new snapshot %s not after the stray %s", s.ID, snapName(5))
	}
}

// CAP-3 (Lens R1 on #5457): a meta.json that reads but does not decode was
// written atomically, so it is not a transient fault: the snapshot is
// dropped from the list and from disk, not kept.
func TestCAP3UndecodableSnapshotDropped(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	s, err := e.m.Step(bg, "m")
	must(t, err)
	must(t, os.WriteFile(filepath.Join(e.m.snapDir(s.ID), "meta.json"), []byte("{not json"), 0o600))
	e.restart("m")
	if got := e.m.Snapshots("m"); len(got) != 0 {
		t.Fatalf("an undecodable snapshot loaded: %+v", got)
	}
	if got := e.m.Unread(); len(got) != 0 {
		t.Fatalf("an undecodable snapshot kept unread: %v", got)
	}
	if _, err := os.Lstat(e.m.snapDir(s.ID)); !os.IsNotExist(err) {
		t.Fatalf("an undecodable snapshot left on disk: %v", err)
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

// CAP-3 (#5481): a forget that deletes snapshots kept unread tells the
// owner's side how many, as a forget (not a prune); a forget that could not
// delete them tells nothing, and one that deletes none tells nothing.
func TestCAP3ForgetTellsOfUnreadDeleted(t *testing.T) {
	e := newEnv(t, 4096)
	mc := e.create("m", admission.Accepted, 500)
	type told struct {
		n         int
		forgotten bool
	}
	var calls []told
	e.cfg.UnreadGone = func(n int, forgotten bool) { calls = append(calls, told{n, forgotten}) }
	must(t, e.m.ForgetSince(bg, mc.Lineage, time.Now()))
	e.restart("m")
	must(t, e.m.ForgetSince(bg, mc.Lineage, time.Now()))
	if len(calls) != 0 {
		t.Fatalf("told of %v with nothing unread", calls)
	}
	for _, n := range []int{3, 4} {
		must(t, os.MkdirAll(filepath.Join(e.cfg.StateDir, "snapshots", snapName(n), "meta.json"), 0o700))
	}
	e.restart("m")
	real := syncSnapDir
	syncSnapDir = func(string) error { return errors.New("sync failed") }
	if err := e.m.ForgetSince(bg, mc.Lineage, time.Now()); err == nil {
		t.Fatal("forget succeeded with unread snapshots left")
	}
	syncSnapDir = real
	if len(calls) != 0 {
		t.Fatalf("told of %v although nothing was deleted", calls)
	}
	// The record unpublished but the directory not removed: still deleted
	// as far as the owner is concerned, so counted.
	realRemove := removeAll
	removeAll = func(string) error { return errors.New("remove failed") }
	err := e.m.ForgetSince(bg, mc.Lineage, time.Now())
	removeAll = realRemove
	if err == nil {
		t.Fatal("forget succeeded although a directory stayed")
	}
	if len(calls) != 1 || calls[0] != (told{2, true}) {
		t.Fatalf("told %v, want one notice of 2 deleted by a forget", calls)
	}
}

// CAP-3 (#5481): a snapshot kept unread is not pruned while the state disk
// has room, and is pruned, with a notice, while it is short of room and the
// snapshot is older than MinAge; its directory is gone, and a younger one
// stays.
func TestCAP3PruneFreesUnreadUnderPressure(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	old, young, base := snapName(3), snapName(4), snapName(5)
	for _, id := range []string{old, young, base} {
		dir := filepath.Join(e.cfg.StateDir, "snapshots", id)
		must(t, os.MkdirAll(filepath.Join(dir, "meta.json"), 0o700))
		must(t, os.WriteFile(filepath.Join(dir, "disk.img"), []byte("layer"), 0o600))
	}
	longAgo := time.Now().Add(-time.Hour)
	for _, id := range []string{old, base} {
		must(t, os.Chtimes(filepath.Join(e.cfg.StateDir, "snapshots", id), longAgo, longAgo))
	}
	type told struct {
		n         int
		forgotten bool
	}
	var calls []told
	e.cfg.UnreadGone = func(n int, forgotten bool) { calls = append(calls, told{n, forgotten}) }
	e.restart("m")
	// A live machine forked from the unread snapshot: it stays, as a
	// readable fork base does (Security on #5499).
	mc, err := e.m.get("m")
	must(t, err)
	mc.mu.Lock()
	mc.ForkBase = base
	mc.mu.Unlock()
	p := PrunePolicy{LowWaterBytes: 1 << 30}
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 1 << 50, nil }
	if gone, err := e.m.Prune(p); err != nil || len(gone) != 0 || len(calls) != 0 {
		t.Fatalf("pruned %v (%v), told %v with room on the disk", gone, err, calls)
	}
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 0, nil }
	gone, err := e.m.Prune(p)
	must(t, err)
	if len(gone) != 1 || gone[0] != old {
		t.Fatalf("pruned %v, want only %s (the %s is younger than MinAge)", gone, old, young)
	}
	if _, err := os.Lstat(filepath.Join(e.cfg.StateDir, "snapshots", old)); !os.IsNotExist(err) {
		t.Fatalf("pruned unread snapshot left on disk: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(e.cfg.StateDir, "snapshots", young)); err != nil {
		t.Fatalf("a young unread snapshot removed: %v", err)
	}
	if got := e.m.Unread(); len(got) != 2 || !slices.Contains(got, young) || !slices.Contains(got, base) {
		t.Fatalf("unread after the prune = %v, want [%s %s]", got, young, base)
	}
	if len(calls) != 1 || calls[0] != (told{1, false}) {
		t.Fatalf("told %v, want one notice of 1 pruned", calls)
	}
	if gone, err := e.m.Prune(p); err != nil || len(gone) != 0 || len(calls) != 1 {
		t.Fatalf("second prune: %v (%v), told %v", gone, err, calls)
	}
	// The record unpublished but the directory not removed: counted.
	e.m.mu.Lock()
	e.m.unread[old] = true
	e.m.mu.Unlock()
	// A failure before the record is unpublished: still listed, not counted.
	realSync := syncSnapDir
	syncSnapDir = func(string) error { return errors.New("sync failed") }
	_, err = e.m.Prune(p)
	syncSnapDir = realSync
	if err == nil || len(calls) != 1 || !slices.Contains(e.m.Unread(), old) {
		t.Fatalf("a prune that could not unpublish: %v, told %v, unread %v", err, calls, e.m.Unread())
	}
	realRemove := removeAll
	removeAll = func(string) error { return errors.New("remove failed") }
	_, err = e.m.Prune(p)
	removeAll = realRemove
	if err == nil || len(calls) != 2 || calls[1] != (told{1, false}) {
		t.Fatalf("a prune whose directory stayed: %v, told %v, want one more notice", err, calls)
	}
}

// CAP-3 (#5481, Security 1 on #5480): a snapshot recorded before Instance
// that is unread at one open, while its machine is destroyed and created
// anew under the ID, and reads at the next, is not the new machine's: it
// began after the snapshot was taken.
func TestCAP3LegacyUnreadSnapshotNotInheritedByReplacement(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "who", "predecessor")
	s, err := e.m.Checkpoint(bg, "m")
	must(t, err)
	s.Lineage, s.Instance = "", ""
	meta := filepath.Join(e.m.snapDir(s.ID), "meta.json")
	must(t, writeJSON(meta, s))
	saved, err := os.ReadFile(meta)
	must(t, err)
	must(t, os.Remove(meta))
	must(t, os.Mkdir(meta, 0o700))
	e.restart("m") // the snapshot is unread
	must(t, e.m.Destroy(bg, "m"))
	e.create("m", admission.Accepted, 500)
	e.guestWrite("m", "who", "successor")
	must(t, os.Remove(meta))
	must(t, os.WriteFile(meta, saved, 0o600))
	e.restart("m") // the record reads
	e.guestWrite("m", "who", "successor")
	if err := e.m.Rollback(bg, "m", s.ID); !errors.Is(err, ErrLineage) {
		t.Fatalf("the replacement's rollback to its predecessor's legacy snapshot: %v, want ErrLineage", err)
	}
	if got := e.guestRead("m", "who"); got != "successor" {
		t.Fatalf("who = %q, want the successor's", got)
	}
}

// CAP-3 (#5481): a snapshot kept unread whose directory cannot be statted
// for a reason other than absence is not known to be old: a prune keeps it
// and tells nothing. Here a file stands where the snapshots directory was
// (ENOTDIR).
func TestCAP3PruneKeepsUnreadWhenStatFails(t *testing.T) {
	e := newEnv(t, 4096)
	e.create("m", admission.Accepted, 500)
	id := snapName(3)
	snaps := filepath.Join(e.cfg.StateDir, "snapshots")
	must(t, os.MkdirAll(filepath.Join(snaps, id, "meta.json"), 0o700))
	told := 0
	e.cfg.UnreadGone = func(int, bool) { told++ }
	e.restart("m")
	must(t, os.Rename(snaps, snaps+".away"))
	must(t, os.WriteFile(snaps, []byte("x"), 0o600))
	e.m.cfg.FreeBytes = func(string) (int64, error) { return 0, nil }
	gone, err := e.m.Prune(PrunePolicy{LowWaterBytes: 1 << 30})
	must(t, err)
	if len(gone) != 0 || told != 0 {
		t.Fatalf("pruned %v, told %d times, although its directory could not be statted", gone, told)
	}
	if got := e.m.Unread(); len(got) != 1 || got[0] != id {
		t.Fatalf("unread after the prune = %v, want [%s]", got, id)
	}
}
