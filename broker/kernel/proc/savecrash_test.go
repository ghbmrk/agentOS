package proc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// REV-CHK-save-kernel (#4190): each save of the kernel process is stopped
// after every step of its file write (privfile.WriteAtomic: 0 create the
// temporary, 1 write, 2 sync, 3 close, 4 rename, 5 sync the directory), as
// a crash would, and the test checks that what the process holds and what
// is on disk agree, then and after a restart. A save stopped after its
// rename is accounted for at the next start (#4368): an unnamed key and
// an unlogged item are kept and reported (a stale log the anchor still
// takes cannot tell them from a live subject's), the records file is
// joined with the log, a snapshot is removed, a restore's staging is
// removed by the next restore, and the anchor's whole file opens on no
// head.

// stopAt is a write stop that ends the write after step.
func stopAt(step int) func(int) bool { return func(i int) bool { return i == step } }

// stopped fails unless err is the stop's.
func stopped(t *testing.T, step int, err error) {
	t.Helper()
	if !errors.Is(err, privfile.ErrStopped) {
		t.Fatalf("step %d: got %v, want ErrStopped", step, err)
	}
}

// names lists dir's entries.
func names(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}

// REQ: STO-1, LOG-2
// Enrollment's anchor start stopped at any step leaves either no head file,
// so the anchor does not open and enrollment starts it again, or the whole
// file, which opens on no head; never a file that opens on something else.
func TestInitCounterAnchorCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		dir, c, priv := t.TempDir(), &fakeCounter{n: 4}, headKey(t)
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		stopped(t, step, initCounterAnchor(dir, noLog(t), c, priv, stopAt(step)))
		if c.n != 4 {
			t.Fatalf("step %d: the start moved the counter to %d", step, c.n)
		}
		a, err := OpenCounterAnchor(dir, c, priv)
		if step < 4 {
			if !errors.Is(err, ErrAnchorMissing) {
				t.Fatalf("step %d: open before the rename: %v, want ErrAnchorMissing", step, err)
			}
			if err := InitCounterAnchor(dir, noLog(t), c, priv); err != nil {
				t.Fatalf("step %d: a second start: %v", step, err)
			}
			if a, err = OpenCounterAnchor(dir, c, priv); err != nil {
				t.Fatalf("step %d: open after the second start: %v", step, err)
			}
		} else {
			if err != nil {
				t.Fatalf("step %d: open after the rename: %v", step, err)
			}
			if err := InitCounterAnchor(dir, noLog(t), c, priv); !errors.Is(err, ErrAnchorExists) {
				t.Fatalf("step %d: a second start over the whole file: %v", step, err)
			}
		}
		if h, ok := a.Latest(); ok {
			t.Fatalf("step %d: the started anchor holds head %d", step, h.Seq)
		}
	}
}

// fileContent reopens b's key table and content stores as the kernel's
// own and returns the table and the vision store, for a test to set their
// stops on.
func fileContent(t *testing.T, b *bbox) (*FileKeys, *FileContent) {
	t.Helper()
	keys, err := OpenFileKeys(b.cfg.KeyDir, b.cfg.Key)
	if err != nil {
		t.Fatal(err)
	}
	stores, _, err := OpenContentStores(b.cfg.ContentDir, b.cfg.Stores)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.OpenContent(keys, stores, b.now); return err }); err != nil {
		t.Fatal(err)
	}
	return keys, stores["vision"].(*FileContent)
}

// REQ: LOG-4
// A subject whose key put is stopped is never opened: nothing is logged,
// the next start removes a temporary the put left and names a key it
// left whole as unnamed, so the kernel's view of the table is what is on
// disk. A later subject opens and seals. Revert mutants: OpenSubject
// logging before the put (a stopped put leaves a logged subject with no
// key, Missing); OpenFileKeys keeping a temporary.
func TestASubjectKeyPutCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		b := newBBox(t, recipientWire(t, testRK))
		keys, _ := fileContent(t, b)
		keys.stop = stopAt(step)
		n := len(b.logBytes())
		err := b.h.With(func(k *kernel.Kernel) error { _, err := k.OpenSubject(b.now); return err })
		stopped(t, step, err)
		if len(b.logBytes()) != n {
			t.Fatalf("step %d: a stopped key put was logged", step)
		}
		var onDisk []string
		for _, f := range names(t, b.cfg.KeyDir) {
			if sub, ok := strings.CutSuffix(f, keyExt); ok {
				onDisk = append(onDisk, sub)
			}
		}
		if (len(onDisk) == 1) != (step >= 4) || len(onDisk) > 1 {
			t.Fatalf("step %d: key files %q", step, onDisk)
		}
		b.restart()
		rep := b.h.Content()
		if !slices.Equal(rep.Unnamed, onDisk) || len(rep.Missing) != 0 {
			t.Fatalf("step %d: after a restart the start found %+v, on disk %q", step, rep, onDisk)
		}
		var want []string
		for _, sub := range onDisk {
			want = append(want, sub+keyExt)
		}
		if got := names(t, b.cfg.KeyDir); !slices.Equal(got, want) {
			t.Fatalf("step %d: after a restart the table holds %q, want %q", step, got, want)
		}
		for _, sub := range onDisk {
			err := b.h.With(func(k *kernel.Kernel) error {
				_, err := k.Seal(b.now, sub, "vision", "wrap-key", []byte(canary))
				return err
			})
			if !errors.Is(err, kernel.ErrSubject) {
				t.Fatalf("step %d: a seal under the unnamed key: %v", step, err)
			}
		}
		sub := b.subject()
		if h := b.seal(sub, []byte(canary)); !readsBack(t, b, h) {
			t.Fatalf("step %d: a later subject's item does not read back", step)
		}
	}
}

// readsBack reports whether h opens to the canary in b's kernel.
func readsBack(t *testing.T, b *bbox, h kernel.Hash) bool {
	t.Helper()
	var pt []byte
	err := b.h.With(func(k *kernel.Kernel) (err error) { pt, err = k.Read(h); return err })
	return err == nil && string(pt) == canary
}

// REQ: LOG-4
// An item whose store put is stopped is never logged: the kernel refuses
// to read it, before and after a restart, whether the put left nothing,
// a temporary (removed at the start) or the whole file (kept, and named
// by the start's Unlogged), and the subject seals again. Revert mutants:
// Seal logging before the put (a logged item whose file is missing); the
// start not reporting an unlogged item.
func TestAContentPutCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		b := newBBox(t, recipientWire(t, testRK))
		sub := b.subject()
		_, fc := fileContent(t, b)
		fc.stop = stopAt(step)
		n := len(b.logBytes())
		err := b.h.With(func(k *kernel.Kernel) error {
			_, err := k.Seal(b.now, sub, "vision", "wrap-key", []byte(canary))
			return err
		})
		stopped(t, step, err)
		if len(b.logBytes()) != n {
			t.Fatalf("step %d: a stopped item put was logged", step)
		}
		var items []kernel.Hash
		for _, f := range names(t, b.storeDir()) {
			if x, ok := strings.CutSuffix(f, itemExt); ok {
				hb, err := hex.DecodeString(x)
				if err != nil {
					t.Fatal(err)
				}
				items = append(items, kernel.Hash(hb))
			}
		}
		if (len(items) == 1) != (step >= 4) || len(items) > 1 {
			t.Fatalf("step %d: item files %v", step, names(t, b.storeDir()))
		}
		for range 2 {
			for _, h := range items {
				if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Read(h); return err }); !errors.Is(err, kernel.ErrItem) {
					t.Fatalf("step %d: the stopped item read: %v, want ErrItem", step, err)
				}
			}
			b.restart()
		}
		if got := names(t, b.storeDir()); len(got) != len(items) {
			t.Fatalf("step %d: after a restart the store holds %q", step, got)
		}
		var want []string
		for _, h := range items {
			want = append(want, "vision/"+hex.EncodeToString(h[:]))
		}
		if got := b.h.Unlogged(); !slices.Equal(got, want) {
			t.Fatalf("step %d: the start reported unlogged %q, want %q", step, got, want)
		}
		if h := b.seal(sub, []byte(canary)); !readsBack(t, b, h) {
			t.Fatalf("step %d: the subject's next item does not read back", step)
		}
	}
}

// REQ: BAK-1, LOG-4
// The records file's save stopped as a backup's pending record is kept
// sends nothing and keeps nothing in memory; after a restart the logged
// backup is kept once, from the file when the save's rename landed and
// rebuilt from the log when it did not. Revert mutant: PutTable going on
// when the save fails (the stopped write is reported as sent).
func TestTheRecordsSaveCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		b := newBBox(t, recipientWire(t, testRK))
		b.subject()
		dir := b.addTarget("drive", false)
		b.h.bk.stop = stopAt(step)
		taken := b.backup()
		if len(taken) != 1 || taken[0].Backup != nil || !strings.Contains(taken[0].Error, privfile.ErrStopped.Error()) {
			t.Fatalf("step %d: taken %+v", step, taken)
		}
		if ids := tablesAt(t, dir); len(ids) != 0 {
			t.Fatalf("step %d: a table went out with no saved record: %v", step, ids)
		}
		if len(b.h.bk.kept) != 0 || len(b.h.bk.set.List()) != 0 {
			t.Fatalf("step %d: kept in memory: %+v", step, b.h.bk.kept)
		}
		b.h.bk.stop = nil
		b.restart()
		logged := b.taken()
		if len(logged) != 1 {
			t.Fatalf("step %d: logged %d backups, want 1", step, len(logged))
		}
		kp := b.kept(logged[0].BackupID)
		if len(b.h.bk.kept) != 1 || kp == nil || kp.Rebuilt != (step < 4) || len(b.h.bk.set.List()) != 1 {
			t.Fatalf("step %d: after a restart kept %+v", step, b.h.bk.kept)
		}
		if tk := b.backup(); len(tk) != 1 || tk[0].Backup == nil || !tk[0].Backup.Verified {
			t.Fatalf("step %d: the next backup: %+v", step, tk)
		}
	}
}

// REQ: BAK-1
// A snapshot item's copy stopped at any step fails the backup before
// anything is logged or sent, removes the snapshot and leaves the store
// as it was; the next backup carries the item. Revert mutant: snap keeping
// its directory on an error (a snapshot left in the backup directory).
func TestASnapshotCopyCrashDuringTheFileWrite(t *testing.T) {
	for step := range 6 {
		b := newBBox(t, recipientWire(t, testRK))
		b.h.bk.link = func(string, string) error { return errors.New("cross-device link") }
		item := b.seal(b.subject(), []byte(canary))
		dir := b.addTarget("drive", false)
		store := names(t, b.storeDir())
		b.h.bk.stop = stopAt(step)
		if _, err := b.h.Backup(b.now); !errors.Is(err, privfile.ErrStopped) {
			t.Fatalf("step %d: backup: %v, want ErrStopped", step, err)
		}
		if got := names(t, b.cfg.BackupDir); slices.ContainsFunc(got, func(f string) bool { return strings.HasPrefix(f, snapPrefix) }) {
			t.Fatalf("step %d: the backup directory holds %q", step, got)
		}
		if len(b.taken()) != 0 || len(tablesAt(t, dir)) != 0 || len(b.h.bk.kept) != 0 {
			t.Fatalf("step %d: a stopped snapshot logged, sent or kept a backup", step)
		}
		if got := names(t, b.storeDir()); !slices.Equal(got, store) || !readsBack(t, b, item) {
			t.Fatalf("step %d: the store holds %q, had %q", step, got, store)
		}
		b.h.bk.stop = nil
		tk := b.backup()
		if tk[0].Backup == nil || !tk[0].Backup.Verified {
			t.Fatalf("step %d: the next backup: %+v", step, tk)
		}
		r := restoreOnto(t, dir, tk[0].Backup.BackupID, nil)
		if got := restoredItems(t, r); !slices.Equal(got, []string{itemName(item)}) {
			t.Fatalf("step %d: restored %q", step, got)
		}
	}
}

// REQ: BAK-1
// A restored item's write stopped at any step leaves every item before it
// whole and the stopped one either absent or whole, never torn (the
// staging is dropped with the restore: TestARestoreStoppedInAnItemWrite).
func TestARestoredItemCrashDuringTheFileWrite(t *testing.T) {
	first, second := []byte("first sealed item"), []byte("second sealed item")
	for step := range 6 {
		dir := filepath.Join(t.TempDir(), "vision")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		writes := 0
		sec := append(frame(first, uint32(len(first))), frame(second, uint32(len(second)))...)
		err := restoreItems(bytes.NewReader(sec), dir, func(i int) bool {
			if i == 0 {
				writes++
			}
			return writes == 2 && i == step
		})
		stopped(t, step, err)
		want := map[string][]byte{itemName(sha256.Sum256(first)): first}
		if step >= 4 {
			want[itemName(sha256.Sum256(second))] = second
		}
		for _, f := range names(t, dir) {
			if strings.HasSuffix(f, tmpExt) {
				continue // never read, and dropped with the staging
			}
			got, err := os.ReadFile(filepath.Join(dir, f))
			if err != nil || !bytes.Equal(got, want[f]) {
				t.Fatalf("step %d: %s holds %q, want %q", step, f, got, want[f])
			}
			delete(want, f)
		}
		if len(want) != 0 {
			t.Fatalf("step %d: missing %v", step, slices.Collect(maps.Keys(want)))
		}
	}
}

// stages lists the restore stagings in dir.
func stages(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	for _, f := range names(t, dir) {
		if strings.HasPrefix(f, restoreStage) {
			out = append(out, f)
		}
	}
	return out
}

// REQ: BAK-1
// A restore stopped in an item's write at any step returns the stop,
// leaves the content folder absent and drops its staging, so no restored
// item is in place; a restore that a crash cut off, which runs no defer,
// leaves its staging, and the next restore removes it (#4368). Revert
// mutants: the deferred RemoveAll dropped (a staging left after the
// stop); RestoreSections not removing an old staging.
func TestARestoreStoppedInAnItemWrite(t *testing.T) {
	ct := []byte("a sealed item")
	for step := range 6 {
		parent := t.TempDir()
		content := filepath.Join(parent, "content")
		obj := objectWith(t, map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))})
		stopped(t, step, restoreSections(obj, nil, content, stopAt(step)))
		if _, err := os.Stat(content); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("step %d: the content folder is in place: %v", step, err)
		}
		if got := stages(t, parent); len(got) != 0 {
			t.Fatalf("step %d: the staging stayed: %q", step, got)
		}
	}
	parent := t.TempDir()
	left := filepath.Join(parent, restoreStage+"crash", "vision")
	if err := os.MkdirAll(left, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(left, itemName(sha256.Sum256(ct))), ct, 0o600); err != nil {
		t.Fatal(err)
	}
	obj := objectWith(t, map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))})
	if err := RestoreSections(obj, nil, filepath.Join(parent, "content")); err != nil {
		t.Fatal(err)
	}
	if got := stages(t, parent); len(got) != 0 {
		t.Fatalf("a crashed restore's staging stayed after the next restore: %q", got)
	}
	if got := names(t, filepath.Join(parent, "content", "vision")); !slices.Equal(got, []string{itemName(sha256.Sum256(ct))}) {
		t.Fatalf("the restore after the sweep put back %q", got)
	}
}

// REQ: LOG-4
// The start names an item as unlogged unless the log names it in that
// store: a copy of a logged item in another store's folder is reported
// and kept, and the logged one still reads. Revert mutant: unlogged
// ignoring the store.
func TestAnItemInAStoreTheLogDoesNotNameIsReported(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	h := b.seal(b.subject(), []byte(canary))
	ct, err := os.ReadFile(filepath.Join(b.storeDir(), itemName(h)))
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(b.cfg.ContentDir, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, itemName(h)), ct, 0o600); err != nil {
		t.Fatal(err)
	}
	b.restart()
	if got, want := b.h.Unlogged(), []string{"other/" + hex.EncodeToString(h[:])}; !slices.Equal(got, want) {
		t.Fatalf("unlogged %q, want %q", got, want)
	}
	if got := names(t, other); len(got) != 1 || !readsBack(t, b, h) {
		t.Fatalf("the other store holds %q, or the logged item does not read back", got)
	}
}

// REQ: LOG-4
// The start's stderr line counts each of a missing key, an unnamed key and
// an unlogged item alone, and is empty when there is none.
func TestTheStartReportCountsEachKind(t *testing.T) {
	if got := startReport(kernel.ContentReport{}, nil); got != "" {
		t.Fatalf("an empty start reports %q", got)
	}
	for _, c := range []struct {
		r    kernel.ContentReport
		u    []string
		want string
	}{
		{kernel.ContentReport{Missing: []string{"a"}}, nil, "lacks 1 open subjects' keys and holds 0 keys no subject names; the stores hold 0 items"},
		{kernel.ContentReport{Unnamed: []string{"a", "b"}}, nil, "lacks 0 open subjects' keys and holds 2 keys no subject names; the stores hold 0 items"},
		{kernel.ContentReport{}, []string{"vision/00"}, "lacks 0 open subjects' keys and holds 0 keys no subject names; the stores hold 1 items"},
		{kernel.ContentReport{Missing: []string{"a"}, Unnamed: []string{"b"}}, nil, "lacks 1 open subjects' keys and holds 1 keys no subject names; the stores hold 0 items"},
		{kernel.ContentReport{Unnamed: []string{"b"}}, []string{"vision/00"}, "lacks 0 open subjects' keys and holds 1 keys no subject names; the stores hold 1 items"},
	} {
		if got := startReport(c.r, c.u); !strings.Contains(got, c.want) {
			t.Fatalf("report %q, want %q", got, c.want)
		}
	}
}

// REQ: LOG-4
// A stale copy of the log that the anchor still takes (the entries after
// the last owner action are missing) opens and deletes nothing: the
// subject it lacks is an unnamed key and its item an unlogged one, and
// once the real log is back the item reads and nothing is missing
// (Security, #4395). Revert mutant: the start deleting unnamed keys or
// unlogged items.
func TestAStaleLogTheAnchorTakesDeletesNothing(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.addTarget("drive", false)
	old := b.logBytes()
	sub := b.subject()
	item := b.seal(sub, []byte(canary))
	real := b.logBytes()
	b.h.Close()
	if err := os.WriteFile(b.cfg.Log, old, 0o600); err != nil {
		t.Fatal(err)
	}
	b.open()
	if got := b.h.Content(); !slices.Equal(got.Unnamed, []string{sub}) || len(got.Missing) != 0 {
		t.Fatalf("the stale start reported %+v, want only %s unnamed", got, sub)
	}
	if got, want := b.h.Unlogged(), []string{"vision/" + hex.EncodeToString(item[:])}; !slices.Equal(got, want) {
		t.Fatalf("the stale start reported unlogged %q, want %q", got, want)
	}
	b.h.Close()
	if err := os.WriteFile(b.cfg.Log, real, 0o600); err != nil {
		t.Fatal(err)
	}
	b.open()
	if got := b.h.Content(); len(got.Missing)+len(got.Unnamed) != 0 || len(b.h.Unlogged()) != 0 {
		t.Fatalf("with the real log back the start reported %+v and unlogged %q", got, b.h.Unlogged())
	}
	if !readsBack(t, b, item) {
		t.Fatal("with the real log back the item does not read")
	}
}

// REQ: LOG-4
// Only an item file under its canonical name (lowercase hex, .item) is an
// item: an uppercase-hex name or a bare hash is neither reported nor
// removed (#4414). Revert mutant: unlogged without its name check.
func TestOnlyACanonicalItemNameIsReportedUnlogged(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	h := sha256.Sum256([]byte("not logged"))
	x := hex.EncodeToString(h[:])
	odd := []string{strings.ToUpper(x) + itemExt, x}
	for _, f := range odd {
		if err := os.WriteFile(filepath.Join(b.storeDir(), f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b.restart()
	if got := b.h.Unlogged(); len(got) != 0 {
		t.Fatalf("the start reported unlogged %q for non-item names", got)
	}
	if got := names(t, b.storeDir()); !slices.Equal(got, slices.Sorted(slices.Values(odd))) {
		t.Fatalf("the store holds %q, want %q kept", got, odd)
	}
}

// REQ: BAK-1
// A restore holds the lock beside the content folder over its sweep and
// its staging: a second restore into the same parent while the first is
// writing is refused and removes nothing, the first then completes whole,
// and once it is over the second runs (#4413). Revert mutants: no lock
// (the second's sweep removes the first's live staging); the lock taken
// after the sweep.
func TestARestoreHoldsTheLockOverItsSweep(t *testing.T) {
	ct := []byte("a sealed item")
	sec := map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))}
	parent := t.TempDir()
	paused, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	first := objectWith(t, sec)
	go func() {
		once := false
		done <- restoreSections(first, nil, filepath.Join(parent, "a"), func(int) bool {
			if !once {
				once = true
				close(paused)
				<-release
			}
			return false
		})
	}()
	<-paused
	if err := RestoreSections(objectWith(t, sec), nil, filepath.Join(parent, "b")); !errors.Is(err, ErrRestoreLocked) {
		close(release)
		<-done
		t.Fatalf("a restore beside a running one: %v, want ErrRestoreLocked", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("the first restore: %v", err)
	}
	want := []string{itemName(sha256.Sum256(ct))}
	if got := names(t, filepath.Join(parent, "a", "vision")); !slices.Equal(got, want) {
		t.Fatalf("the first restore put back %q", got)
	}
	if err := RestoreSections(objectWith(t, sec), nil, filepath.Join(parent, "b")); err != nil {
		t.Fatalf("the second restore once the first is over: %v", err)
	}
	if got := names(t, filepath.Join(parent, "b", "vision")); !slices.Equal(got, want) {
		t.Fatalf("the second restore put back %q", got)
	}
	if got := stages(t, parent); len(got) != 0 {
		t.Fatalf("stagings left: %q", got)
	}
}

// REQ: BAK-1
// A restore that cannot take its lock, list the content folder's parent or
// remove a crashed staging there stops with that error and puts nothing
// in place (#4413). Revert mutants: each of those errors ignored.
func TestARestoreStopsOnAParentItCannotUse(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the modes; CI runs these as a plain user")
	}
	ct := []byte("a sealed item")
	for _, c := range []struct {
		name string
		mode os.FileMode
		// at makes what c locks down, in parent, and returns it.
		at func(parent string) string
	}{
		{"lock", 0o500, func(p string) string { return p }},
		{"list", 0o300, func(p string) string {
			// The lock is there already, so only the listing fails.
			if err := os.WriteFile(filepath.Join(p, restoreLock), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"remove", 0o500, func(p string) string {
			left := filepath.Join(p, restoreStage+"crash")
			if err := os.MkdirAll(filepath.Join(left, "vision"), 0o700); err != nil {
				t.Fatal(err)
			}
			return left
		}},
	} {
		parent := t.TempDir()
		dir := c.at(parent)
		if err := os.Chmod(dir, c.mode); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dir, 0o700) })
		obj := objectWith(t, map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))})
		if err := RestoreSections(obj, nil, filepath.Join(parent, "content")); !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("no %s: %v, want a permission error", c.name, err)
		}
		os.Chmod(dir, 0o700)
		if _, err := os.Stat(filepath.Join(parent, "content")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("no %s: the content folder is in place: %v", c.name, err)
		}
	}
}
