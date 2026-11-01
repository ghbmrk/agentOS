package proc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
// is on disk agree, then and after a restart.

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

// REQ: STO-1, STO-2
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
	stores, err := OpenContentStores(b.cfg.ContentDir, b.cfg.Stores)
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
// and after a restart the start names a key the put left whole as
// unnamed, so the kernel's view of the table is what is on disk. A later
// subject opens and seals. Revert mutant: OpenSubject logging before the
// put (a stopped put leaves a logged subject with no key, Missing).
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
// a temporary (removed at the start) or the whole file, and the subject
// seals again. Revert mutant: Seal logging before the put (a logged item
// whose file is missing).
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
// whole and the stopped one either absent or whole, never torn; a restore
// that fails there drops its staging (RestoreSections).
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
