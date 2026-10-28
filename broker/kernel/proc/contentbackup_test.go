package proc

// REQ: BAK-1, LOG-4

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel"
)

// KRN-content-backup (#3559): every backup carries the live subjects'
// items as content/<store> sections, and a restore puts them back before
// the kernel serves a read.

func (b *bbox) seal(sub string, pt []byte) kernel.Hash {
	b.t.Helper()
	var h kernel.Hash
	if err := b.h.With(func(k *kernel.Kernel) (err error) { h, err = k.Seal(b.now, sub, "vision", "wrap-key", pt); return err }); err != nil {
		b.t.Fatal(err)
	}
	return h
}

func (b *bbox) erase(sub string) {
	b.t.Helper()
	if c, err := b.h.Erase(b.now, sub); err != nil || len(c.Unconfirmed) != 0 {
		b.t.Fatalf("erase: %+v %v", c, err)
	}
}

func (b *bbox) storeDir() string { return filepath.Join(b.cfg.ContentDir, "vision") }

// restoreOnto restores backup id at dir onto a fresh drive r: its content
// sections into r/content, its newest key table into r/keys, and logBytes
// as r/log, or the backup's own log section when logBytes is nil.
func restoreOnto(t *testing.T, dir, id string, logBytes []byte) string {
	t.Helper()
	r := t.TempDir()
	f := mustOpen(t, filepath.Join(dir, id+".content"))
	defer f.Close()
	_, secs, err := backup.Open(f, testRK)
	if err != nil {
		t.Fatal(err)
	}
	var lb bytes.Buffer
	if err := RestoreSections(secs, &lb, filepath.Join(r, "content")); err != nil {
		t.Fatalf("RestoreSections: %v", err)
	}
	if logBytes == nil {
		logBytes = lb.Bytes()
	}
	if err := os.WriteFile(filepath.Join(r, "log"), logBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	_, keys := openBackup(t, dir, id, testRK)
	fk, err := OpenFileKeys(filepath.Join(r, "keys"), [32]byte{7})
	if err != nil {
		t.Fatal(err)
	}
	for s, k := range keys.M {
		if err := fk.Put(s, k); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// startRestored starts a kernel on the drive restoreOnto made, at anchor a.
func startRestored(t *testing.T, r string, a *kernel.MemAnchor) *Kernel {
	t.Helper()
	h, err := OpenKernel(KernelConfig{Log: filepath.Join(r, "log"), Anchor: a, Key: [32]byte{7}, Pub: headPub, Sign: headPriv,
		Anchors: anchors, KeyDir: filepath.Join(r, "keys"), ContentDir: filepath.Join(r, "content"), Stores: []string{"vision"}}, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.Close() })
	return h
}

func restoredItems(t *testing.T, r string) []string {
	t.Helper()
	des, err := os.ReadDir(filepath.Join(r, "content", "vision"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}

// The acceptance test: a backup taken after a seal, restored onto an empty
// drive, reads the item back through readfor; a subject erased before the
// backup has no item in the restored stores. Revert mutants: Write given
// the log section alone (readfor is ErrItem); snap taking an erased
// subject's items (two files restored).
func TestARestoredBackupReadsItsItemBack(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	live, gone := b.subject(), b.subject()
	item := b.seal(live, []byte(canary))
	b.seal(gone, []byte("gone-"+canary))
	b.erase(gone)
	dir := b.addTarget("drive", false)
	tk := b.backup()
	if len(tk) != 1 || tk[0].Backup == nil || !tk[0].Backup.Verified {
		t.Fatalf("backup: %+v", tk)
	}
	noCanary(t, dir)
	if des, _ := os.ReadDir(b.cfg.BackupDir); len(des) != 1 {
		t.Fatalf("the backup directory holds %v, want the records alone", des)
	}

	r := restoreOnto(t, dir, tk[0].Backup.BackupID, nil)
	if got := restoredItems(t, r); !slices.Equal(got, []string{itemName(item)}) {
		t.Fatalf("restored items %q, want the live subject's alone", got)
	}
	h := startRestored(t, r, &kernel.MemAnchor{})
	c := contentConn(t, h, "vision")
	got, err := c.ReadFor(item, "vision-lin")
	if err != nil || string(got) != canary {
		t.Fatalf("readfor after the restore: %q %v", got, err)
	}
}

// LOG-4: an erase newer than the backup is re-applied to the restored
// items before any read: the item file goes at the start and readfor is
// ErrErased. Revert mutant: OpenContent's delete of a confirmed erase's
// items dropped (the file stays).
func TestAnEraseAfterTheBackupReachesTheRestoredItem(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	item := b.seal(sub, []byte(canary))
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	b.erase(sub)
	later := b.logBytes()
	a := anchor(t, b.cfg.Log)
	b.h.Close()

	r := restoreOnto(t, dir, id, later)
	if got := restoredItems(t, r); len(got) != 1 {
		t.Fatalf("restored items %q, want the one in the backup", got)
	}
	h := startRestored(t, r, a)
	if got := restoredItems(t, r); len(got) != 0 {
		t.Fatalf("the start left %q, an item erased after the backup", got)
	}
	if _, err := contentConn(t, h, "vision").ReadFor(item, "vision-lin"); !errors.Is(err, kernel.ErrErased) {
		t.Fatalf("readfor: %v, want ErrErased", err)
	}
}

// BAK-1: the items are taken under the lock, so a store file removed while
// the backup is written is still carried, and a damaged item file is left
// out rather than spoiling the backup, both when the snapshot links and
// when it copies. Revert mutants: contentSources reading the store
// directory (the removed item is lost); itemsReader carrying a damaged
// item (the restore refuses).
func TestTheSnapshotHoldsItsItems(t *testing.T) {
	for _, copies := range []bool{false, true} {
		b := newBBox(t, recipientWire(t, testRK))
		if copies {
			b.h.bk.link = func(string, string) error { return errors.New("cross-device link") }
		}
		sub := b.subject()
		kept, bad := b.seal(sub, []byte(canary)), b.seal(sub, []byte("damaged"))
		if err := os.WriteFile(filepath.Join(b.storeDir(), itemName(bad)), []byte("not its hash"), 0o600); err != nil {
			t.Fatal(err)
		}
		dir := b.addTarget("drive", false)
		b.h.bk.hook = func() { os.Remove(filepath.Join(b.storeDir(), itemName(kept))) }
		tk := b.backup()
		if tk[0].Backup == nil || !tk[0].Backup.Verified {
			t.Fatalf("copies %v: backup %+v", copies, tk)
		}
		r := restoreOnto(t, dir, tk[0].Backup.BackupID, nil)
		if got := restoredItems(t, r); !slices.Equal(got, []string{itemName(kept)}) {
			t.Fatalf("copies %v: restored %q, want the removed item alone", copies, got)
		}
		got, err := contentConn(t, startRestored(t, r, &kernel.MemAnchor{}), "vision").ReadFor(kept, "vision-lin")
		if err != nil || string(got) != canary {
			t.Fatalf("copies %v: readfor %q %v", copies, got, err)
		}
	}
}

// A snapshot a stop left in the backup directory is removed at start.
func TestALeftSnapshotIsRemovedAtStart(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	left := filepath.Join(b.cfg.BackupDir, snapPrefix+"123")
	if err := os.MkdirAll(filepath.Join(left, "vision"), 0o700); err != nil {
		t.Fatal(err)
	}
	b.restart()
	if _, err := os.Stat(left); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the left snapshot: %v", err)
	}
}

// frame is one item as a content section frames it, with n as its length.
func frame(ct []byte, n uint32) []byte {
	h := sha256.Sum256(ct)
	return append(binary.BigEndian.AppendUint32(h[:], n), ct...)
}

// objectWith writes a content object at the recipient of testRK holding a
// log section and the given sections, and opens it.
func objectWith(t *testing.T, secs map[string][]byte) *backup.Sections {
	t.Helper()
	rcp, err := backup.RecipientFor(testRK)
	if err != nil {
		t.Fatal(err)
	}
	src := []backup.Source{{Name: "log", Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader([]byte("log"))), nil }}}
	for _, name := range slices.Sorted(maps.Keys(secs)) {
		body := secs[name]
		src = append(src, backup.Source{Name: name, Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }})
	}
	var obj bytes.Buffer
	if _, err := backup.Write(&obj, backup.DirTarget{Dir: t.TempDir()}, backup.Input{Recipient: rcp, Created: 1, Sections: src,
		Keys: kernel.NewMemKeys(), State: liveSet{}}); err != nil {
		t.Fatal(err)
	}
	_, s, err := backup.Open(&obj, testRK)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// MIG-4-recovery-a-6, a-10: a restore puts nothing in place unless every
// section is whole, takes a store name only a file store takes, and writes
// only onto an empty content folder. Revert mutants: no hash check, no
// length bound, no repeat check, items written straight into contentDir
// (a refused restore leaves files).
func TestARestoreRefusesContentThatIsNotWhole(t *testing.T) {
	ct := []byte("sealed item")
	big := make([]byte, maxSealed+1)
	flipped := frame(ct, uint32(len(ct)))
	flipped[len(flipped)-1] ^= 1
	for name, secs := range map[string]map[string][]byte{
		"hash":     {"content/vision": flipped},
		"length":   {"content/vision": frame(big, uint32(len(big)))},
		"cut":      {"content/vision": frame(ct, uint32(len(ct)))[:itemFrame+3]},
		"header":   {"content/vision": frame(ct, uint32(len(ct)))[:10]},
		"repeated": {"content/vision": append(frame(ct, uint32(len(ct))), frame(ct, uint32(len(ct)))...)},
		"later":    {"content/a-store": frame(ct, uint32(len(ct))), "content/vision": []byte("x")},
		"store":    {"content/Vision": frame(ct, uint32(len(ct)))},
	} {
		r := t.TempDir()
		err := RestoreSections(objectWith(t, secs), nil, filepath.Join(r, "content"))
		if err == nil {
			t.Fatalf("%s: a restore took it", name)
		}
		if des, _ := os.ReadDir(r); len(des) != 0 {
			t.Fatalf("%s (%v): the refused restore left %v", name, err, des)
		}
	}

	r := t.TempDir()
	if err := RestoreSections(objectWith(t, map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))}), nil, filepath.Join(r, "content")); err != nil {
		t.Fatalf("a whole section: %v", err)
	}
	if err := RestoreSections(objectWith(t, nil), nil, filepath.Join(r, "content")); !errors.Is(err, ErrRestoreNotEmpty) {
		t.Fatalf("a restore over content: %v, want ErrRestoreNotEmpty", err)
	}
	empty := filepath.Join(t.TempDir(), "content")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSections(objectWith(t, map[string][]byte{"content/vision": frame(ct, uint32(len(ct)))}), nil, empty); err != nil {
		t.Fatalf("a restore into an empty folder: %v", err)
	}
	if des, _ := os.ReadDir(filepath.Join(empty, "vision")); len(des) != 1 {
		t.Fatalf("restored %v, want one item", des)
	}
}
