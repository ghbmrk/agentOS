package proc

// REQ: BAK-1, LOG-4
//
// MUT-kill-6305-proc (#6367): the backups' records, targets, snapshots and
// writes, each checked by what they return, keep or leave on disk.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// sealRecords writes pt, sealed as the records file is, as b's records.
func sealRecords(t *testing.T, b *bbox, pt []byte) string {
	t.Helper()
	p := filepath.Join(b.cfg.BackupDir, recordsName)
	if err := os.WriteFile(p+".new", sealer(b.cfg.Key).Seal(nil, nil, pt, recordsAAD()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p+".new", p); err != nil {
		t.Fatal(err)
	}
	return p
}

// keptNow is b's kept records, read under the lock.
func keptNow(b *bbox) []Kept {
	var out []Kept
	b.h.With(func(*kernel.Kernel) error { out = slices.Clone(b.h.bk.kept); return nil })
	return out
}

// reopen closes b's kernel and starts another on its files, returning the
// start's error; b.h is then the new kernel, or the closed one.
func reopen(b *bbox) error {
	b.h.Close()
	h, err := OpenKernel(b.cfg, b.now)
	if err == nil {
		b.h = h
	}
	return err
}

// A records file of exactly maxRecords bytes saves and loads whole; one
// byte more is refused both ways. A link, a file open to other uids, one
// not sealed under the key and a record with a field it does not know are
// refused, and a load keeps no descriptor open.
func TestTheRecordsFileUpToItsBound(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	bk := b.h.bk
	p := filepath.Join(b.cfg.BackupDir, recordsName)
	empty, _ := json.Marshal([]Kept{{}})
	pad := maxRecords - len(empty) - sealer(b.cfg.Key).Overhead()
	for n, ok := range map[int]bool{pad: true, pad + 1: false} {
		bk.kept = []Kept{{Target: strings.Repeat("a", n)}}
		if err := bk.save(); (err == nil) != ok {
			t.Fatalf("save of %d bytes: %v", maxRecords-pad+n, err)
		}
	}
	if fi, err := os.Stat(p); err != nil || fi.Size() != maxRecords {
		t.Fatalf("the records file: %v %v, want %d bytes", fi, err, maxRecords)
	}
	if kept, err := bk.load(); err != nil || len(kept) != 1 || len(kept[0].Target) != pad {
		t.Fatalf("load of %d bytes: %d records, %v", maxRecords, len(kept), err)
	}
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte{0})
	f.Close()
	if _, err := bk.load(); !errors.Is(err, ErrRecordsFile) {
		t.Fatalf("load of %d bytes: %v, want ErrRecordsFile", maxRecords+1, err)
	}
	sealRecords(t, b, []byte(`[{"target":"drive","unknown":1}]`))
	if _, err := bk.load(); !errors.Is(err, ErrRecordsFile) {
		t.Fatalf("a record with an unknown field: %v, want ErrRecordsFile", err)
	}
	if err := os.WriteFile(p, make([]byte, 100), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.load(); !errors.Is(err, ErrRecordsFile) {
		t.Fatalf("records not sealed under the key: %v, want ErrRecordsFile", err)
	}
	sealRecords(t, b, []byte(`[]`))
	for range 3 {
		if _, err := bk.load(); err != nil {
			t.Fatal(err)
		}
		if n := openFDsTo(t, p); n != 0 {
			t.Fatalf("%d descriptors to the records file stay open", n)
		}
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.load(); err == nil {
		t.Fatal("a records file open to other uids was read")
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), p); err != nil {
		t.Fatal(err)
	}
	if _, err := bk.load(); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a records file that is a link: %v, want ELOOP", err)
	}
}

// A kept record the log names is left as it is at a start, its Upto too,
// and logs nothing; one the log does not name and cannot take (its
// snapshot after the head), or one at a target the log never added, stops
// the start.
func TestAStartTakesOnlyRecordsItsLogCanName(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	b.backup()
	kept := keptNow(b)
	kept[0].Upto = 0
	pt, _ := json.Marshal(kept)
	sealRecords(t, b, pt)
	n := len(b.logBytes())
	if err := reopen(b); err != nil {
		t.Fatal(err)
	}
	if got := keptNow(b); got[0].Upto != 0 || len(b.logBytes()) != n {
		t.Fatalf("a logged record at a start: upto %d, log %d bytes, want 0 and %d", got[0].Upto, len(b.logBytes()), n)
	}
	id := kept[0].Record.BackupID
	other := id[:31] + map[bool]string{true: "1", false: "0"}[id[31] == '0']
	for _, c := range []struct{ target, id, why string }{{"drive", other, "cannot log it"}, {"nope", id, "never added"}} {
		k := slices.Clone(kept)
		k[0].Target, k[0].Record.BackupID, k[0].Upto = c.target, c.id, 1<<40
		pt, _ := json.Marshal(k)
		sealRecords(t, b, pt)
		if err := reopen(b); !errors.Is(err, ErrRecordsFile) || !strings.Contains(err.Error(), c.why) {
			t.Fatalf("a record the log cannot take: %v, want %q", err, c.why)
		}
	}
}

// A re-seal keeps the content object's sum; a written backup keeps its
// key table's.
func TestAKeptRecordKeepsItsSums(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	b.subject()
	dir := b.addTarget("drive", false)
	b.backup()
	before := keptNow(b)[0].Record
	tb, err := backup.DirTarget{Dir: dir}.GetTable(before.BackupID, before.Generation)
	if err != nil || before.TableSum != sumHex(tb) || before.ContentSum == "" {
		t.Fatalf("the written record: %+v %v", before, err)
	}
	b.erase(sub)
	after := keptNow(b)[0].Record
	if after.Generation == before.Generation || after.ContentSum != before.ContentSum {
		t.Fatalf("the re-sealed record: %+v, want a new table and the same content sum %s", after, before.ContentSum)
	}
}

// A backup directory open to other uids stops the start; without a content
// directory the kernel still takes a backup target.
func TestTheBackupDirectoryAndTheGuard(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	if err := os.Chmod(b.cfg.BackupDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := reopen(b); err == nil {
		t.Fatal("a backup directory open to other uids was taken")
	}
	if err := os.Chmod(b.cfg.BackupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	b.cfg.ContentDir, b.cfg.Stores = "", nil
	if err := reopen(b); err != nil {
		t.Fatal(err)
	}
	if err := b.add(kernel.BackupTarget{Name: "drive", Kind: kernel.KindDir, Locator: t.TempDir()}); err != nil {
		t.Fatalf("a target with no content directory: %v", err)
	}
}

// A target at a file is no directory; one in the kernel's data refuses
// every call; an append-only one refuses a delete; one whose first table
// is on its way refuses every call.
func TestATargetRefusesWhatItCannotHold(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := b.add(kernel.BackupTarget{Name: "file", Kind: kernel.KindDir, Locator: f}); !errors.Is(err, ErrTargetNotDir) {
		t.Fatalf("a target at a file: %v, want ErrTargetNotDir", err)
	}
	const id = "0123456789abcdef0123456789abcdef"
	calls := func(tg backup.Target) []error {
		_, gerr := tg.GetTable(id, 1)
		_, lerr := tg.Tables(id)
		return []error{tg.PutTable(id, 1, []byte("t")), gerr, tg.DeleteTable(id, 1), lerr}
	}
	for i, err := range calls(dirTarget{b.h.bk, b.cfg.KeyDir, false}) {
		if !errors.Is(err, ErrTargetInKernel) {
			t.Fatalf("call %d at a target in the kernel's data: %v", i, err)
		}
	}
	dir := t.TempDir()
	if err := (dirTarget{b.h.bk, dir, true}).DeleteTable(id, 1); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("a delete at an append-only target: %v", err)
	}
	on := new(atomic.Bool)
	on.Store(true)
	for i, err := range calls(inFlight{dirTarget{b.h.bk, dir, false}, on}) {
		if !errors.Is(err, ErrInFlight) {
			t.Fatalf("call %d while the first table is on its way: %v", i, err)
		}
	}
}

// A snapshot stops on a log it cannot size, a key table it cannot list and
// a key it cannot read, and leaves out a key no live subject names.
func TestASnapshotStopsOnWhatItCannotRead(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	b.addTarget("drive", false)
	stray := newBBox(t, recipientWire(t, testRK)).subject()
	if err := b.h.bk.keys.Put(stray, [32]byte{9}); err != nil {
		t.Fatal(err)
	}
	b.backup()
	if got := keptNow(b)[0].Record.Subjects; !slices.Equal(got, []string{sub}) {
		t.Fatalf("the backup's subjects %q, want %q alone", got, sub)
	}
	b.now += BackupEvery
	was := b.h.store.f
	b.h.store.f = statFails{was}
	if _, err := b.h.Backup(b.now); !errors.Is(err, errFault) {
		t.Fatalf("a backup of a log it cannot size: %v", err)
	}
	b.h.store.f = was
	kf := filepath.Join(b.cfg.KeyDir, sub+keyExt)
	if err := os.Rename(kf, kf+".x"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(kf+".x", kf); err != nil {
		t.Fatal(err)
	}
	if _, err := b.h.Backup(b.now); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a backup of a key that is a link: %v", err)
	}
	if os.Geteuid() == 0 {
		return // root lists any directory; CI runs these as a plain user
	}
	if err := os.Chmod(b.cfg.KeyDir, 0o300); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(b.cfg.KeyDir, 0o700)
	if _, err := b.h.Backup(b.now); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("a backup of a key table it cannot list: %v", err)
	}
}

type statFails struct{ logFile }

func (statFails) Stat() (os.FileInfo, error) { return nil, errFault }

// snapDir is the one snapshot directory in b's backup directory.
func snapDir(t *testing.T, b *bbox) string {
	m, _ := filepath.Glob(filepath.Join(b.cfg.BackupDir, snapPrefix+"*"))
	if len(m) != 1 {
		t.Fatalf("snapshots %q, want one", m)
	}
	return m[0]
}

// A snapshot links each item, and where it copies, leaves out an item gone
// from the store and stops on one it cannot read.
func TestASnapshotLinksOrCopiesEachItem(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	h := b.seal(sub, []byte("an item"))
	b.addTarget("drive", false)
	item := filepath.Join(b.storeDir(), itemName(h))
	linked := false
	b.h.bk.hook = func() {
		a, _ := os.Stat(item)
		c, _ := os.Stat(filepath.Join(snapDir(t, b), "vision", itemName(h)))
		linked = a != nil && c != nil && os.SameFile(a, c)
	}
	if tk := b.backup(); !linked || tk[0].Backup == nil || !tk[0].Backup.Verified {
		t.Fatalf("a snapshot of an item it can link: linked %v, %+v", linked, tk)
	}
	b.h.bk.hook = nil
	b.h.bk.link = func(string, string) error { return errors.New("cross-device link") }
	if err := os.Rename(item, item+".x"); err != nil {
		t.Fatal(err)
	}
	b.now += BackupEvery
	if tk := b.backup(); tk[0].Backup == nil || !tk[0].Backup.Verified {
		t.Fatalf("a copy of an item gone from the store: %+v", tk)
	}
	if err := os.Symlink(item+".x", item); err != nil {
		t.Fatal(err)
	}
	b.now += BackupEvery
	if _, err := b.h.Backup(b.now); !errors.Is(err, syscall.ELOOP) {
		t.Fatalf("a copy of an item that is a link: %v, want ELOOP", err)
	}
}

// A content section leaves out an item gone from the snapshot and stops on
// one it cannot read; a log section it cannot open fails the write.
func TestASectionLeavesOutOrStops(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	h := b.seal(b.subject(), []byte("an item"))
	b.addTarget("drive", false)
	inSnap := func(do func(p string)) func() {
		return func() { do(filepath.Join(snapDir(t, b), "vision", itemName(h))) }
	}
	b.h.bk.hook = inSnap(func(p string) { os.Remove(p) })
	if tk := b.backup(); tk[0].Error != "" || tk[0].Backup == nil || !tk[0].Backup.Verified {
		t.Fatalf("a section with an item gone: %+v", tk)
	}
	b.now += BackupEvery
	b.h.bk.hook = inSnap(func(p string) { os.Remove(p); os.Symlink("/dev/null", p) })
	if tk := b.backup(); tk[0].Error == "" {
		t.Fatalf("a section with an item that is a link: %+v", tk)
	}
	b.now += BackupEvery
	b.h.bk.hook = func() { os.Rename(b.cfg.Log, b.cfg.Log+".x") }
	tk := b.backup()
	if err := os.Rename(b.cfg.Log+".x", b.cfg.Log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tk[0].Error, "no such file") {
		t.Fatalf("a log section it cannot open: %+v", tk)
	}
}

// The newest verified backup at a target is kept for BackupEvery, and from
// its own time on: of two made at once, the later counts. A call that
// keeps one target's and writes another's does both, and one that keeps
// every target's takes no snapshot.
func TestABackupKeepsWhatIsRecentAndVerified(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	b.h.bk.wrap = func(t backup.Target) backup.Target { return flipTable{t} }
	if tk := b.backup(); tk[0].Backup.Verified {
		t.Fatalf("a mismatched read-back: %+v", tk)
	}
	b.h.bk.wrap = nil
	if tk := b.backup(); tk[0].Reused || !tk[0].Backup.Verified {
		t.Fatalf("the write after an unverified one: %+v", tk)
	}
	if tk := b.backup(); !tk[0].Reused {
		t.Fatalf("a backup at once after a verified one: %+v", tk)
	}
	b.addTarget("other", false)
	if tk := b.backup(); len(tk) != 2 || !tk[0].Reused || tk[1].Reused || tk[1].Error != "" {
		t.Fatalf("a call that keeps one and writes one: %+v", tk)
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(b.cfg.KeyDir, 0o300); err != nil {
			t.Fatal(err)
		}
		tk, err := b.h.Backup(b.now)
		os.Chmod(b.cfg.KeyDir, 0o700)
		if err != nil || len(tk) != 2 || !tk[0].Reused || !tk[1].Reused {
			t.Fatalf("a call that keeps every target's: %+v %v", tk, err)
		}
	}
	b.now += BackupEvery
	if tk := b.backup(); tk[0].Reused || tk[1].Reused {
		t.Fatalf("a backup BackupEvery after: %+v", tk)
	}
}

// A backup's content object is synced, closed and put in place, its
// directory synced, and no temporary stays.
func TestABackupWriteSyncsAndCleansUp(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	dir := b.addTarget("drive", false)
	got := syncs(t, nil)
	tmps := func() int {
		n := 0
		des, _ := os.ReadDir("/proc/self/fd")
		for _, de := range des {
			if l, _ := os.Readlink(filepath.Join("/proc/self/fd", de.Name())); strings.HasPrefix(l, filepath.Join(dir, ".tmp-content-")) {
				n++
			}
		}
		return n
	}
	tk := b.backup()
	if tk[0].Backup == nil || !tk[0].Backup.Verified || tmps() != 0 {
		t.Fatalf("the write: %+v, %d descriptors to its temporary", tk, tmps())
	}
	var file, d int
	for _, s := range got() {
		file += map[bool]int{true: 1}[strings.HasPrefix(s, filepath.Join(dir, ".tmp-content-"))]
		d += map[bool]int{true: 1}[s == dir]
	}
	if file != 1 || d == 0 {
		t.Fatalf("synced the content object %d times and its directory %d: %q", file, d, got())
	}
	if m, _ := filepath.Glob(filepath.Join(dir, ".tmp-content-*")); len(m) != 0 {
		t.Fatalf("temporaries stay: %q", m)
	}
	if os.Geteuid() == 0 {
		return // root writes anywhere; CI runs these as a plain user
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	b.now += BackupEvery
	if tk := b.backup(); tk[0].Error == "" {
		t.Fatalf("a write to a directory closed to it: %+v", tk)
	}
}

// A kernel without backups answers ErrBackupsOff to every backup call; one
// with no recipient holds none to rotate from.
func TestBackupCallsWithoutBackups(t *testing.T) {
	d := t.TempDir()
	h, err := OpenKernel(KernelConfig{Log: filepath.Join(d, "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub,
		Sign: headPriv, Anchors: anchors, KeyDir: filepath.Join(d, "keys")}, 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	_, e1 := h.Backups()
	_, e2 := h.Backup(1_000_000)
	_, e3 := h.RecoveryRotate(1_000_000, "", key.Cosign{})
	for i, err := range []error{e1, e2, e3, h.AddBackupTarget(1_000_000, kernel.BackupTarget{}, key.Cosign{}),
		h.SwitchRecipient(1_000_000, nil, nil)} {
		if !errors.Is(err, ErrBackupsOff) {
			t.Fatalf("call %d without backups: %v", i, err)
		}
	}
	b := newBBox(t, nil)
	if _, err := b.h.RecoveryRotate(b.now, "", key.Cosign{}); err == nil {
		t.Fatal("a rotation with no signature was taken")
	}
}

// sectionNames are the sections of backup id at dir, in order.
func sectionNames(t *testing.T, dir, id string) []string {
	t.Helper()
	f := mustOpen(t, filepath.Join(dir, id+contentExt))
	defer f.Close()
	_, secs, err := backup.Open(f, testRK)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for {
		s, _, err := secs.Next()
		if err != nil {
			return out
		}
		out = append(out, s.Name)
	}
}

// A backup with no item to carry, or no content directory to carry them
// from, takes no snapshot directory and writes the log section alone.
func TestABackupWithNoItemsTakesNoSnapshot(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	dir := b.addTarget("drive", false)
	snaps := -1
	b.h.bk.hook = func() {
		m, _ := filepath.Glob(filepath.Join(b.cfg.BackupDir, snapPrefix+"*"))
		snaps = len(m)
	}
	if tk := b.backup(); snaps != 0 || !slices.Equal(sectionNames(t, dir, tk[0].Backup.BackupID), []string{"log"}) {
		t.Fatalf("a backup with no item: %d snapshots, %+v", snaps, tk)
	}
	b.seal(sub, []byte("an item"))
	b.cfg.ContentDir, b.cfg.Stores = "", nil
	if err := reopen(b); err != nil {
		t.Fatal(err)
	}
	b.h.bk.hook = func() {
		m, _ := filepath.Glob(filepath.Join(b.cfg.BackupDir, snapPrefix+"*"))
		snaps = len(m)
	}
	b.now += BackupEvery
	if tk := b.backup(); snaps != 0 || !slices.Equal(sectionNames(t, dir, tk[0].Backup.BackupID), []string{"log"}) {
		t.Fatalf("a backup with no content directory: %d snapshots, %+v", snaps, tk)
	}
}
