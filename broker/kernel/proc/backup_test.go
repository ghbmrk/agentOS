package proc

// REQ: BAK-1, LOG-4

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// MIG-4-recovery-e3 (#3251): the kernel process takes, writes and verifies
// backups, and keeps their records for an erase.

var testRK = bytes.Repeat([]byte{0x5a}, 32)

// recipientWire is rk's recipient as the unlock step hands it.
func recipientWire(t *testing.T, rk []byte) []byte {
	t.Helper()
	r, err := backup.RecipientFor(rk)
	if err != nil {
		t.Fatal(err)
	}
	return append(slices.Clone(r.X), r.EK...)
}

// bbox is a kernel process with its data folder, its key table and its
// backups' records, which restarts over the same files.
type bbox struct {
	t   *testing.T
	cfg KernelConfig
	h   *Kernel
	now int64
}

func newBBox(t *testing.T, recipient []byte) *bbox {
	t.Helper()
	data := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(data, "log")
	b := &bbox{t: t, now: 1_000_000, cfg: KernelConfig{
		Log: logPath, Anchor: anchor(t, logPath), Key: [32]byte{7}, Pub: headPub, Sign: headPriv, Anchors: anchors,
		KeyDir: filepath.Join(data, "keys"), BackupDir: filepath.Join(data, "backups"), Recipient: recipient,
		ContentDir: filepath.Join(data, "content"), Stores: []string{"vision"},
	}}
	b.open()
	t.Cleanup(func() { b.h.Close() })
	return b
}

func (b *bbox) open() {
	b.t.Helper()
	h, err := OpenKernel(b.cfg, b.now)
	if err != nil {
		b.t.Fatal(err)
	}
	b.h = h
}

func (b *bbox) restart() {
	b.t.Helper()
	b.h.Close()
	b.open()
}

// addTarget adds a dir target at a fresh directory, signed by an anchor.
func (b *bbox) addTarget(name string, appendOnly bool) string {
	b.t.Helper()
	dir := b.t.TempDir()
	b.add(kernel.BackupTarget{Name: name, Kind: kernel.KindDir, Locator: dir, AppendOnly: appendOnly})
	return dir
}

func (b *bbox) add(t kernel.BackupTarget) error {
	var n int
	b.h.With(func(k *kernel.Kernel) error { n = k.State().TargetsAdded(); return nil })
	c := key.Approve(key.Ed25519Signer(ownerPriv), kernel.BackupTargetHash(n, t))
	return b.h.AddBackupTarget(b.now, t, c)
}

func (b *bbox) subject() string {
	b.t.Helper()
	var sub string
	if err := b.h.With(func(k *kernel.Kernel) (err error) { sub, err = k.OpenSubject(b.now); return err }); err != nil {
		b.t.Fatal(err)
	}
	return sub
}

func (b *bbox) backup() []Taken {
	b.t.Helper()
	out, err := b.h.Backup(b.now)
	if err != nil {
		b.t.Fatal(err)
	}
	return out
}

func (b *bbox) logBytes() []byte {
	b.t.Helper()
	l, err := os.ReadFile(b.cfg.Log)
	if err != nil {
		b.t.Fatal(err)
	}
	return l
}

// openBackup opens backup id at dir with rk: the log section and the keys
// its newest key table gives. Only content sections follow the log.
func openBackup(t *testing.T, dir, id string, rk []byte) ([]byte, *kernel.MemKeys) {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, id+".content"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, secs, err := backup.Open(f, rk)
	if err != nil {
		t.Fatal(err)
	}
	s, r, err := secs.Next()
	if err != nil || s.Name != "log" {
		t.Fatalf("first section %q: %v", s.Name, err)
	}
	logBytes, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	for {
		s, _, err := secs.Next()
		if err == io.EOF {
			break
		}
		if err != nil || !strings.HasPrefix(s.Name, "content/") {
			t.Fatalf("a section %q after the log: %v", s.Name, err)
		}
	}
	gens, err := backup.DirTarget{Dir: dir}.Tables(id)
	if err != nil || len(gens) == 0 {
		t.Fatalf("tables of %s: %v %v", id, gens, err)
	}
	tb, err := os.Open(filepath.Join(dir, id+".table."+itoa(gens[len(gens)-1])))
	if err != nil {
		t.Fatal(err)
	}
	defer tb.Close()
	keys := kernel.NewMemKeys()
	if _, err := backup.UnwrapTable(tb, rk, id, keys); err != nil {
		t.Fatal(err)
	}
	return logBytes, keys
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

// serveOwner serves the owner side of h on a fresh socket.
func serveOwner(t *testing.T, h *Kernel, clock func() int64) Owner {
	t.Helper()
	sock := filepath.Join(shortDir(t), "owner.sock")
	ln, err := ListenKernel(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go ServeKernel(ln, h, OwnerSide, clock)
	return Owner{Conn{Socket: sock, UID: os.Getuid(), Timeout: 20 * time.Second}}
}

// A backup taken through the owner socket opens with the recovery key
// alone, and holds the log as it was and the live subjects' keys.
func TestBackupOpensWithTheRecoveryKeyOnly(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	o := serveOwner(t, b.h, func() int64 { return b.now })
	dir := t.TempDir()
	tg := kernel.BackupTarget{Name: "drive", Kind: kernel.KindDir, Locator: dir}
	if err := o.BackupTarget(tg, key.Approve(key.Ed25519Signer(ownerPriv), kernel.BackupTargetHash(0, tg))); err != nil {
		t.Fatal(err)
	}
	logNow := b.logBytes()
	taken, err := o.Backup()
	if err != nil || len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Verified || taken[0].Error != "" {
		t.Fatalf("backup: %+v %v", taken, err)
	}
	id := taken[0].Backup.BackupID
	gotLog, keys := openBackup(t, dir, id, testRK)
	if !bytes.Equal(gotLog, logNow) {
		t.Fatalf("the backup's log is %d bytes, the log was %d", len(gotLog), len(logNow))
	}
	live, ok, err := b.h.bk.keys.Get(sub)
	if err != nil || !ok {
		t.Fatal(err)
	}
	if k, ok, _ := keys.Get(sub); !ok || k != live {
		t.Fatal("the backup's key table does not give the live subject's key")
	}
	if _, _, err := backup.Open(mustOpen(t, filepath.Join(dir, id+".content")), bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("another recovery key opened the backup")
	}
	v, err := o.Backups()
	if err != nil || v.Recipient == "" || len(v.Targets) != 1 || len(v.Backups) != 1 || v.Backups[0].BackupID != id || !v.Backups[0].Verified {
		t.Fatalf("backups: %+v %v", v, err)
	}
	if err := o.Untarget("drive"); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Backup(); !errors.Is(err, ErrNoBackupTarget) {
		t.Fatalf("a backup with no current target: %v", err)
	}
}

func mustOpen(t *testing.T, p string) *os.File {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// Two targets get two backups, each with its own ID, each verified on its
// own target only.
func TestOneBackupPerTarget(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	d1, d2 := b.addTarget("one", false), b.addTarget("two", false)
	taken := b.backup()
	if len(taken) != 2 || taken[0].Backup == nil || taken[1].Backup == nil {
		t.Fatalf("taken: %+v", taken)
	}
	id1, id2 := taken[0].Backup.BackupID, taken[1].Backup.BackupID
	if id1 == id2 || taken[0].Target != "one" || taken[1].Target != "two" || !taken[0].Backup.Verified || !taken[1].Backup.Verified {
		t.Fatalf("taken: %+v", taken)
	}
	for dir, ids := range map[string][2]string{d1: {id1, id2}, d2: {id2, id1}} {
		if _, err := os.Stat(filepath.Join(dir, ids[0]+".content")); err != nil {
			t.Fatalf("%s lacks its own backup: %v", dir, err)
		}
		if gens, _ := (backup.DirTarget{Dir: dir}).Tables(ids[1]); len(gens) != 0 {
			t.Fatalf("%s holds the other target's key table", dir)
		}
		if _, err := os.Stat(filepath.Join(dir, ids[1]+".content")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s holds the other target's content: %v", dir, err)
		}
	}
}

// Entries appended while a backup is written are not in it, and the
// backup does not fail with ErrChanged.
func TestSnapshotIgnoresLaterAppends(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	dir := b.addTarget("drive", false)
	before := b.logBytes()
	var late []string
	b.h.bk.hook = func() { late = append(late, b.subject()) }
	taken := b.backup()
	b.h.bk.hook = nil
	if len(late) != 2 || len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Verified {
		t.Fatalf("taken %+v, late subjects %v", taken, late)
	}
	got, keys := openBackup(t, dir, taken[0].Backup.BackupID, testRK)
	if !bytes.Equal(got, before) || len(b.logBytes()) <= len(before) {
		t.Fatalf("the backup holds %d bytes of the log; it was %d before and is %d now", len(got), len(before), len(b.logBytes()))
	}
	for _, s := range late {
		if _, ok, _ := keys.Get(s); ok {
			t.Fatalf("a subject opened after the snapshot is in the key table")
		}
	}
}

// flipTable gives back other bytes than the target holds.
type flipTable struct{ backup.Target }

func (f flipTable) GetTable(id string, gen uint64) ([]byte, error) {
	b, err := f.Target.GetTable(id, gen)
	if len(b) > 0 {
		b[len(b)-1] ^= 1
	}
	return b, err
}

// A target that reads back other bytes leaves the backup unverified, its
// record kept for an erase; the next backup writes again.
func TestReadBackMismatchIsNeverVerified(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	b.h.bk.wrap = func(t backup.Target) backup.Target { return flipTable{t} }
	taken := b.backup()
	if len(taken) != 1 || taken[0].Backup == nil || taken[0].Backup.Verified {
		t.Fatalf("a mismatched read-back: %+v", taken)
	}
	first := taken[0].Backup.BackupID
	if v, _ := b.h.Backups(); len(v.Backups) != 1 || v.Backups[0].Verified {
		t.Fatalf("backups: %+v", v)
	}
	if !slices.Contains(b.h.bk.set.List(), first) {
		t.Fatal("an unverified backup is not in the erase's set")
	}
	b.h.bk.wrap = nil
	b.now += 60_000
	taken = b.backup()
	if len(taken) != 1 || taken[0].Reused || taken[0].Backup == nil || taken[0].Backup.BackupID == first || !taken[0].Backup.Verified {
		t.Fatalf("the backup after a mismatch: %+v", taken)
	}
}

// Records and verified marks survive a restart; a records file edited on
// the drive stops the start.
func TestRecordsSurviveRestartAndRefuseATamperedFile(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	taken := b.backup()
	b.restart()
	v, err := b.h.Backups()
	if err != nil || len(v.Backups) != 1 || v.Backups[0].BackupID != taken[0].Backup.BackupID || !v.Backups[0].Verified || len(v.Targets) != 1 {
		t.Fatalf("backups after a restart: %+v %v", v, err)
	}
	if got := b.h.bk.set.List(); !slices.Equal(got, []string{taken[0].Backup.BackupID}) {
		t.Fatalf("the set after a restart: %v", got)
	}
	b.h.Close()
	p := filepath.Join(b.cfg.BackupDir, "records")
	f, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	f[len(f)/2] ^= 1
	if err := os.WriteFile(p, f, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKernel(b.cfg, b.now); !errors.Is(err, ErrRecordsFile) {
		t.Fatalf("a tampered records file: %v", err)
	}
	b.h, _ = OpenKernel(KernelConfig{Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7}, Pub: headPub, Sign: headPriv}, b.now)
}

// After a restart, an erase re-seals every kept backup that gave the
// subject's key through the Set this slice builds, at a removed target
// too (the #3188 path, end to end; blocker 2 of the #3255 fix-list).
func TestEraseResealsAKeptBackup(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, kept := b.subject(), b.subject()
	d1, d2 := b.addTarget("one", false), b.addTarget("two", false)
	taken := b.backup()
	if err := b.h.With(func(k *kernel.Kernel) error { return k.Untarget(b.now, "two") }); err != nil {
		t.Fatal(err)
	}
	b.restart()
	c, err := b.h.Erase(b.now, gone)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{taken[0].Backup.BackupID, taken[1].Backup.BackupID}
	if got := slices.Sorted(slices.Values(c.Resealed)); !slices.Equal(got, slices.Sorted(slices.Values(ids))) || len(c.StillHeld) != 0 || c.BackupsUnknown {
		t.Fatalf("the erase's confirmation: %+v, want both of %v resealed", c, ids)
	}
	for i, dir := range []string{d1, d2} {
		_, keys := openBackup(t, dir, ids[i], testRK)
		if _, ok, _ := keys.Get(gone); ok {
			t.Fatalf("%s still gives the erased subject's key", dir)
		}
		if _, ok, _ := keys.Get(kept); !ok {
			t.Fatalf("%s lost a live subject's key", dir)
		}
		if gens, _ := (backup.DirTarget{Dir: dir}).Tables(ids[i]); len(gens) != 1 {
			t.Fatalf("%s keeps key tables %v", dir, gens)
		}
	}
	// The re-sealed records are what the next start reads.
	b.restart()
	v, _ := b.h.Backups()
	for _, bv := range v.Backups {
		if bv.Generation != 2 {
			t.Fatalf("a re-sealed record after a restart: %+v", bv)
		}
	}
}

// Within BackupEvery a backup returns the last verified one; after it, or
// at a new recipient, it writes again.
func TestRateAndRecipientChange(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	first := b.backup()[0].Backup.BackupID
	b.now += 60_000
	again := b.backup()
	if !again[0].Reused || again[0].Backup.BackupID != first {
		t.Fatalf("a second backup within ten minutes: %+v", again)
	}
	b.now += BackupEvery
	later := b.backup()
	if later[0].Reused || later[0].Backup.BackupID == first {
		t.Fatalf("a backup past ten minutes: %+v", later)
	}
	rk2 := bytes.Repeat([]byte{0x6b}, 32)
	b.cfg.Recipient = recipientWire(t, rk2)
	b.restart()
	b.now += 1000
	rotated := b.backup()
	if rotated[0].Reused || rotated[0].Backup.BackupID == later[0].Backup.BackupID {
		t.Fatalf("a backup at a new recipient: %+v", rotated)
	}
	v, _ := b.h.Backups()
	if v.Recipient != rotated[0].Backup.Recipient || v.Recipient == later[0].Backup.Recipient {
		t.Fatalf("recipients: now %s, last %s, before %s", v.Recipient, rotated[0].Backup.Recipient, later[0].Backup.Recipient)
	}
	if v.Backups[len(v.Backups)-1].BackupID != rotated[0].Backup.BackupID {
		t.Fatal("the new backup is not kept")
	}
}

// A box enrolled before the recipient was stored refuses every backup
// with a fixed reason, across the socket too.
func TestNoRecipientRefuses(t *testing.T) {
	b := newBBox(t, nil)
	b.addTarget("drive", false)
	if _, err := b.h.Backup(b.now); !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("a backup with no recipient: %v", err)
	}
	o := serveOwner(t, b.h, func() int64 { return b.now })
	if _, err := o.Backup(); !errors.Is(err, ErrNoRecipient) {
		t.Fatalf("over the socket: %v", err)
	}
	if v, err := o.Backups(); err != nil || v.Recipient != "" || len(v.Backups) != 0 {
		t.Fatalf("backups: %+v %v", v, err)
	}
	b.cfg.Recipient = []byte("short")
	b.h.Close()
	if _, err := OpenKernel(b.cfg, b.now); !errors.Is(err, handoff.ErrHandoff) {
		t.Fatalf("a malformed recipient: %v", err)
	}
	b.cfg.Recipient = nil
	b.open()
}

// An append-only target is reported as one an erase cannot rewrite, and
// an erase leaves its backup held, saying why.
func TestAppendOnlyTargetReportedUnrewritable(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	b.addTarget("worm", true)
	taken := b.backup()
	v, _ := b.h.Backups()
	if len(v.Targets) != 1 || v.Targets[0].Rewritable || !v.Targets[0].AppendOnly {
		t.Fatalf("an append-only target: %+v", v.Targets)
	}
	c, _ := b.h.Erase(b.now, sub)
	if len(c.StillHeld) != 1 || c.StillHeld[0].Backup != taken[0].Backup.BackupID || len(c.Resealed) != 0 {
		t.Fatalf("an erase at an append-only target: %+v", c)
	}
}

// A dir target cannot be, or be inside, the kernel's own data folder, by
// its path or through a link, at the add and again at the write (#3251
// review note 1).
func TestADirTargetInTheKernelsDataRefuses(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	data := filepath.Dir(b.cfg.Log)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(b.cfg.KeyDir, link); err != nil {
		t.Fatal(err)
	}
	for _, loc := range []string{data, b.cfg.KeyDir, b.cfg.BackupDir, link} {
		if err := b.add(kernel.BackupTarget{Name: "bad", Kind: kernel.KindDir, Locator: loc}); !errors.Is(err, ErrTargetInKernel) {
			t.Errorf("a target at %s: %v", loc, err)
		}
	}
	sub := filepath.Join(data, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := b.add(kernel.BackupTarget{Name: "bad", Kind: kernel.KindDir, Locator: sub}); !errors.Is(err, ErrTargetInKernel) {
		t.Errorf("a target in a subfolder: %v", err)
	}
	if err := b.add(kernel.BackupTarget{Name: "bad", Kind: kernel.KindDir, Locator: filepath.Join(t.TempDir(), "absent")}); !errors.Is(err, ErrTargetNotDir) {
		t.Errorf("a missing target: %v", err)
	}
	// A link swapped in after the add.
	swap := filepath.Join(t.TempDir(), "swap")
	if err := os.Mkdir(swap, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := b.add(kernel.BackupTarget{Name: "swap", Kind: kernel.KindDir, Locator: swap}); err != nil {
		t.Fatal(err)
	}
	os.Remove(swap)
	if err := os.Symlink(data, swap); err != nil {
		t.Fatal(err)
	}
	b.subject()
	taken := b.backup()
	if len(taken) != 1 || taken[0].Backup != nil || taken[0].Error != ErrTargetInKernel.Error() {
		t.Fatalf("a backup to a target linked into the data folder: %+v", taken)
	}
	if es, _ := os.ReadDir(data); slices.ContainsFunc(es, func(e os.DirEntry) bool { return filepath.Ext(e.Name()) == ".content" }) {
		t.Fatal("a backup was written into the data folder")
	}
}

// The kernel process never starts without its backups' records.
func TestRunKernelNeedsABackupDir(t *testing.T) {
	err := RunKernel(t.Context(), MainConfig{Log: filepath.Join(t.TempDir(), "log"), KeyDir: t.TempDir()}, handoff.KernelKeys{Head: headPriv}, &kernel.MemAnchor{})
	if !errors.Is(err, ErrNoBackupDir) {
		t.Fatalf("RunKernel with no backup dir: %v", err)
	}
	if _, err := OpenKernel(KernelConfig{Log: filepath.Join(t.TempDir(), "log"), Anchor: &kernel.MemAnchor{}, Key: [32]byte{7},
		Pub: headPub, Sign: headPriv, Anchors: anchors, BackupDir: t.TempDir()}, 1000); err == nil {
		t.Fatal("backups opened with no key table")
	}
}

// A backup's key table written as a subject's key file does not open as
// one: the table never uses the log key (MIG-4-recovery-a,
// TestTableNeverUsesTheLogKey, which cannot link this package).
func TestABackupTableIsNoKeyFile(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	sub := b.subject()
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	obj, err := os.ReadFile(filepath.Join(dir, id+".table.1"))
	if err != nil {
		t.Fatal(err)
	}
	fk, err := OpenFileKeys(filepath.Join(t.TempDir(), "keys"), b.cfg.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fk.dir, sub+keyExt), obj, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fk.Get(sub); err == nil {
		t.Fatal("a key table opens as a FileKeys key")
	}
}

// REC-1: a backup's key table unwraps into a fresh FileKeys, and a kernel
// started on the log with a later erase appended deletes that subject's
// key and finds every live one (MIG-4-recovery-a,
// TestUnwrapIntoAFreshFileKeys, which cannot link this package).
func TestARestoreUnwrapsIntoFreshFileKeys(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	live, gone := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	table, err := os.ReadFile(filepath.Join(dir, id+".table.1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.h.Erase(b.now, gone); err != nil {
		t.Fatal(err)
	}
	later := b.logBytes()
	a := anchor(t, b.cfg.Log)
	b.h.Close()

	r := t.TempDir()
	fk, err := OpenFileKeys(filepath.Join(r, "keys"), b.cfg.Key)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := backup.UnwrapTable(bytes.NewReader(table), testRK, id, fk); err != nil || n != 2 {
		t.Fatalf("UnwrapTable: %d %v", n, err)
	}
	if _, err := backup.UnwrapTable(bytes.NewReader(table), testRK, id, fk); !errors.Is(err, backup.ErrNotEmpty) {
		t.Fatalf("an unwrap into a table that is not empty: %v", err)
	}
	if err := os.WriteFile(filepath.Join(r, "log"), later, 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := OpenKernel(KernelConfig{Log: filepath.Join(r, "log"), Anchor: a, Key: b.cfg.Key, Pub: headPub, Sign: headPriv,
		Anchors: anchors, KeyDir: filepath.Join(r, "keys")}, b.now)
	if err != nil {
		t.Fatal(err)
	}
	b.h = h
	if rep := h.Content(); len(rep.Missing) != 0 {
		t.Fatalf("restored keys missing: %v", rep.Missing)
	}
	if _, ok, _ := fk.Get(gone); ok {
		t.Fatal("the start left the erased subject's key")
	}
	if _, ok, _ := fk.Get(live); !ok {
		t.Fatal("the live subject's key is gone")
	}
}

// closeOnRead closes the kernel as the read-back starts: a stop partway
// through a backup, after its key table went out.
type closeOnRead struct {
	backup.Target
	h *Kernel
}

func (c closeOnRead) GetTable(id string, gen uint64) ([]byte, error) {
	c.h.Close()
	return c.Target.GetTable(id, gen)
}

// failAfterPut puts the table and then reports a failure, as a directory
// sync that fails after the link does.
type failAfterPut struct{ backup.Target }

func (f failAfterPut) PutTable(id string, gen uint64, b []byte) error {
	if err := f.Target.PutTable(id, gen, b); err != nil {
		return err
	}
	return errors.New("sync dir: input/output error")
}

// tablesAt lists every backup ID with a key table in dir.
func tablesAt(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, e := range es {
		if id, _, ok := strings.Cut(e.Name(), ".table."); ok {
			ids = append(ids, id)
		}
	}
	return ids
}

// LOG-4 (Security fix-list 1 on #3311): a key table never reaches a target
// without a kept Record. Whether the kernel stops partway through (a), the
// table lands but its put reports a failure (b), or the records cannot be
// saved (c), after a restart an erase either re-seals every table at the
// target or none went out.
func TestNoTableGoesOutWithoutAKeptRecord(t *testing.T) {
	for _, c := range []struct {
		name string
		wrap func(b *bbox) func(backup.Target) backup.Target
	}{
		{"stopped during read-back", func(b *bbox) func(backup.Target) backup.Target {
			return func(t backup.Target) backup.Target { return closeOnRead{t, b.h} }
		}},
		{"table landed, put failed", func(*bbox) func(backup.Target) backup.Target {
			return func(t backup.Target) backup.Target { return failAfterPut{t} }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newBBox(t, recipientWire(t, testRK))
			gone, live := b.subject(), b.subject()
			dir := b.addTarget("drive", false)
			b.h.bk.wrap = c.wrap(b)
			b.h.Backup(b.now)
			ids := tablesAt(t, dir)
			if len(ids) != 1 {
				t.Fatalf("tables at the target: %v", ids)
			}
			b.h.Close() // closed already when stopped during the read-back
			b.open()
			v, _ := b.h.Backups()
			if len(v.Backups) != 1 || v.Backups[0].BackupID != ids[0] || v.Backups[0].Verified || !v.Backups[0].Pending {
				t.Fatalf("kept after a restart: %+v", v.Backups)
			}
			conf, err := b.h.Erase(b.now, gone)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(conf.Resealed, ids) || len(conf.StillHeld) != 0 {
				t.Fatalf("the erase's confirmation: %+v", conf)
			}
			tb, err := os.ReadFile(filepath.Join(dir, ids[0]+".table.2"))
			if err != nil {
				t.Fatal(err)
			}
			keys := kernel.NewMemKeys()
			if _, err := backup.UnwrapTable(bytes.NewReader(tb), testRK, ids[0], keys); err != nil {
				t.Fatal(err)
			}
			if _, ok, _ := keys.Get(gone); ok {
				t.Fatal("the re-sealed table still gives the erased subject's key")
			}
			if _, ok, _ := keys.Get(live); !ok {
				t.Fatal("the re-sealed table lost a live subject's key")
			}
			if gens, _ := (backup.DirTarget{Dir: dir}).Tables(ids[0]); !slices.Equal(gens, []uint64{2}) {
				t.Fatalf("tables left: %v", gens)
			}
		})
	}
	t.Run("records not saved", func(t *testing.T) {
		b := newBBox(t, recipientWire(t, testRK))
		b.subject()
		dir := b.addTarget("drive", false)
		b.h.bk.saveErr = func() error { return errors.New("no space left on device") }
		taken := b.backup()
		if len(taken) != 1 || taken[0].Backup != nil || !strings.Contains(taken[0].Error, "nothing went out") {
			t.Fatalf("taken: %+v", taken)
		}
		if ids := tablesAt(t, dir); len(ids) != 0 {
			t.Fatalf("a table went out with no saved record: %v", ids)
		}
		if v, _ := b.h.Backups(); len(v.Backups) != 0 || len(b.h.bk.set.List()) != 0 {
			t.Fatalf("kept: %+v", v.Backups)
		}
		// A finish that cannot be saved leaves the saved pending record.
		saves := 0
		b.h.bk.saveErr = func() error {
			if saves++; saves > 1 {
				return errors.New("no space left on device")
			}
			return nil
		}
		taken = b.backup()
		if len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Pending || taken[0].Error == "" {
			t.Fatalf("a finish not saved: %+v", taken)
		}
		b.h.bk.saveErr = nil
		b.restart()
		// The first backup was logged before its save failed, so the
		// start rebuilds it (#3316); nothing of it went out.
		if v, _ := b.h.Backups(); len(v.Backups) != 2 || !v.Backups[0].Pending || v.Backups[0].Rebuilt ||
			!v.Backups[1].Rebuilt || len(b.h.bk.set.List()) != 2 {
			t.Fatalf("kept after a restart: %+v", v.Backups)
		}
	})
}

// eraseBeforePut runs an erase just before the key table goes out, after
// the pending record is saved.
type eraseBeforePut struct {
	backup.Target
	fire *func()
}

func (e eraseBeforePut) PutTable(id string, gen uint64, b []byte) error {
	if f := *e.fire; f != nil {
		*e.fire = nil
		f()
	}
	return e.Target.PutTable(id, gen, b)
}

// LOG-4 (#3311 L3 and Security on 6ef6bef): an erase that runs while a
// backup's first key table is on its way names the backup held, never
// re-sealed, and the table that then lands is re-sealed at once, so no
// table at the target gives the erased key. The erase is the kernel's,
// and a Tick's re-seal meets the in-flight table: the process's Erase
// waits for the write (#3338, TestAnEraseDuringABackupWriteNamesIt).
func TestAnEraseWhileATableIsOnItsWay(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, live := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	var conf kernel.Confirmation
	var fire func()
	fire = func() {
		if err := b.h.With(func(k *kernel.Kernel) (err error) { conf, err = k.Erase(b.now, gone); return err }); err != nil {
			t.Error(err)
		}
		if err := b.h.Tick(b.now); err != nil {
			t.Error(err)
		}
		b.h.reseals.Wait()
		b.h.With(func(k *kernel.Kernel) error { conf = k.Confirm(conf); return nil })
	}
	b.h.bk.wrap = func(t backup.Target) backup.Target { return eraseBeforePut{t, &fire} }
	taken := b.backup()
	b.h.bk.wrap = nil
	if fire != nil || len(taken) != 1 || taken[0].Backup == nil {
		t.Fatalf("taken: %+v", taken)
	}
	id := taken[0].Backup.BackupID
	if len(conf.Resealed) != 0 || len(conf.StillHeld) != 1 || conf.StillHeld[0].Backup != id || !strings.Contains(conf.StillHeld[0].Why, "on its way") {
		t.Fatalf("the erase's confirmation while the table was on its way: %+v", conf)
	}
	gens, _ := (backup.DirTarget{Dir: dir}).Tables(id)
	if len(gens) != 1 || gens[0] < 2 {
		t.Fatalf("tables at the target: %v", gens)
	}
	_, keys := openBackup(t, dir, id, testRK)
	if _, ok, _ := keys.Get(gone); ok {
		t.Fatal("the table that landed still gives the erased subject's key")
	}
	if _, ok, _ := keys.Get(live); !ok {
		t.Fatal("the re-sealed table lost a live subject's key")
	}
	b.restart()
	if v, _ := b.h.Backups(); len(v.Backups) != 1 || v.Backups[0].Generation != gens[0] {
		t.Fatalf("kept after a restart: %+v", v.Backups)
	}
}

// LOG-4 (#3378 Security finding 1, its probe P1): the process's Erase
// while a backup's first key table is on its way waits for the write and
// names the backup, Resealed only once no table at the target gives the
// erased key, and leaves no re-seal or write behind.
func TestTheProcessEraseWhileATableIsOnItsWay(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, live := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	var cs <-chan kernel.Confirmation
	var fire func()
	fire = func() { cs, _ = erasing(t, b, gone) }
	b.h.bk.wrap = func(t backup.Target) backup.Target { return eraseBeforePut{t, &fire} }
	taken := b.backup()
	b.h.bk.wrap = nil
	id := taken[0].Backup.BackupID
	if c := reply(t, cs); !slices.Equal(c.Resealed, []string{id}) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase's reply: %+v", c)
	}
	if gives(t, dir, id, gone) || !gives(t, dir, id, live) {
		t.Fatal("the table at the target is wrong")
	}
	b.h.reseals.Wait()
	b.h.With(func(*kernel.Kernel) error {
		if len(b.h.running) != 0 || b.h.bk.writing != nil {
			t.Errorf("left behind: running %v, writing %+v", b.h.running, b.h.bk.writing)
		}
		return nil
	})
}

// failRewrap runs an erase just before the first key table goes out and
// fails every later generation's put while fail is set.
type failRewrap struct {
	backup.Target
	fire *func()
	fail *bool
}

func (f failRewrap) PutTable(id string, gen uint64, b []byte) error {
	if fn := *f.fire; fn != nil {
		*f.fire = nil
		fn()
	}
	if gen >= 2 && *f.fail {
		return errors.New("the drive is busy")
	}
	return f.Target.PutTable(id, gen, b)
}

// LOG-4 (#3311 L3 on 6e14b28): when the re-seal after an in-flight put
// fails, the kernel process's Tick retries it with its backoff until no
// table at the target gives the erased key.
func TestTickRetriesAFailedReseal(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, live := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	var fire func()
	// The kernel's erase: the process's waits for the write (#3338).
	fire = func() {
		b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err })
	}
	fail := true
	b.h.bk.wrap = func(tg backup.Target) backup.Target { return failRewrap{tg, &fire, &fail} }
	id := b.backup()[0].Backup.BackupID
	if gens, _ := (backup.DirTarget{Dir: dir}).Tables(id); !slices.Equal(gens, []uint64{1}) {
		t.Fatalf("tables before the retry: %v", gens)
	}
	fail = false
	for range 12 {
		b.now += 3600
		b.tick()
	}
	gens, _ := (backup.DirTarget{Dir: dir}).Tables(id)
	if len(gens) != 1 || gens[0] < 2 {
		t.Fatalf("tables after the process's ticks: %v", gens)
	}
	_, keys := openBackup(t, dir, id, testRK)
	if _, ok, _ := keys.Get(gone); ok {
		t.Fatal("the retried table still gives the erased subject's key")
	}
	if _, ok, _ := keys.Get(live); !ok {
		t.Fatal("the retried table lost a live subject's key")
	}
}

func (b *bbox) tick() {
	b.t.Helper()
	if err := b.h.Tick(b.now); err != nil {
		b.t.Fatal(err)
	}
	b.h.reseals.Wait()
}

// REQ: CH-9, BAK-1
// MIG-4-recovery-f1: every backup carries the page authority the kernel
// holds, so a restore brings back the fingerprint the Owner Card prints,
// and its kept Record names that fingerprint, also after a restart. A
// kernel with no authority writes none and names none.
func TestBackupCarriesThePageCA(t *testing.T) {
	ca, a := testPageCA(t)
	b := newBBox(t, recipientWire(t, testRK))
	b.cfg.PageCA = ca
	b.restart()
	b.subject()
	dir := b.addTarget("drive", false)
	taken := b.backup()
	if len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Verified {
		t.Fatalf("backup: %+v", taken)
	}
	id := taken[0].Backup.BackupID
	f := mustOpen(t, filepath.Join(dir, id+".content"))
	defer f.Close()
	m, _, err := backup.Open(f, testRK)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pageca.Unmarshal(m.PageCA)
	if err != nil || !bytes.Equal(got.Certificate(), a.Certificate()) || got.Fingerprint() != a.Fingerprint() {
		t.Fatalf("the backup's page authority is not the kernel's: %v", err)
	}
	if !bytes.Equal(m.PageCA, ca) {
		t.Fatal("the backup's page authority is not in its sealed form")
	}
	b.restart()
	if i := b.h.bk.find(id); i < 0 || b.h.bk.kept[i].Record.PageCA != a.Fingerprint() {
		t.Fatalf("the kept record does not name the authority's fingerprint: %+v", b.h.bk.kept)
	}

	n := newBBox(t, recipientWire(t, testRK))
	n.subject()
	ndir := n.addTarget("drive", false)
	nt := n.backup()
	if len(nt) != 1 || nt[0].Backup == nil {
		t.Fatalf("backup without an authority: %+v", nt)
	}
	nf := mustOpen(t, filepath.Join(ndir, nt[0].Backup.BackupID+".content"))
	defer nf.Close()
	if nm, _, err := backup.Open(nf, testRK); err != nil || nm.PageCA != nil || n.h.bk.kept[0].Record.PageCA != "" {
		t.Fatalf("a kernel with no authority wrote one: %v", err)
	}
}

// REQ: BAK-1, HW-15
// EDGE-link-core-b: a kernel holding the core's link key writes no part of
// it into a backup: neither the manifest, the log section nor a key table
// holds an 8-byte run of its seed or its private key (BAK-1 "never the
// kernel's keys"; a restore enrolls again and makes a new one).
// Mutant: writeOne's `PageCA: ca` as `PageCA: h.link.Seed()` (the manifest
// then holds the seed).
func TestBackupHoldsNoLinkKey(t *testing.T) {
	_, link := gen(9)
	b := newBBox(t, recipientWire(t, testRK))
	b.cfg.LinkKey = link
	b.restart()
	b.subject()
	dir := b.addTarget("drive", false)
	taken := b.backup()
	if len(taken) != 1 || taken[0].Backup == nil || !taken[0].Backup.Verified {
		t.Fatalf("backup: %+v", taken)
	}
	id := taken[0].Backup.BackupID
	f := mustOpen(t, filepath.Join(dir, id+".content"))
	defer f.Close()
	m, secs, err := backup.Open(f, testRK)
	if err != nil {
		t.Fatal(err)
	}
	var plain [][]byte
	plain = append(plain, []byte(fmt.Sprintf("%+v", m)), m.PageCA)
	for {
		_, r, err := secs.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sec, err := io.ReadAll(r)
		if err != nil {
			t.Fatal(err)
		}
		plain = append(plain, sec)
	}
	tables, err := filepath.Glob(filepath.Join(dir, id+".table.*"))
	if err != nil || len(tables) == 0 {
		t.Fatalf("tables: %v %v", tables, err)
	}
	for _, p := range append(tables, filepath.Join(dir, id+".content")) {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		plain = append(plain, raw)
	}
	_, keys := openBackup(t, dir, id, testRK)
	for _, k := range keys.M {
		plain = append(plain, k[:])
	}
	for _, raw := range plain {
		for i := 0; i+8 <= len(link); i++ {
			if bytes.Contains(raw, link[i:i+8]) {
				t.Fatalf("the backup holds the link key's bytes %d to %d", i, i+8)
			}
		}
	}
}

// #3316 (LOG-4, BAK-1): the log names every backup (backup.taken) before
// its key table leaves, so a rolled-back or deleted records file hides
// none from an erase.

// newestTable is what backup id's newest key table at dir gives, opened
// with rk; ok is false when it does not open with rk.
func newestTable(t *testing.T, dir, id string, rk []byte) (*kernel.MemKeys, bool) {
	t.Helper()
	gens, err := backup.DirTarget{Dir: dir}.Tables(id)
	if err != nil || len(gens) == 0 {
		t.Fatalf("tables of %s: %v %v", id, gens, err)
	}
	tb, err := os.ReadFile(filepath.Join(dir, id+".table."+itoa(gens[len(gens)-1])))
	if err != nil {
		t.Fatal(err)
	}
	keys := kernel.NewMemKeys()
	_, err = backup.UnwrapTable(bytes.NewReader(tb), rk, id, keys)
	return keys, err == nil
}

func (b *bbox) records() string { return filepath.Join(b.cfg.BackupDir, recordsName) }

func (b *bbox) taken() []kernel.BackupTaken {
	var out []kernel.BackupTaken
	b.h.With(func(k *kernel.Kernel) error { out = k.State().BackupsTaken(); return nil })
	return out
}

func (b *bbox) kept(id string) *Kept {
	for i := range b.h.bk.kept {
		if b.h.bk.kept[i].Record.BackupID == id {
			return &b.h.bk.kept[i]
		}
	}
	return nil
}

// rolledBack takes B1, opens gone, takes B2, which gives gone, and then
// hides B2 from the records file with lose (a rollback or a delete) and
// restarts. B2 is the target's only backup that gives gone.
func rolledBack(t *testing.T, b *bbox, lose func(old []byte)) (dir, b2, gone string) {
	t.Helper()
	dir = b.addTarget("drive", false)
	b.backup()
	old, err := os.ReadFile(b.records())
	if err != nil {
		t.Fatal(err)
	}
	gone = b.subject()
	b.now += BackupEvery
	b2 = b.backup()[0].Backup.BackupID
	if keys, _ := newestTable(t, dir, b2, testRK); keys.M[gone] == (kernel.SubjectKey{}) {
		t.Fatal("B2 does not give the subject to begin with")
	}
	b.h.Close()
	lose(old)
	b.open()
	return dir, b2, gone
}

func rollRecords(t *testing.T, b *bbox) func([]byte) {
	return func(old []byte) {
		if err := os.WriteFile(b.records(), old, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func deleteRecords(t *testing.T, b *bbox) func([]byte) {
	return func([]byte) {
		if err := os.Remove(b.records()); err != nil {
			t.Fatal(err)
		}
	}
}

// eraseReseals erases gone and checks b2 was re-sealed and its table at dir
// gives gone no more.
func eraseReseals(t *testing.T, b *bbox, dir, b2, gone string) {
	t.Helper()
	c, err := b.h.Erase(b.now, gone)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(c.Resealed, b2) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase's confirmation: %+v, want %s resealed", c, b2)
	}
	keys, ok := newestTable(t, dir, b2, testRK)
	if !ok {
		t.Fatal("the re-sealed table does not open with the recovery key")
	}
	if _, has, _ := keys.Get(gone); has {
		t.Fatal("the re-sealed table still gives the erased subject's key")
	}
}

// LOG-4, the issue's failure path: B2 survives a records file put back to
// before it, and an erase re-seals it.
func TestRolledBackRecordsStillReachEveryBackup(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	dir, b2, gone := rolledBack(t, b, rollRecords(t, b))
	kp := b.kept(b2)
	if kp == nil || !kp.Rebuilt || !kp.Pending || kp.Verified || !slices.Contains(kp.Record.Subjects, gone) {
		t.Fatalf("B2 after the rollback: %+v", kp)
	}
	if v, _ := b.h.Backups(); !slices.ContainsFunc(v.Backups, func(bv BackupView) bool { return bv.BackupID == b2 && bv.Rebuilt }) {
		t.Fatal("the backups answer does not show B2 rebuilt")
	}
	eraseReseals(t, b, dir, b2, gone)
}

// LOG-4: the same with the records file deleted.
func TestDeletedRecordsRebuildFromTheLog(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	dir, b2, gone := rolledBack(t, b, deleteRecords(t, b))
	if len(b.h.bk.kept) != 2 || len(b.h.bk.set.List()) != 2 {
		t.Fatalf("rebuilt %d backups, set %v; want both", len(b.h.bk.kept), b.h.bk.set.List())
	}
	if _, err := os.Stat(b.records()); err != nil {
		t.Fatalf("the rebuilt records are not saved: %v", err)
	}
	eraseReseals(t, b, dir, b2, gone)
}

// LOG-4: a rebuilt backup whose target is unreachable is named held. If
// the records are rolled back again after the erase, the next rebuild still
// lists the erased subject, so once the target is back Tick re-seals it.
func TestRebuiltBackupOffTargetIsNamedHeld(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	var old []byte
	dir, b2, gone := rolledBack(t, b, func(o []byte) { old = o; rollRecords(t, b)(o) })
	away := dir + ".away"
	if err := os.Rename(dir, away); err != nil {
		t.Fatal(err)
	}
	c, err := b.h.Erase(b.now, gone)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(c.StillHeld, func(h kernel.BackupHold) bool { return h.Backup == b2 && h.Why != "" }) || slices.Contains(c.Resealed, b2) {
		t.Fatalf("the erase's confirmation: %+v, want %s held", c, b2)
	}
	b.h.Close()
	rollRecords(t, b)(old)
	b.open()
	if kp := b.kept(b2); kp == nil || !slices.Contains(kp.Record.Subjects, gone) {
		t.Fatalf("rebuilt after the erase without the erased subject: %+v", kp)
	}
	if err := os.Rename(away, dir); err != nil {
		t.Fatal(err)
	}
	b.tick()
	if keys, ok := newestTable(t, dir, b2, testRK); !ok || keys.M[gone] != (kernel.SubjectKey{}) {
		t.Fatal("Tick did not re-seal the rebuilt backup")
	}
}

// failingAnchor is the test anchor, down while *down is set.
type failingAnchor struct {
	*kernel.MemAnchor
	down *bool
}

func (a failingAnchor) Put(h kernel.Head) error {
	if *a.down {
		return errors.New("anchor down")
	}
	return a.MemAnchor.Put(h)
}

// LOG-4: no key table leaves without its backup.taken logged and anchored:
// a failing log write, or a failing anchor, saves no record and sends no
// table, and the Taken carries the error.
func TestNoTableLeavesWithoutItsEntry(t *testing.T) {
	for _, name := range []string{"log write fails", "anchor fails"} {
		t.Run(name, func(t *testing.T) {
			b := newBBox(t, recipientWire(t, testRK))
			down := false
			b.cfg.Anchor = failingAnchor{anchor(t, b.cfg.Log), &down}
			b.restart()
			b.subject()
			dir := b.addTarget("drive", false)
			var dirs []string
			if name == "log write fails" {
				// A widening whose anchor fails breaks the log: every
				// later write fails until a restart.
				down = true
				spare := t.TempDir()
				if err := b.add(kernel.BackupTarget{Name: "spare", Kind: kernel.KindDir, Locator: spare}); err == nil {
					t.Fatal("an unanchored target must report the anchor")
				}
				down = false
				dirs = append(dirs, spare)
			} else {
				down = true
			}
			n := len(b.logBytes())
			taken := b.backup()
			down = false
			for _, tk := range taken {
				if tk.Backup != nil || !strings.Contains(tk.Error, "not in my log") {
					t.Fatalf("taken: %+v", taken)
				}
			}
			for _, d := range append(dirs, dir) {
				if ids := tablesAt(t, d); len(ids) != 0 {
					t.Fatalf("a table went out with no anchored entry: %v", ids)
				}
			}
			if len(b.h.bk.kept) != 0 || len(b.h.bk.set.List()) != 0 {
				t.Fatalf("kept: %+v", b.h.bk.kept)
			}
			if name == "log write fails" && len(b.logBytes()) != n {
				t.Fatal("a broken log took an entry")
			}
		})
	}
}

// LOG-4: an entry logged whose record save failed is rebuilt at the next
// start, and nothing is rebuilt or logged twice on the one after.
func TestCrashBetweenEntryAndRecord(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone := b.subject()
	dir := b.addTarget("drive", false)
	b.h.bk.saveErr = func() error { return errors.New("no space left on device") }
	taken := b.backup()
	if len(taken) != 1 || taken[0].Backup != nil || len(tablesAt(t, dir)) != 0 {
		t.Fatalf("taken: %+v, tables %v", taken, tablesAt(t, dir))
	}
	logged := b.taken()
	if len(logged) != 1 {
		t.Fatalf("logged %d backups, want 1", len(logged))
	}
	b.h.bk.saveErr = nil
	b.restart()
	kp := b.kept(logged[0].BackupID)
	if len(b.h.bk.kept) != 1 || kp == nil || !kp.Rebuilt || !slices.Equal(kp.Record.Subjects, []string{gone}) {
		t.Fatalf("after a restart: %+v", b.h.bk.kept)
	}
	n := len(b.logBytes())
	b.restart()
	if len(b.h.bk.kept) != 1 || len(b.taken()) != 1 || len(b.logBytes()) != n {
		t.Fatalf("a second restart rebuilt or logged again: %d kept, %d logged", len(b.h.bk.kept), len(b.taken()))
	}
	// An erase over it acts as over a pending backup: nothing was at the
	// target, and what the re-seal puts there gives no erased key.
	c, err := b.h.Erase(b.now, gone)
	if err != nil || !slices.Contains(c.Resealed, kp.Record.BackupID) {
		t.Fatalf("the erase's confirmation: %+v %v", c, err)
	}
	if keys, ok := newestTable(t, dir, kp.Record.BackupID, testRK); !ok || keys.M[gone] != (kernel.SubjectKey{}) || len(keys.M) != 0 {
		t.Fatal("the re-sealed table gives the erased subject's key")
	}
}

// LOG-4: a kept record whose entry the log lost (rolled back past it) is
// logged once at start, with its Upto; a record from before this build,
// with no Upto, is logged at the head.
func TestRecordAheadOfLogIsLoggedAtStart(t *testing.T) {
	for _, preBuild := range []bool{false, true} {
		t.Run(fmt.Sprint("pre-build ", preBuild), func(t *testing.T) {
			b := newBBox(t, recipientWire(t, testRK))
			b.subject()
			b.addTarget("drive", false)
			oldLog, a := b.logBytes(), anchor(t, b.cfg.Log)
			oldAnchor := *a
			id := b.backup()[0].Backup.BackupID
			upto := b.kept(id).Upto
			if upto == 0 || upto != b.taken()[0].Upto {
				t.Fatalf("kept upto %d, logged %+v", upto, b.taken())
			}
			if preBuild {
				b.h.With(func(*kernel.Kernel) error { b.h.bk.kept[0].Upto = 0; return b.h.bk.save() })
			}
			b.h.Close()
			if err := os.WriteFile(b.cfg.Log, oldLog, 0o600); err != nil {
				t.Fatal(err)
			}
			*a = oldAnchor
			b.open()
			got := b.taken()
			if len(got) != 1 || got[0].BackupID != id {
				t.Fatalf("logged at start: %+v", got)
			}
			if !preBuild && got[0].Upto != upto {
				t.Fatalf("logged upto %d, want %d", got[0].Upto, upto)
			}
			if preBuild && (got[0].Upto < upto || b.kept(id).Upto != got[0].Upto) {
				t.Fatalf("a pre-build record logged at %d, kept %d; want the head, at least %d", got[0].Upto, b.kept(id).Upto, upto)
			}
			if b.kept(id).Rebuilt {
				t.Fatal("a kept record is marked rebuilt")
			}
			n := len(b.logBytes())
			b.restart()
			if len(b.taken()) != 1 || len(b.logBytes()) != n {
				t.Fatal("a second start logged it again")
			}
		})
	}
}

// BAK-1: after a recovery-key rotation, a rebuilt backup re-seals to its
// own recipient, the one its content opens with, not the new one.
func TestRebuiltBackupKeepsItsRecipient(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, live := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	rk2 := bytes.Repeat([]byte{0x6b}, 32)
	b.cfg.Recipient = recipientWire(t, rk2)
	b.restart()
	b.h.Close()
	if err := os.Remove(b.records()); err != nil {
		t.Fatal(err)
	}
	b.open()
	if kp := b.kept(id); kp == nil || !kp.Rebuilt {
		t.Fatalf("not rebuilt: %+v", b.h.bk.kept)
	}
	if _, err := b.h.Erase(b.now, gone); err != nil {
		t.Fatal(err)
	}
	if _, ok := newestTable(t, dir, id, rk2); ok {
		t.Fatal("the re-sealed table opens with the new recovery key")
	}
	keys, ok := newestTable(t, dir, id, testRK)
	if !ok {
		t.Fatal("the re-sealed table does not open with the backup's own recovery key")
	}
	if _, has, _ := keys.Get(gone); has {
		t.Fatal("the re-sealed table gives the erased subject")
	}
	if _, has, _ := keys.Get(live); !has {
		t.Fatal("the re-sealed table lost a live subject")
	}
}

// LOG-4: a rebuilt backup's subjects stop at its snapshot: a subject opened
// after it is never put in its re-sealed table, so a rebuild hands no newer
// key to an old recipient.
func TestRebuiltSubjectsStopAtUpto(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	kept, gone := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	id := b.backup()[0].Backup.BackupID
	later := b.subject()
	b.h.Close()
	if err := os.Remove(b.records()); err != nil {
		t.Fatal(err)
	}
	b.open()
	if kp := b.kept(id); kp == nil || !slices.Equal(kp.Record.Subjects, slices.Sorted(slices.Values([]string{kept, gone}))) {
		t.Fatalf("rebuilt subjects: %+v", kp)
	}
	if _, err := b.h.Erase(b.now, gone); err != nil {
		t.Fatal(err)
	}
	keys, ok := newestTable(t, dir, id, testRK)
	if !ok {
		t.Fatal("the re-sealed table does not open")
	}
	if _, has, _ := keys.Get(later); has {
		t.Fatal("the re-sealed table gives a subject opened after the backup")
	}
	if _, has, _ := keys.Get(gone); has {
		t.Fatal("the re-sealed table gives the erased subject")
	}
	if _, has, _ := keys.Get(kept); !has {
		t.Fatal("the re-sealed table lost a subject the backup held")
	}
}

// LOG-4 (#3367 L3 and Security blocker 1): the key files sit beside the
// records, so deleting them with a rollback must not shrink a rebuilt
// backup's subjects. The rebuild lists every subject opened by B2's
// snapshot, and an erase whose re-seal then lacks a live key names B2 held
// instead of skipping it.
func TestRebuildIgnoresDeletedKeyFiles(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	other := b.subject()
	_, b2, gone := rolledBack(t, b, func(old []byte) {
		rollRecords(t, b)(old)
		es, err := os.ReadDir(b.cfg.KeyDir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			if err := os.Remove(filepath.Join(b.cfg.KeyDir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	})
	if kp := b.kept(b2); kp == nil || !kp.Rebuilt || !slices.Equal(kp.Record.Subjects, slices.Sorted(slices.Values([]string{other, gone}))) {
		t.Fatalf("B2 rebuilt without its subjects: %+v", kp)
	}
	c, err := b.h.Erase(b.now, gone)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(c.StillHeld, func(h kernel.BackupHold) bool { return h.Backup == b2 && h.Why != "" }) || slices.Contains(c.Resealed, b2) {
		t.Fatalf("the erase's confirmation: %+v, want %s held", c, b2)
	}
}

// REQ: LOG-4
// #3338 (Security finding 1 on #3332; adopts the probe
// TestSecProbeEraseBeforeTheFirstPutNamesNothing): an erase that lands
// while a backup is being written, after its snapshot took the subject
// and before the backup is in the Set, waits for the write and names that
// backup, which it then re-seals. The erase runs on its own goroutine,
// since it waits for the write the hook is part of. Mutant: skip the wait
// for the write, so the reply names no backup.
func TestAnEraseDuringABackupWriteNamesIt(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone, live := b.subject(), b.subject()
	dir := b.addTarget("drive", false)
	var cs <-chan kernel.Confirmation
	b.h.bk.hook = func() {
		if cs == nil {
			cs, _ = erasing(t, b, gone)
		}
	}
	id := b.backup()[0].Backup.BackupID
	c := reply(t, cs)
	if !slices.Equal(c.Resealed, []string{id}) || len(c.StillHeld) != 0 {
		t.Fatalf("the erase during the write: %+v", c)
	}
	if gives(t, dir, id, gone) || !gives(t, dir, id, live) {
		t.Fatal("the new backup's table at the target still gives the erased key")
	}
}

// REQ: LOG-4
// #3338: a write that fails before its first table goes out added no
// backup, so an erase waiting on it names none and returns, and nothing at
// the target gives the key.
func TestAnEraseOverAFailedWriteNamesNothing(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	gone := b.subject()
	dir := b.addTarget("drive", false)
	b.h.bk.saveErr = func() error { return errors.New("synthetic: the records file is not saved") }
	var cs <-chan kernel.Confirmation
	b.h.bk.hook = func() {
		if cs == nil {
			cs, _ = erasing(t, b, gone)
		}
	}
	if tk := b.backup(); tk[0].Error == "" || tk[0].Backup != nil {
		t.Fatalf("the write did not fail before its first put: %+v", tk)
	}
	if c := reply(t, cs); len(c.Resealed) != 0 || len(c.StillHeld) != 0 {
		t.Fatalf("the erase over a failed write: %+v", c)
	}
	if ents, _ := filepath.Glob(filepath.Join(dir, "*.table.*")); len(ents) != 0 {
		t.Fatalf("a key table went out: %v", ents)
	}
}

// rotate asks b's kernel for an approval of next, signed by an anchor over
// the recipient the kernel holds now.
func (b *bbox) rotate(next string) []byte {
	b.t.Helper()
	v, err := b.h.Backups()
	if err != nil {
		b.t.Fatal(err)
	}
	c := key.Approve(key.Ed25519Signer(sparePriv), kernel.RecoveryRotateHash(v.Recipient, next))
	a, err := b.h.RecoveryRotate(b.now, next, c)
	if err != nil {
		b.t.Fatal(err)
	}
	return a
}

func recipientID(t *testing.T, rk []byte) string {
	t.Helper()
	r, err := backup.RecipientFor(rk)
	if err != nil {
		t.Fatal(err)
	}
	return r.ID()
}

// REQ: REC-4
// MIG-4-recovery-r1 (#3391): the kernel's approval binds the recipient it
// holds, the new one, the route and an expiry, under the store's head key.
// One for another old, next or route, past its expiry, or under another
// store's head key fails VerifyApproval or its caller's check; a restart
// keeps it verifying. Catches a replayed or cross-box approval.
func TestApprovalBindsOldNextRouteAndExpiry(t *testing.T) {
	if handoff.RouteCard != kernel.RouteCard || handoff.RouteLost != kernel.RouteLost {
		t.Fatal("the approval's routes are not the kernel's")
	}
	b := newBBox(t, recipientWire(t, testRK))
	old, next := recipientID(t, testRK), recipientID(t, bytes.Repeat([]byte{0x6b}, 32))
	card := b.rotate(next)
	a, err := handoff.VerifyApproval(headPub, card, b.now)
	if err != nil || a != (handoff.Approval{Route: handoff.RouteCard, Old: old, Next: next, Expires: b.now + handoff.CardApprovalFor}) {
		t.Fatalf("card approval %+v, %v", a, err)
	}
	if _, err := handoff.VerifyApproval(headPub, card, b.now+handoff.CardApprovalFor); !errors.Is(err, handoff.ErrApprovalExpired) {
		t.Fatalf("past its quarter hour: %v", err)
	}
	other, _ := gen(9)
	if _, err := handoff.VerifyApproval(other, card, b.now); !errors.Is(err, handoff.ErrApproval) {
		t.Fatalf("under another store's head key: %v", err)
	}
	lost := b.rotate("")
	a, err = handoff.VerifyApproval(headPub, lost, b.now+handoff.CardApprovalFor)
	if err != nil || a != (handoff.Approval{Route: handoff.RouteLost, Old: old, Expires: b.now + handoff.LostApprovalFor}) {
		t.Fatalf("lost-card approval %+v, %v", a, err)
	}
	if _, err := handoff.VerifyApproval(headPub, lost, b.now+handoff.LostApprovalFor); !errors.Is(err, handoff.ErrApprovalExpired) {
		t.Fatalf("past its week: %v", err)
	}
	// A phone passkey, or a signature over another old, approves nothing.
	phonePub, phonePriv := gen(8)
	if err := b.h.With(func(k *kernel.Kernel) error {
		return k.Enroll(b.now, key.Enroll(key.Ed25519Signer(ownerPriv), key.Ed25519(phonePub)))
	}); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]key.Cosign{
		"phone":     key.Approve(key.Ed25519Signer(phonePriv), kernel.RecoveryRotateHash(old, next)),
		"other old": key.Approve(key.Ed25519Signer(ownerPriv), kernel.RecoveryRotateHash("", next)),
	} {
		if got, err := b.h.RecoveryRotate(b.now, next, c); !errors.Is(err, kernel.ErrRotateSig) || got != nil {
			t.Fatalf("%s: %x, %v", name, got, err)
		}
	}
	// The approval is the store's head key's, so a restart keeps it.
	b.restart()
	if _, err := handoff.VerifyApproval(headPub, card, b.now); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
	// A lost-card approval never switches the recipient: it has no next.
	if err := b.h.SwitchRecipient(b.now, recipientWire(t, bytes.Repeat([]byte{0x6b}, 32)), lost); !errors.Is(err, ErrNotApproved) {
		t.Fatalf("a lost-card approval switched: %v", err)
	}
	if err := b.h.SwitchRecipient(b.now+handoff.CardApprovalFor, recipientWire(t, bytes.Repeat([]byte{0x6b}, 32)), card); !errors.Is(err, handoff.ErrApprovalExpired) {
		t.Fatalf("an expired approval switched: %v", err)
	}
}

// REQ: BAK-1, REC-4
// MIG-4-recovery-r1 (#3391): a matching approval switches the recipient at
// once, so no kept backup counts and the next backup is new, at the new
// recipient, opening with the new key; a retry changes nothing. A stale
// old, a recipient whose ID is not next, a forged or lost-card approval
// refuses and keeps the old recipient. Over the owner socket too. Catches a
// rooted owner side redirecting backups.
func TestRecipientSwitchesAtOnceOnlyWhenApproved(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	dir := b.addTarget("drive", false)
	first := b.backup()[0].Backup
	rk2, rk3 := bytes.Repeat([]byte{0x6b}, 32), bytes.Repeat([]byte{0x7c}, 32)
	old, next := recipientID(t, testRK), recipientID(t, rk2)
	card := b.rotate(next)
	o := serveOwner(t, b.h, func() int64 { return b.now })
	keeps := func(name string, err, want error) {
		t.Helper()
		if !errors.Is(err, want) {
			t.Fatalf("%s: %v, want %v", name, err, want)
		}
		if v, _ := b.h.Backups(); v.Recipient != old {
			t.Fatalf("%s: the recipient moved to %s", name, v.Recipient)
		}
	}
	keeps("another recipient", o.SwitchRecipient(recipientWire(t, rk3), card), ErrNotApproved)
	keeps("not a recipient", o.SwitchRecipient([]byte("short"), card), ErrArgs)
	forged := bytes.Clone(card)
	forged[len(forged)-1] ^= 1
	keeps("forged", o.SwitchRecipient(recipientWire(t, rk2), forged), handoff.ErrApproval)
	keeps("lost-card", o.SwitchRecipient(recipientWire(t, rk2), b.rotate("")), ErrNotApproved)
	keeps("oversized", o.SwitchRecipient(recipientWire(t, rk2), bytes.Repeat([]byte{1}, handoff.MaxApproval+1)), ErrArgs)
	stale, err := handoff.SignApproval(headPriv, handoff.Approval{Route: handoff.RouteCard, Old: recipientID(t, rk3), Next: next, Expires: b.now + 1000})
	if err != nil {
		t.Fatal(err)
	}
	keeps("stale old", o.SwitchRecipient(recipientWire(t, rk2), stale), ErrApprovalStale)

	if err := o.SwitchRecipient(recipientWire(t, rk2), card); err != nil {
		t.Fatal(err)
	}
	v, err := o.Backups()
	if err != nil || v.Recipient != next {
		t.Fatalf("after the switch: %+v %v", v, err)
	}
	for _, kp := range v.Backups {
		if kp.Recipient == v.Recipient {
			t.Fatalf("a kept backup counts at the new recipient: %+v", kp)
		}
	}
	// A retry once switched succeeds and changes nothing.
	if err := o.SwitchRecipient(recipientWire(t, rk2), card); err != nil {
		t.Fatalf("a retry: %v", err)
	}
	// The approval is spent: a third recipient's needs a new one.
	c3, err := handoff.SignApproval(headPriv, handoff.Approval{Route: handoff.RouteCard, Old: old, Next: recipientID(t, rk3), Expires: b.now + 1000})
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SwitchRecipient(recipientWire(t, rk3), c3); !errors.Is(err, ErrApprovalStale) {
		t.Fatalf("an approval from before the switch: %v", err)
	}
	b.now += 1000 // well within BackupEvery
	taken := b.backup()
	if taken[0].Reused || taken[0].Backup.BackupID == first.BackupID || taken[0].Backup.Recipient != next {
		t.Fatalf("the backup after the switch: %+v", taken[0])
	}
	openBackup(t, dir, taken[0].Backup.BackupID, rk2)
	f := mustOpen(t, filepath.Join(dir, taken[0].Backup.BackupID+".content"))
	defer f.Close()
	if _, _, err := backup.Open(f, testRK); err == nil {
		t.Fatal("the old key opens the backup taken after the switch")
	}
}

// REQ: BAK-1
// A switch waits for a backup call being written, so that backup is
// sealed to one recipient throughout and kept at the old one; the switch
// lands once it is over.
func TestASwitchWaitsForABackupBeingWritten(t *testing.T) {
	b := newBBox(t, recipientWire(t, testRK))
	b.subject()
	b.addTarget("drive", false)
	rk2 := bytes.Repeat([]byte{0x6b}, 32)
	card := b.rotate(recipientID(t, rk2))
	// started is buffered so the hook's send never depends on the test already waiting.
	started, release := make(chan struct{}, 1), make(chan struct{})
	b.h.bk.hook = func() {
		select {
		case started <- struct{}{}:
			<-release
		default:
		}
	}
	taken := make(chan []Taken, 1)
	go func() { out, _ := b.h.Backup(b.now); taken <- out }()
	<-started
	switched := make(chan error, 1)
	go func() { switched <- b.h.SwitchRecipient(b.now, recipientWire(t, rk2), card) }()
	select {
	case err := <-switched:
		t.Fatalf("the switch landed during a backup write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	out := <-taken
	if err := <-switched; err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Backup == nil || out[0].Backup.Recipient != recipientID(t, testRK) {
		t.Fatalf("the backup written across the switch: %+v", out)
	}
	if v, _ := b.h.Backups(); v.Recipient != recipientID(t, rk2) {
		t.Fatalf("after the backup: %s", v.Recipient)
	}
}
