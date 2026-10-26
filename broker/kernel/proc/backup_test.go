package proc

// REQ: BAK-1, LOG-4

import (
	"bytes"
	"errors"
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
// its newest key table gives.
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
	if _, _, err := secs.Next(); err != io.EOF {
		t.Fatalf("a section after the log: %v", err)
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
	var c kernel.Confirmation
	if err := b.h.With(func(k *kernel.Kernel) (err error) { c, err = k.Erase(b.now, gone); return err }); err != nil {
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
	var c kernel.Confirmation
	b.h.With(func(k *kernel.Kernel) (err error) { c, err = k.Erase(b.now, sub); return err })
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
	if err := b.h.With(func(k *kernel.Kernel) error { _, err := k.Erase(b.now, gone); return err }); err != nil {
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
			var conf kernel.Confirmation
			if err := b.h.With(func(k *kernel.Kernel) (err error) { conf, err = k.Erase(b.now, gone); return err }); err != nil {
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
		if v, _ := b.h.Backups(); len(v.Backups) != 1 || !v.Backups[0].Pending || len(b.h.bk.set.List()) != 1 {
			t.Fatalf("kept after a restart: %+v", v.Backups)
		}
	})
}
