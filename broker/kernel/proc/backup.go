package proc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// Backups on the running box (BAK-1, MIG-4-recovery-e3). The kernel process
// holds the destinations (kernel.BackupTarget, logged) and does the
// carrying: it takes a backupSnap under its lock, writes one backup to each
// current target outside it, reads each back and marks it verified itself,
// so a lying owner side cannot mark one. It keeps every backup's Record in
// one file in its backup directory, sealed under the log key, and at start
// builds the backup.Set an erase re-seals through (LOG-4, D-168, #3188),
// removed targets included. The log names every backup (backup.taken)
// before its key table leaves, so at start the Set is the union of the log
// and that file, and a rolled-back file hides none (#3316). The owner side
// only triggers, chooses and tells.

var (
	// ErrBackupsOff: the kernel was started with no backup directory (tests
	// only; RunKernel refuses that).
	ErrBackupsOff = errors.New("run: I keep no backups here")
	// ErrNoBackupDir: the kernel process never starts without one, since an
	// erase must reach every backup taken before.
	ErrNoBackupDir = errors.New("run: a kernel needs its backup directory")
	// ErrNoBackupTarget: there is no current destination to back up to.
	ErrNoBackupTarget = errors.New("run: there is no backup destination; add one first")
	// ErrTargetInKernel refuses a destination inside the kernel's own data.
	ErrTargetInKernel = errors.New("run: a backup destination cannot be inside my own data folder")
	// ErrTargetNotDir refuses a destination that is not a reachable directory.
	ErrTargetNotDir = errors.New("run: that backup destination is not a directory I can reach")
	// ErrRecordsFile: the backup records do not open under the log key, so
	// the drive was edited; the kernel starts nothing until the owner looks.
	ErrRecordsFile = errors.New("run: my backup records do not open under my store's key; I start nothing until you choose what to do")
)

// BackupEvery is the least time between two backups to one target at one
// recipient: within it a backup call returns the last verified one instead
// of writing, so a rooted owner side cannot fill a target. A changed
// recipient, or a last backup that was not verified, skips the wait.
const BackupEvery = 10 * 60 * 1000 // ms

const (
	recordsName = "records"
	maxRecords  = 16 << 20
	contentExt  = ".content"
)

func recordsAAD() []byte { return []byte("agentos.backup.records.v1") }

// Kept is a backup as the kernel keeps it: its Record, the target it went
// to, and whether the kernel read it back whole. Pending is a backup whose
// key table was about to go out when it was saved: the kernel saves it
// before the table leaves, so a table never reaches a target without a
// kept Record (LOG-4); its Record lacks only the content and table sums,
// which an erase does not use. One that never finished stays pending and
// unverified, and in the Set. Upto is the log head's sequence number in
// the backup's snapshot, as its backup.taken names it. Rebuilt is a
// pending backup the start rebuilt from its backup.taken because the
// records file lacked it: its Subjects are every subject opened at or
// below Upto, whatever the key table holds.
type Kept struct {
	Target   string        `json:"target"`
	Verified bool          `json:"verified"`
	Pending  bool          `json:"pending,omitempty"`
	Rebuilt  bool          `json:"rebuilt,omitempty"`
	Upto     uint64        `json:"upto,omitempty"`
	Record   backup.Record `json:"record"`
}

// BackupView is one kept backup as the owner side reads it: no key, and
// its recipient only by ID.
type BackupView struct {
	Target     string `json:"target"`
	BackupID   string `json:"backup_id"`
	Recipient  string `json:"recipient"` // backup.Recipient.ID
	Created    int64  `json:"created"`
	Generation uint64 `json:"generation"`
	Verified   bool   `json:"verified"`
	Pending    bool   `json:"pending,omitempty"`
	Rebuilt    bool   `json:"rebuilt,omitempty"`
}

// TargetView is a destination as the owner side reads it. Rewritable is
// false for an append-only target: an erase cannot drop a key table there
// (D-168).
type TargetView struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Locator    string `json:"locator"`
	AppendOnly bool   `json:"append_only"`
	Removed    bool   `json:"removed"`
	Rewritable bool   `json:"rewritable"`
}

// BackupsView is the backups call's answer: the current recipient's ID
// ("" when the store holds none), every target, and every kept backup.
type BackupsView struct {
	Recipient string       `json:"recipient"`
	Targets   []TargetView `json:"targets"`
	Backups   []BackupView `json:"backups"`
}

// Taken is one current target's outcome of a backup call: the backup now
// kept for it (Reused when it is the last one, within BackupEvery), or why
// none was written.
type Taken struct {
	Target string      `json:"target"`
	Backup *BackupView `json:"backup,omitempty"`
	Reused bool        `json:"reused,omitempty"`
	Error  string      `json:"error,omitempty"`
}

func (k Kept) view() BackupView {
	return BackupView{Target: k.Target, BackupID: k.Record.BackupID, Recipient: k.Record.Recipient.ID(),
		Created: k.Record.Created, Generation: k.Record.Generation, Verified: k.Verified, Pending: k.Pending, Rebuilt: k.Rebuilt}
}

// backups is the kernel process's backup state. Every field but run, and
// every call of set, is used under the Kernel's lock.
type backups struct {
	dir       string
	aead      cipher.AEAD
	recipient *backup.Recipient // nil: the store holds none (enrolled before e1)
	log       string
	keys      kernel.Keys
	guard     []string // the kernel's own data folders, resolved
	kept      []Kept
	set       *backup.Set
	run       sync.Mutex // one backup at a time
	// For tests only: hook runs as each section opens, wrap, when set,
	// wraps every target, and saveErr, when set, fails every save.
	hook    func()
	wrap    func(backup.Target) backup.Target
	saveErr func() error
}

// openBackups opens the records in dir under logKey, made 0700 if missing,
// and builds the Set from them, the logged backups and the logged targets.
// It runs before k is shared, so it takes no lock.
func openBackups(cfg KernelConfig, keys kernel.Keys, k *kernel.Kernel, now int64) (*backups, error) {
	st := k.State()
	if err := os.Mkdir(cfg.BackupDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	if err := privfile.Check(cfg.BackupDir, true); err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(cfg.Key[:])
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	bk := &backups{dir: cfg.BackupDir, aead: a, log: cfg.Log, keys: keys}
	if len(cfg.Recipient) > 0 {
		x, ek, err := handoff.SplitRecipient(cfg.Recipient)
		if err != nil {
			return nil, err
		}
		bk.recipient = &backup.Recipient{X: x, EK: ek}
	}
	for _, d := range []string{filepath.Dir(cfg.Log), cfg.KeyDir, cfg.BackupDir} {
		if d == "" {
			continue
		}
		r, err := filepath.EvalSymlinks(d)
		if err != nil {
			return nil, err
		}
		bk.guard = append(bk.guard, r)
	}
	if bk.kept, err = bk.load(); err != nil {
		return nil, err
	}
	targets := map[string]kernel.KeptTarget{}
	for _, t := range st.BackupTargets() {
		targets[t.Name] = t
	}
	for _, kp := range bk.kept {
		if _, ok := targets[kp.Target]; !ok {
			return nil, fmt.Errorf("%w: a record names target %q, which the log never added", ErrRecordsFile, kp.Target)
		}
	}
	if err := bk.union(k, now); err != nil {
		return nil, err
	}
	bk.set = backup.NewSet(bk.saveRecord)
	for _, kp := range bk.kept {
		if err := bk.set.Add(bk.target(targets[kp.Target].BackupTarget), kp.Record); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRecordsFile, err)
		}
	}
	return bk, nil
}

// taken is the backup.taken that names kp, its snapshot at upto.
func taken(target string, rec backup.Record, upto uint64) kernel.BackupTaken {
	return kernel.BackupTaken{BackupID: rec.BackupID, Target: target, Created: rec.Created, Upto: upto,
		Recipient: kernel.BackupRecipient{X: rec.Recipient.X, EK: rec.Recipient.EK}}
}

// union makes kept and the log name the same backups (brief decisions 3
// and 4). A kept record the log does not name (the log lost its entry, or
// the record predates backup.taken) is logged, at its Upto, or at the head
// when it has none, a superset of its subjects. A logged backup kept lacks
// (the records file was rolled back or deleted, or the start came between
// the entry and the save) is rebuilt as a pending backup. A record is never
// dropped, so the Set only grows.
func (bk *backups) union(k *kernel.Kernel, now int64) error {
	st := k.State()
	logged := map[string]bool{}
	for _, b := range st.BackupsTaken() {
		logged[b.BackupID] = true
	}
	dirty := false
	for i := range bk.kept {
		kp := &bk.kept[i]
		if logged[kp.Record.BackupID] {
			continue
		}
		if kp.Upto == 0 {
			kp.Upto, dirty = uint64(k.Log().Len()), true
		}
		// The entry is not a widening, so an anchor error leaves it logged.
		err := k.BackupTaken(now, taken(kp.Target, kp.Record, kp.Upto))
		if err != nil && !slices.ContainsFunc(st.BackupsTaken(), func(b kernel.BackupTaken) bool { return b.BackupID == kp.Record.BackupID }) {
			return fmt.Errorf("%w: backup %s is not in my log and I cannot log it: %w", ErrRecordsFile, kp.Record.BackupID, err)
		}
		logged[kp.Record.BackupID] = true
	}
	have := map[string]bool{}
	for _, kp := range bk.kept {
		have[kp.Record.BackupID] = true
	}
	for _, b := range st.BackupsTaken() {
		if have[b.BackupID] {
			continue
		}
		// Every subject opened by the snapshot, whatever the key table
		// holds now: the key files sit beside records and may be deleted
		// with it, and a live one whose key is missing makes the re-seal
		// fail, so an erase names the backup held instead of skipping it.
		subs := st.SubjectsUpto(b.Upto)
		bk.kept = append(bk.kept, Kept{Target: b.Target, Pending: true, Rebuilt: true, Upto: b.Upto, Record: backup.Record{
			BackupID: b.BackupID, Recipient: backup.Recipient{X: b.Recipient.X, EK: b.Recipient.EK},
			Created: b.Created, Subjects: subs}})
		have[b.BackupID], dirty = true, true
	}
	if dirty {
		// Unsaved, the next start rebuilds and logs the same again.
		_ = bk.save()
	}
	return nil
}

func (bk *backups) load() ([]Kept, error) {
	f, err := os.OpenFile(filepath.Join(bk.dir, recordsName), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := privfile.CheckFile(f); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRecords+1))
	if err != nil {
		return nil, err
	}
	ns := bk.aead.NonceSize()
	if len(b) > maxRecords || len(b) < ns {
		return nil, ErrRecordsFile
	}
	pt, err := bk.aead.Open(nil, b[:ns], b[ns:], recordsAAD())
	if err != nil {
		return nil, ErrRecordsFile
	}
	var kept []Kept
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&kept); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRecordsFile, err)
	}
	return kept, nil
}

// save seals and writes every kept record, atomically.
func (bk *backups) save() error {
	if bk.saveErr != nil {
		if err := bk.saveErr(); err != nil {
			return err
		}
	}
	pt, err := json.Marshal(bk.kept)
	if err != nil {
		return err
	}
	nonce := make([]byte, bk.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	b := bk.aead.Seal(nonce, nonce, pt, recordsAAD())
	if len(b) > maxRecords {
		return errors.New("run: the backup records are over 16 MiB")
	}
	return privfile.WriteAtomic(bk.dir, recordsName, b, nil)
}

// saveRecord is the Set's save: the Record a re-seal returned replaces the
// kept one of its backup. A re-seal never changes the content object, so
// the kept content sum stays (a pending Record has none yet).
func (bk *backups) saveRecord(rec backup.Record) error {
	for i := range bk.kept {
		if bk.kept[i].Record.BackupID == rec.BackupID {
			old := bk.kept[i].Record
			rec.ContentSum = old.ContentSum
			bk.kept[i].Record = rec
			if err := bk.save(); err != nil {
				bk.kept[i].Record = old
				return err
			}
			return nil
		}
	}
	return backup.ErrNoBackup
}

// checkDir resolves locator and refuses one that is not a directory or is
// inside, or is, one of the kernel's own data folders (#3251 review note 1).
func (bk *backups) checkDir(locator string) (string, error) {
	r, err := filepath.EvalSymlinks(locator)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTargetNotDir, err)
	}
	fi, err := os.Stat(r)
	if err != nil || !fi.IsDir() {
		return "", ErrTargetNotDir
	}
	for _, g := range bk.guard {
		if r == g || strings.HasPrefix(r, strings.TrimSuffix(g, "/")+"/") {
			return "", ErrTargetInKernel
		}
	}
	return r, nil
}

// dirTarget is a kind dir destination: a backup.DirTarget whose directory
// is resolved and checked again at every use, so a link swapped in after
// the add cannot point it into the kernel's own data. A target logged as
// append-only is never asked to delete.
type dirTarget struct {
	bk         *backups
	locator    string
	appendOnly bool
}

func (bk *backups) target(t kernel.BackupTarget) backup.Target {
	var tg backup.Target = dirTarget{bk, t.Locator, t.AppendOnly}
	if bk.wrap != nil {
		tg = bk.wrap(tg)
	}
	return tg
}

func (d dirTarget) dir() (backup.DirTarget, error) {
	r, err := d.bk.checkDir(d.locator)
	return backup.DirTarget{Dir: r}, err
}

func (d dirTarget) PutTable(id string, gen uint64, b []byte) error {
	t, err := d.dir()
	if err != nil {
		return err
	}
	return t.PutTable(id, gen, b)
}

func (d dirTarget) GetTable(id string, gen uint64) ([]byte, error) {
	t, err := d.dir()
	if err != nil {
		return nil, err
	}
	return t.GetTable(id, gen)
}

func (d dirTarget) DeleteTable(id string, gen uint64) error {
	if d.appendOnly {
		return errors.New("run: an append-only backup destination cannot delete")
	}
	t, err := d.dir()
	if err != nil {
		return err
	}
	return t.DeleteTable(id, gen)
}

func (d dirTarget) Tables(id string) ([]uint64, error) {
	t, err := d.dir()
	if err != nil {
		return nil, err
	}
	return t.Tables(id)
}

func (d dirTarget) AppendOnly() bool { return d.appendOnly }

// liveSet is the backupSnap's Recaller: every subject live at the backupSnap.
type liveSet map[string]bool

func (l liveSet) Recall(s string) (kernel.Recall, bool) { return kernel.Recall{Subject: s}, l[s] }

// backupSnap is what one backup call writes: the log's first n bytes and the
// live keys, both read under the kernel's lock (brief decision 7).
type backupSnap struct {
	n    int64
	upto uint64 // the log head's sequence number at n
	keys *kernel.MemKeys
	live liveSet
}

func (h *Kernel) snap() (backupSnap, error) {
	n, err := h.store.Size()
	if err != nil {
		return backupSnap{}, err
	}
	s := backupSnap{n: n, upto: uint64(h.k.Log().Len()), keys: kernel.NewMemKeys(), live: liveSet{}}
	subs, err := h.bk.keys.List()
	if err != nil {
		return backupSnap{}, err
	}
	st := h.k.State()
	for _, sub := range subs {
		if r, ok := st.Recall(sub); !ok || r.Erased {
			continue
		}
		k, ok, err := h.bk.keys.Get(sub)
		if err != nil {
			return backupSnap{}, err
		}
		if ok {
			s.keys.Put(sub, k)
			s.live[sub] = true
		}
	}
	return s, nil
}

// logSource is the log's first n bytes, opened afresh each time.
func (bk *backups) logSource(n int64) backup.Source {
	return backup.Source{Name: "log", Open: func() (io.ReadCloser, error) {
		if bk.hook != nil {
			bk.hook()
		}
		f, err := os.OpenFile(bk.log, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return struct {
			io.Reader
			io.Closer
		}{io.NewSectionReader(f, 0, n), f}, nil
	}}
}

// lastFor is the newest kept backup to target at recipient, if any.
func (bk *backups) lastFor(target, recipient string) *Kept {
	var last *Kept
	for i := range bk.kept {
		kp := &bk.kept[i]
		if kp.Target == target && kp.Record.Recipient.ID() == recipient && (last == nil || kp.Record.Created >= last.Record.Created) {
			last = kp
		}
	}
	return last
}

// Backup takes one backup now to every current target (the owner's
// backup call), one backup per target (brief decision 3). A target whose
// last backup at this recipient is verified and under BackupEvery old
// keeps it. One call runs at a time; the writing runs outside the
// kernel's lock, so STOP never waits on a target.
func (h *Kernel) Backup(now int64) ([]Taken, error) {
	if h.bk == nil {
		return nil, ErrBackupsOff
	}
	bk := h.bk
	bk.run.Lock()
	defer bk.run.Unlock()
	var (
		out   []Taken
		write []kernel.BackupTarget
		snap  backupSnap
		rid   string
	)
	err := h.With(func(k *kernel.Kernel) (err error) {
		if bk.recipient == nil {
			return ErrNoRecipient
		}
		rid = bk.recipient.ID()
		for _, t := range k.State().BackupTargets() {
			if t.Removed {
				continue
			}
			if last := bk.lastFor(t.Name, rid); last != nil && last.Verified && now-last.Record.Created < BackupEvery && now >= last.Record.Created {
				v := last.view()
				out = append(out, Taken{Target: t.Name, Backup: &v, Reused: true})
				continue
			}
			write = append(write, t.BackupTarget)
		}
		if len(out)+len(write) == 0 {
			return ErrNoBackupTarget
		}
		if len(write) > 0 {
			snap, err = h.snap()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	done := map[int]string{} // out's index: the backup ID written there
	for _, t := range write {
		id, err := h.writeOne(t, snap, now)
		tk := Taken{Target: t.Name}
		if err != nil {
			tk.Error = err.Error()
		}
		if id != "" {
			done[len(out)] = id
		}
		out = append(out, tk)
	}
	if len(done) == 0 {
		return out, nil
	}
	// Each Taken shows its backup as kept now: a re-seal during the
	// write, or a finish that did not land, shows as it is.
	err = h.With(func(k *kernel.Kernel) error {
		for j, id := range done {
			if i := bk.find(id); i >= 0 {
				v := bk.kept[i].view()
				out[j].Backup = &v
			}
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	// A subject erased since the snapshot is in a new table: re-seal it
	// at once, without the lock.
	wg, err := h.reseal(now)
	if err == nil {
		wg.Wait()
	}
	return out, err
}

// find is the index in kept of backup id, -1 if none.
func (bk *backups) find(id string) int {
	for i := range bk.kept {
		if bk.kept[i].Record.BackupID == id {
			return i
		}
	}
	return -1
}

// pendingPut is a target that, before a key table goes out, logs and
// anchors the backup's backup.taken, then saves it as pending, under the
// kernel's lock, and adds it to the Set, and sends nothing when any of
// those fails (Security fix-list 1 on #3311, #3316).
type pendingPut struct {
	backup.Target
	h    *Kernel
	t    kernel.BackupTarget
	rec  backup.Record // the pending Record, less its ID and generation
	upto uint64        // the snapshot's log head
	id   string        // set once the pending Record is saved
	// inflight is set while the first key table is on its way.
	inflight atomic.Bool
}

func (p *pendingPut) PutTable(id string, gen uint64, b []byte) error {
	bk := p.h.bk
	err := p.h.With(func(k *kernel.Kernel) error {
		rec := p.rec
		rec.BackupID, rec.Generation = id, gen
		if err := k.BackupTaken(rec.Created, taken(p.t.Name, rec, p.upto)); err != nil {
			return fmt.Errorf("run: the backup is not in my log, so nothing went out: %w", err)
		}
		bk.kept = append(bk.kept, Kept{Target: p.t.Name, Pending: true, Upto: p.upto, Record: rec})
		if err := bk.save(); err != nil {
			bk.kept = bk.kept[:len(bk.kept)-1]
			return fmt.Errorf("run: the backup's record is not saved, so nothing went out: %w", err)
		}
		p.id = id
		p.inflight.Store(true)
		return bk.set.Add(inFlight{bk.target(p.t), &p.inflight}, rec)
	})
	if err != nil {
		return err
	}
	perr := p.Target.PutTable(id, gen, b)
	// An erase while the table was on its way named the backup held (the
	// Set's target refused while in flight); now that the put is over,
	// Backup re-seals it at once, and Tick retries it if that fails
	// (#3311 L3 and Security on 6ef6bef).
	p.inflight.Store(false)
	p.h.With(func(k *kernel.Kernel) error { k.RetryBackup(id); return nil })
	return perr
}

// inFlight is a Set member's target while its first key table is on its
// way: every call refuses, so an erase then names the backup held instead
// of re-sealing a table that is not there yet, which the put would then
// land beside, still giving the erased key.
type inFlight struct {
	backup.Target
	on *atomic.Bool
}

// ErrInFlight: a backup's first key table is still on its way to its
// target; the erase re-seals it once the put is over.
var ErrInFlight = errors.New("run: this backup's key table is still on its way; I re-seal it once it lands")

func (f inFlight) busy() error {
	if f.on.Load() {
		return ErrInFlight
	}
	return nil
}

func (f inFlight) PutTable(id string, gen uint64, b []byte) error {
	if err := f.busy(); err != nil {
		return err
	}
	return f.Target.PutTable(id, gen, b)
}

func (f inFlight) GetTable(id string, gen uint64) ([]byte, error) {
	if err := f.busy(); err != nil {
		return nil, err
	}
	return f.Target.GetTable(id, gen)
}

func (f inFlight) DeleteTable(id string, gen uint64) error {
	if err := f.busy(); err != nil {
		return err
	}
	return f.Target.DeleteTable(id, gen)
}

func (f inFlight) Tables(id string) ([]uint64, error) {
	if err := f.busy(); err != nil {
		return nil, err
	}
	return f.Target.Tables(id)
}

// writeOne writes one backup of snap to t: the content object as
// <id>.content beside its key tables, then reads both back, and keeps the
// result. It returns the backup's ID once its pending Record is saved,
// that is whenever a key table may be at the target, and "" otherwise.
func (h *Kernel) writeOne(t kernel.BackupTarget, snap backupSnap, now int64) (string, error) {
	bk := h.bk
	dt, err := dirTarget{bk, t.Locator, t.AppendOnly}.dir()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp(dt.Dir, ".tmp-content-*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	tg := bk.target(t)
	// The page authority goes in every backup, so a restore brings back
	// the fingerprint the Owner Card prints, and the kept Record names it,
	// so restore refuses a backup whose authority is another (CH-9, BAK-1).
	var ca []byte
	var caPrint string
	if h.page != nil {
		if ca, err = pageca.Marshal(h.page); err != nil {
			return "", err
		}
		defer clear(ca)
		caPrint = h.page.Fingerprint()
	}
	pp := &pendingPut{Target: tg, h: h, t: t, upto: snap.upto, rec: backup.Record{Recipient: *bk.recipient, Created: now,
		Subjects: slices.Sorted(maps.Keys(snap.live)), PageCA: caPrint}}
	rec, err := backup.Write(f, pp, backup.Input{
		Recipient: *bk.recipient, Created: now, PageCA: ca, PageCAFingerprint: caPrint,
		Sections: []backup.Source{bk.logSource(snap.n)}, Keys: snap.keys, State: snap.live,
	})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if pp.id == "" || err != nil {
		return pp.id, err
	}
	if err := os.Link(tmp, filepath.Join(dt.Dir, rec.BackupID+contentExt)); err != nil {
		return pp.id, err
	}
	if err := privfile.SyncDir(dt.Dir); err != nil {
		return pp.id, err
	}
	verified := readBack(tg, dt.Dir, rec)
	return pp.id, h.With(func(*kernel.Kernel) error {
		i := bk.find(rec.BackupID)
		if i < 0 {
			return backup.ErrNoBackup
		}
		kp := &bk.kept[i]
		old := *kp
		kp.Pending, kp.Verified, kp.Record.ContentSum = false, verified, rec.ContentSum
		// A re-seal during the write has a newer table and sum already.
		if kp.Record.Generation == rec.Generation {
			kp.Record.TableSum = rec.TableSum
		}
		if err := bk.save(); err != nil {
			*kp = old
			return fmt.Errorf("run: the backup was written but its record stays pending: %w", err)
		}
		return nil
	})
}

// readBack reports whether t, at dir, gives back rec's content object and key
// table, byte for byte as their sums.
func readBack(t backup.Target, dir string, rec backup.Record) bool {
	tb, err := t.GetTable(rec.BackupID, rec.Generation)
	if err != nil || sumHex(tb) != rec.TableSum {
		return false
	}
	f, err := os.OpenFile(filepath.Join(dir, rec.BackupID+contentExt), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == rec.ContentSum
}

func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// Backups is the backups call's answer, read under the lock.
func (h *Kernel) Backups() (BackupsView, error) {
	if h.bk == nil {
		return BackupsView{}, ErrBackupsOff
	}
	var v BackupsView
	err := h.With(func(k *kernel.Kernel) error {
		if h.bk.recipient != nil {
			v.Recipient = h.bk.recipient.ID()
		}
		for _, t := range k.State().BackupTargets() {
			v.Targets = append(v.Targets, TargetView{Name: t.Name, Kind: t.Kind, Locator: t.Locator,
				AppendOnly: t.AppendOnly, Removed: t.Removed, Rewritable: !h.bk.target(t.BackupTarget).AppendOnly()})
		}
		for _, kp := range h.bk.kept {
			v.Backups = append(v.Backups, kp.view())
		}
		return nil
	})
	return v, err
}

// AddBackupTarget adds t on an anchor's signature c (kernel.BackupTarget),
// after checking its directory is reachable and outside the kernel's own
// data.
func (h *Kernel) AddBackupTarget(now int64, t kernel.BackupTarget, c key.Cosign) error {
	if h.bk == nil {
		return ErrBackupsOff
	}
	if t.Kind == kernel.KindDir {
		if _, err := h.bk.checkDir(t.Locator); err != nil {
			return err
		}
	}
	return h.With(func(k *kernel.Kernel) error { return k.BackupTarget(now, t, c) })
}
