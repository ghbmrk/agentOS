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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/ghbmrk/agentos/broker/backup"
	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/kernel/privfile"
)

// Backups on the running box (BAK-1, MIG-4-recovery-e3). The kernel process
// holds the destinations (kernel.BackupTarget, logged) and does the
// carrying: it takes a backupSnap under its lock, writes one backup to each
// current target outside it, reads each back and marks it verified itself,
// so a lying owner side cannot mark one. It keeps every backup's Record in
// one file in its backup directory, sealed under the log key, and at start
// builds the backup.Set an erase re-seals through (LOG-4, D-168, #3188),
// removed targets included. The owner side only triggers, chooses and tells.

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
// to, and whether the kernel read it back whole.
type Kept struct {
	Target   string        `json:"target"`
	Verified bool          `json:"verified"`
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
		Created: k.Record.Created, Generation: k.Record.Generation, Verified: k.Verified}
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
	// For tests only: hook runs as each section opens, and wrap, when
	// set, wraps every target.
	hook func()
	wrap func(backup.Target) backup.Target
}

// openBackups opens the records in dir under logKey, made 0700 if missing,
// and builds the Set from them and the logged targets.
func openBackups(cfg KernelConfig, keys kernel.Keys, st *kernel.State) (*backups, error) {
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
	bk.set = backup.NewSet(bk.saveRecord)
	targets := map[string]kernel.KeptTarget{}
	for _, t := range st.BackupTargets() {
		targets[t.Name] = t
	}
	for _, kp := range bk.kept {
		t, ok := targets[kp.Target]
		if !ok {
			return nil, fmt.Errorf("%w: a record names target %q, which the log never added", ErrRecordsFile, kp.Target)
		}
		if err := bk.set.Add(bk.target(t.BackupTarget), kp.Record); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrRecordsFile, err)
		}
	}
	return bk, nil
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
// kept one of its backup.
func (bk *backups) saveRecord(rec backup.Record) error {
	for i := range bk.kept {
		if bk.kept[i].Record.BackupID == rec.BackupID {
			old := bk.kept[i].Record
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
	keys *kernel.MemKeys
	live liveSet
}

func (h *Kernel) snap() (backupSnap, error) {
	n, err := h.store.Size()
	if err != nil {
		return backupSnap{}, err
	}
	s := backupSnap{n: n, keys: kernel.NewMemKeys(), live: liveSet{}}
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
	var done []Kept
	for _, t := range write {
		kp, err := bk.writeOne(t, snap, now)
		if kp == nil {
			out = append(out, Taken{Target: t.Name, Error: err.Error()})
			continue
		}
		done = append(done, *kp)
		v := kp.view()
		tk := Taken{Target: t.Name, Backup: &v}
		if err != nil {
			tk.Error = err.Error()
		}
		out = append(out, tk)
	}
	if len(done) == 0 {
		return out, nil
	}
	err = h.With(func(k *kernel.Kernel) error {
		bk.kept = append(bk.kept, done...)
		var errs []error
		// Kept in memory even if the file write fails, so an erase this
		// run still reaches the backup; the error says the restart may not.
		if err := bk.save(); err != nil {
			errs = append(errs, fmt.Errorf("run: a backup's record is not saved: %w", err))
		}
		targets := map[string]kernel.BackupTarget{}
		for _, t := range write {
			targets[t.Name] = t
		}
		for _, kp := range done {
			errs = append(errs, bk.set.Add(bk.target(targets[kp.Target]), kp.Record))
		}
		// A subject erased since the backupSnap is in a new table: re-seal
		// it at once (OpenBackups re-seals every backup giving an erased
		// subject's key).
		k.OpenBackups(bk.set, now)
		return errors.Join(errs...)
	})
	return out, err
}

// writeOne writes one backup of snap to t: the content object as
// <id>.content beside its key tables, then reads both back. It returns the
// Record whenever a key table may be at the target, so an erase can reach
// it, verified only when both read back as written.
func (bk *backups) writeOne(t kernel.BackupTarget, snap backupSnap, now int64) (*Kept, error) {
	dt, err := dirTarget{bk, t.Locator, t.AppendOnly}.dir()
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dt.Dir, ".tmp-content-*")
	if err != nil {
		return nil, err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	tg := bk.target(t)
	rec, err := backup.Write(f, tg, backup.Input{
		Recipient: *bk.recipient, Created: now, Sections: []backup.Source{bk.logSource(snap.n)},
		Keys: snap.keys, State: snap.live,
	})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if rec.BackupID == "" {
		return nil, err
	}
	kp := &Kept{Target: t.Name, Record: rec}
	if err != nil {
		return kp, err
	}
	if err := os.Link(tmp, filepath.Join(dt.Dir, rec.BackupID+contentExt)); err != nil {
		return kp, err
	}
	if err := privfile.SyncDir(dt.Dir); err != nil {
		return kp, err
	}
	kp.Verified = readBack(tg, dt.Dir, rec)
	return kp, nil
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
