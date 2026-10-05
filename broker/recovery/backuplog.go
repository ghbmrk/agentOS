package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// The backup log lets the box name where older backups are after the
// recovery key changes (REC-4, arbitrator ruling on #35). A backup is
// sealed to the recovery key's public half, so the box cannot open or
// rewrap one; it can only say where those still opening with the old
// card are, and, with the owner's tier-4 approval, delete those it can
// reach.
const (
	BackupLogName = "recovery-backup-log"
	KindBackupLog = "backup_log"
	backupLogMax  = 200
	backupLogFmt  = "agentos-backup-log-v1"
)

// BackupEntry is one backup: where it went and when. Nothing else is kept.
type BackupEntry struct {
	Destination string    `json:"destination"`
	Created     time.Time `json:"created"`
	// Verified: read back from the destination and matching what was
	// written.
	Verified bool `json:"verified,omitempty"`
	// Key identifies the backup key the backup was sealed to (keyID). A
	// backup is current only when it matches the drive's backup key now,
	// whatever the clock said (Created is for display).
	Key string `json:"key,omitempty"`
}

type backupLog struct {
	Format  string        `json:"format"`
	Entries []BackupEntry `json:"entries"`
	// KeyChangedAt is when the recovery key last changed; backups before
	// it open only with the old card.
	KeyChangedAt time.Time `json:"key_changed_at,omitempty"`
	// Reminders is how many more digests carry the old-backups line.
	Reminders int `json:"reminders,omitempty"`
}

func loadLog(b *Box) (backupLog, error) {
	raw, ok, err := reserved(b.V, BackupLogName, KindBackupLog)
	if err != nil {
		return backupLog{}, err
	}
	l := backupLog{Format: backupLogFmt}
	if !ok {
		return l, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&l); err != nil || l.Format != backupLogFmt {
		return backupLog{}, errors.New("recovery: malformed backup log")
	}
	return l, nil
}

func saveLog(b *Box, l backupLog) error {
	if len(l.Entries) > backupLogMax {
		l.Entries = l.Entries[len(l.Entries)-backupLogMax:]
	}
	enc, err := json.Marshal(l)
	if err != nil {
		return err
	}
	return b.V.Put(BackupLogName, KindBackupLog, enc)
}

// Receipt is what BackupSum wrote: the backup's time and the SHA-256 of
// its bytes, for RecordBackup. Only BackupSum makes one, so a backup is
// logged as verified, and opens ApproveDelete, only after this box wrote
// it.
type Receipt struct {
	created time.Time
	sum     []byte
	key     string
}

// Created is when the backup was made.
func (r Receipt) Created() time.Time { return r.created }

// BackupSum writes a backup like Backup and returns its receipt.
func BackupSum(b *Box, roots []Root, w io.Writer, now time.Time) (Receipt, error) {
	pub, err := backupKey(b)
	if err != nil {
		return Receipt{}, err
	}
	h := sha256.New()
	if err := backupSealed(b, pub, roots, io.MultiWriter(w, h), now); err != nil {
		return Receipt{}, err
	}
	return Receipt{created: now.UTC(), sum: h.Sum(nil), key: keyID(pub)}, nil
}

// RecordBackup logs a backup written to destination (a name the owner
// recognizes, such as "USB stick SANDISK-1"), at the time in its receipt.
// readBack is the backup as read again from the destination; it is
// verified when it matches the receipt.
func RecordBackup(b *Box, destination string, rc Receipt, readBack io.Reader) (BackupEntry, error) {
	created, sum := rc.created, rc.sum
	b.mu.Lock()
	defer b.mu.Unlock()
	destination = strings.TrimSpace(destination)
	if rc.created.IsZero() {
		return BackupEntry{}, errors.New("recovery: record a backup with BackupSum's receipt")
	}
	if destination == "" || len(destination) > 200 {
		return BackupEntry{}, errors.New("recovery: name the backup's destination")
	}
	e := BackupEntry{Destination: destination, Created: created.UTC(), Key: rc.key}
	if readBack != nil && len(sum) == sha256.Size {
		h := sha256.New()
		if _, err := io.Copy(h, readBack); err == nil {
			e.Verified = bytes.Equal(h.Sum(nil), sum)
		}
	}
	l, err := loadLog(b)
	if err != nil {
		return BackupEntry{}, err
	}
	l.Entries = append(l.Entries, e)
	return e, saveLog(b, l)
}

// keyChanged records a recovery key rotation: the next digest names the
// older backups.
func keyChanged(b *Box, now time.Time) error {
	l, err := loadLog(b)
	if err != nil {
		return err
	}
	l.KeyChangedAt, l.Reminders = now.UTC(), 1
	return saveLog(b, l)
}

// keyID names a backup public key: the first 16 bytes of its SHA-256
// under a label, in hex.
func keyID(pub []byte) string {
	h := sha256.New()
	h.Write([]byte("agentos-backup-key-id-v1"))
	h.Write(pub)
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// currentKey is the keyID of the key backups are sealed to now; empty
// when there is none, so no backup counts as current.
func currentKey(b *Box) string {
	pub, err := backupKey(b)
	if err != nil {
		return ""
	}
	return keyID(pub)
}

// older lists backups sealed to another key than cur, once the key changed.
func (l backupLog) older(cur string) []BackupEntry {
	var out []BackupEntry
	for _, e := range l.Entries {
		if !l.KeyChangedAt.IsZero() && (cur == "" || e.Key != cur) {
			out = append(out, e)
		}
	}
	return out
}

// freshVerified reports a verified backup sealed to the current key cur
// since the key changed.
func (l backupLog) freshVerified(cur string) bool {
	for _, e := range l.Entries {
		if e.Verified && !l.KeyChangedAt.IsZero() && cur != "" && e.Key == cur {
			return true
		}
	}
	return false
}

func destinations(es []BackupEntry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range es {
		if !seen[e.Destination] {
			seen[e.Destination] = true
			out = append(out, e.Destination)
		}
	}
	sort.Strings(out)
	return out
}

func joinNames(ns []string) string {
	switch len(ns) {
	case 0:
		return ""
	case 1:
		return ns[0]
	}
	return strings.Join(ns[:len(ns)-1], ", ") + " and " + ns[len(ns)-1]
}

// OldBackupsNote is the done page's and the digest's line after the
// recovery key changed, naming the logged destinations of older backups.
// Empty when there are none.
func OldBackupsNote(b *Box) (string, error) {
	l, err := loadLog(b)
	if err != nil {
		return "", err
	}
	old := l.older(currentKey(b))
	if len(old) == 0 {
		return "", nil
	}
	return fmt.Sprintf("Backups made before %s still open with your old card. Delete them from %s once the new backup is done.",
		l.KeyChangedAt.Format("2006-01-02"), joinNames(destinations(old))), nil
}

// DigestLine returns the old-backups line for the next digest while
// reminders remain, and uses one up.
func DigestLine(b *Box) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, err := loadLog(b)
	if err != nil || l.Reminders <= 0 {
		return "", err
	}
	note, err := OldBackupsNote(b)
	if err != nil || note == "" {
		return note, err
	}
	l.Reminders--
	return note, saveLog(b, l)
}

// DeleteOffer is the done page's offer to delete older backups the box
// can reach, made once a backup under the new key is verified.
type DeleteOffer struct {
	Text string
	// Reachable are the backups the box would delete on approval.
	Reachable []BackupEntry
	// Elsewhere are destinations the box cannot reach: named instructions.
	Elsewhere []string
}

// OfferDelete builds the offer. reachable says whether the box can reach a
// destination now. There is no offer before a verified backup made after
// the key change, or with nothing reachable to delete.
func OfferDelete(b *Box, reachable func(string) bool) (DeleteOffer, bool, error) {
	l, err := loadLog(b)
	if err != nil {
		return DeleteOffer{}, false, err
	}
	var off DeleteOffer
	var far []BackupEntry
	cur := currentKey(b)
	fresh := l.freshVerified(cur)
	for _, e := range l.older(cur) {
		if reachable != nil && reachable(e.Destination) {
			off.Reachable = append(off.Reachable, e)
		} else {
			far = append(far, e)
		}
	}
	off.Elsewhere = destinations(far)
	if !fresh || len(off.Reachable) == 0 {
		return off, false, nil
	}
	off.Text = fmt.Sprintf("Delete the %d older backups at %s now?", len(off.Reachable), joinNames(destinations(off.Reachable)))
	return off, true, nil
}

// ErrNoFreshBackup is a deletion asked for before a verified backup under
// the new recovery key exists.
var ErrNoFreshBackup = errors.New("recovery: make and verify a new backup before deleting older ones")

// ApproveDelete is the owner's tier-4 answer (CH-3) to an offer. It
// returns the offered older backups for the caller to delete, and only
// once a verified backup under the new key exists. It is never automatic.
// The log keeps them until ForgetBackups confirms the deletion.
func ApproveDelete(b *Box, off DeleteOffer, auth Auth) ([]BackupEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := auth.check(b); err != nil {
		return nil, err
	}
	l, err := loadLog(b)
	if err != nil {
		return nil, err
	}
	cur := currentKey(b)
	if !l.freshVerified(cur) {
		return nil, ErrNoFreshBackup
	}
	offered := map[BackupEntry]bool{}
	for _, e := range off.Reachable {
		offered[e] = true
	}
	var out []BackupEntry
	for _, e := range l.older(cur) {
		if offered[e] {
			out = append(out, e)
		}
	}
	return out, nil
}

// ForgetBackups drops older backups from the log once the caller has
// confirmed their deletion. Backups sealed to the current key are never
// dropped.
func ForgetBackups(b *Box, deleted []BackupEntry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, err := loadLog(b)
	if err != nil {
		return err
	}
	gone := map[BackupEntry]bool{}
	for _, e := range l.older(currentKey(b)) {
		gone[e] = false
	}
	for _, e := range deleted {
		if _, old := gone[e]; old {
			gone[e] = true
		}
	}
	var keep []BackupEntry
	for _, e := range l.Entries {
		if !gone[e] {
			keep = append(keep, e)
		}
	}
	l.Entries = keep
	return saveLog(b, l)
}

// DeclineDelete keeps the backups and repeats the digest line once.
func DeclineDelete(b *Box) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	l, err := loadLog(b)
	if err != nil {
		return err
	}
	l.Reminders = 1
	return saveLog(b, l)
}
