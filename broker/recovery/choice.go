package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Backups are optional and owner-chosen (BAK-1): a second local drive, or
// upload to storage the owner already has. Either way the bytes are the
// sealed stream Backup writes, which only the recovery key opens, so the
// upload is encrypted before it leaves the box. Until a backup is verified
// under the current recovery key, the drive is the only copy, and the box
// says so plainly: on the choice page, on the status page, and in the
// digest.
const (
	BackupChoiceName = "backup-choice"
	KindBackupChoice = "backup_choice"
	backupChoiceFmt  = "agentos-backup-choice-v1"
)

// BackupKind is where the owner chose to keep backups.
type BackupKind string

const (
	// BackupUnchosen: the owner has not chosen yet (a new box).
	BackupUnchosen BackupKind = ""
	// BackupNone: the owner chose no backup.
	BackupNone BackupKind = "none"
	// BackupDrive: a second local drive.
	BackupDrive BackupKind = "drive"
	// BackupUpload: storage the owner already has, reached over the
	// network by the caller.
	BackupUpload BackupKind = "upload"
)

// BackupChoice is the owner's choice. Destination is a name the owner
// recognizes ("USB stick SANDISK-1", "Home NAS"), the same name the
// backup log records; the storage's sign-in, if any, is a credential in
// the vault, never part of the name.
type BackupChoice struct {
	Kind        BackupKind `json:"kind"`
	Destination string     `json:"destination,omitempty"`
	// Chosen is when the owner chose.
	Chosen time.Time `json:"chosen,omitempty"`
}

type choiceValue struct {
	Format string `json:"format"`
	BackupChoice
	// Noticed is when the owner was last told the drive is the only copy.
	Noticed time.Time `json:"noticed,omitempty"`
}

// The plain notices. Each says the drive is the only copy and what that
// means; the variant says why.
const (
	NoticeUnchosen = "This drive is the only copy of your box. If it is lost or fails, everything on it is gone. To keep a copy, choose a backup on the box's Wi-Fi page: a second drive, or storage you already have."
	NoticeNone     = "You chose no backup, so this drive is the only copy of your box. If it is lost or fails, everything on it is gone. You can choose a backup any time on the box's Wi-Fi page."
	noticeNoneYet  = "No backup has finished yet, so this drive is still the only copy of your box. If it is lost or fails, everything on it is gone. Backups go to %s."
	NoticeOldCard  = "Your existing backups open only with your old card. Back up now on the box's Wi-Fi page so your current card can restore the box."
)

// How often the digest repeats the notice: weekly while no backup is
// chosen or none has finished, monthly once the owner chose none.
const (
	noticeEvery     = 7 * 24 * time.Hour
	noticeEveryNone = 30 * 24 * time.Hour
)

// ErrBadBackupChoice is a choice that is not one of the three, or whose
// destination is missing, too long, or carries a sign-in.
var ErrBadBackupChoice = errors.New("recovery: choose no backup, a second drive, or storage you already have, by a name of up to 200 characters")

func loadChoice(b *Box) (choiceValue, error) {
	raw, ok, err := reserved(b.V, BackupChoiceName, KindBackupChoice)
	if err != nil {
		return choiceValue{}, err
	}
	c := choiceValue{Format: backupChoiceFmt}
	if !ok {
		return c, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil || c.Format != backupChoiceFmt || c.valid() != nil {
		return choiceValue{}, errors.New("recovery: malformed backup choice")
	}
	return c, nil
}

func saveChoice(b *Box, c choiceValue) error {
	enc, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return b.V.Put(BackupChoiceName, KindBackupChoice, enc)
}

func (c BackupChoice) valid() error {
	switch c.Kind {
	case BackupUnchosen, BackupNone:
		if c.Destination != "" {
			return ErrBadBackupChoice
		}
		return nil
	case BackupDrive, BackupUpload:
	default:
		return ErrBadBackupChoice
	}
	d := c.Destination
	if d == "" || len(d) > 200 || strings.TrimSpace(d) != d {
		return ErrBadBackupChoice
	}
	for _, r := range d {
		if unicode.IsControl(r) {
			return ErrBadBackupChoice
		}
	}
	// The name goes into the digest, so it must not look like a code or key.
	if owner.SecretShaped(d) {
		return ErrBadBackupChoice
	}
	if strings.Contains(d, "://") {
		if u, err := url.Parse(d); err != nil || u.User != nil {
			return ErrBadBackupChoice
		}
	}
	return nil
}

// LoadBackupChoice returns the owner's choice; BackupUnchosen on a new box.
func LoadBackupChoice(b *Box) (BackupChoice, error) {
	c, err := loadChoice(b)
	return c.BackupChoice, err
}

// ChooseBackup records the owner's choice and returns the notice to show
// with it, empty when a verified backup already exists. Choosing is
// tier-4 (CH-3): an upload destination is a new grant, and turning
// backups off must not be possible from a spoofed text.
func ChooseBackup(b *Box, c BackupChoice, auth Auth, now time.Time) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c.Destination = strings.TrimSpace(c.Destination)
	if c.Kind == BackupUnchosen {
		return "", ErrBadBackupChoice
	}
	if err := c.valid(); err != nil {
		return "", err
	}
	if err := auth.check(b); err != nil {
		return "", err
	}
	cur, err := loadChoice(b)
	if err != nil {
		return "", err
	}
	c.Chosen = now.UTC()
	cur.BackupChoice, cur.Noticed = c, now.UTC()
	if err := saveChoice(b, cur); err != nil {
		return "", err
	}
	return notice(b, cur.BackupChoice)
}

// OnlyCopyNotice is the status page's line: empty when a backup verified
// under the current recovery key exists, else the plain notice. On an
// unreadable choice it still returns the notice, with the error.
func OnlyCopyNotice(b *Box) (string, error) {
	c, err := loadChoice(b)
	if err != nil {
		return NoticeUnchosen, err
	}
	return notice(b, c.BackupChoice)
}

func notice(b *Box, c BackupChoice) (string, error) {
	l, err := loadLog(b)
	if err != nil {
		return NoticeUnchosen, err
	}
	// A backup counts when it was sealed to the drive's backup key now,
	// never by its timestamp, which comes from the box clock.
	cur := currentKey(b)
	older := false
	for _, e := range l.Entries {
		if !e.Verified {
			continue
		}
		if cur != "" && e.Key == cur {
			return "", nil
		}
		older = true
	}
	switch {
	case older:
		return NoticeOldCard, nil
	case c.Kind == BackupNone:
		return NoticeNone, nil
	case c.Kind == BackupUnchosen:
		return NoticeUnchosen, nil
	}
	return strings.Replace(noticeNoneYet, "%s", c.Destination, 1), nil
}

// OnlyCopyDigestLine returns the notice for the digest when it is due, and
// records that it was sent.
func OnlyCopyDigestLine(b *Box, now time.Time) (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	c, err := loadChoice(b)
	if err != nil {
		return NoticeUnchosen, err
	}
	n, err := notice(b, c.BackupChoice)
	if err != nil || n == "" {
		return n, err
	}
	every := noticeEvery
	if n == NoticeNone {
		every = noticeEveryNone
	}
	if !c.Noticed.IsZero() && now.Sub(c.Noticed) < every {
		return "", nil
	}
	c.Noticed = now.UTC()
	return n, saveChoice(b, c)
}
