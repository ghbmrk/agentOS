package kernel

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Backup destinations (BAK-1, MIG-4-recovery-e2). A destination is one of the
// core's own outbound connections, a declared endpoint (HW-16, HW-17), so it
// is authority, not a name: adding one is a widening a hardware key signs,
// and the kernel logs it. Removing one is a narrowing anyone on the owner
// channel may make. A removed target stays in state, since its backups keep
// their erase reach until every record on it is gone (LOG-4, D-168); the
// kernel process (e3) does the carrying.

// Entry types for backup destinations, both version 1.
const (
	TBackupTarget   = "backup.target"
	TBackupUntarget = "backup.untarget"
	TBackupTaken    = "backup.taken"
)

// Target kinds are a closed set: the storage adapter row adds its own.
const KindDir = "dir" // a mounted directory, such as a second local drive

// Limits on a target's shape.
const (
	MaxTargetName = 64
	MaxLocator    = 1024
)

var (
	// ErrTargetSig refuses an add no hardware key signed over BackupTargetHash.
	ErrTargetSig = errors.New("kernel: a backup destination needs your hardware key's signature")
	// ErrTarget refuses a target the kernel cannot carry: an unknown kind, or
	// a name or locator out of shape.
	ErrTarget = errors.New("kernel: not a backup destination I can use")
	// ErrTargetExists refuses a name already used, removed or not.
	ErrTargetExists = errors.New("kernel: that backup destination name is taken")
	// ErrNoTarget refuses removing a target that is not current.
	ErrNoTarget = errors.New("kernel: no such current backup destination")
)

// BackupTarget is a destination as the owner adds it and an anchor signs it.
type BackupTarget struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Locator    string `json:"locator"`
	AppendOnly bool   `json:"append_only"`
}

// KeptTarget is a destination in state: removed ones stay listed.
type KeptTarget struct {
	BackupTarget
	Removed bool
	taken   []BackupTaken // the backups logged to it, in log order
}

// Sizes of a backup recipient's public keys: X25519 and ML-KEM-768's
// encapsulation key (broker/backup.Recipient).
const (
	RecipientXLen  = 32
	RecipientEKLen = 1184
)

// BackupRecipient is a backup's public recipient, as broker/backup.Recipient.
type BackupRecipient struct {
	X  []byte `json:"x"`
	EK []byte `json:"ek"`
}

// BackupTaken names one backup before its key table leaves (LOG-4,
// BAK-1), so a rolled-back records file cannot hide it from an erase.
// Upto is the log head's sequence number in the backup's snapshot: the
// subjects its first table can give are those opened at or below it.
// Recipient is in full, since a backup from before a recovery-key rotation
// re-seals to its own. It grants nothing, so it is not a widening.
type BackupTaken struct {
	BackupID  string          `json:"backup_id"`
	Target    string          `json:"target"`
	Recipient BackupRecipient `json:"recipient"`
	Created   int64           `json:"created"`
	Upto      uint64          `json:"upto"`
}

// ErrBackupTaken refuses a backup.taken the fold would not keep.
var ErrBackupTaken = errors.New("kernel: not a backup I can log")

type (
	backupTarget struct {
		Target BackupTarget
		Cosign key.Cosign
	}
	backupUntarget struct{ Name string }
)

// BackupTargetHash names adding t as the n-th target (State.TargetsAdded),
// so a signature over one add never replays as another.
func BackupTargetHash(n int, t BackupTarget) [32]byte {
	b, _ := json.Marshal(struct {
		N int
		T BackupTarget
	}{n, t})
	return sha256.Sum256(append([]byte("agentos.backup.target.v1\x00"), b...))
}

// shape reports whether the kernel can carry t: a known kind, a short plain
// name not led by a dot, and a locator of printable characters only, so the
// page shows the anchor's signer what it signs (no bidi, zero-width,
// separator or default-ignorable characters), for a directory a clean absolute path.
func (t BackupTarget) shape() bool {
	if len(t.Name) == 0 || len(t.Name) > MaxTargetName || len(t.Locator) == 0 || len(t.Locator) > MaxLocator ||
		!utf8.ValidString(t.Locator) || slices.ContainsFunc([]rune(t.Locator), invisible) || t.Name[0] == '.' {
		return false
	}
	for _, c := range t.Name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	switch t.Kind {
	case KindDir:
		return path.IsAbs(t.Locator) && path.Clean(t.Locator) == t.Locator && !slices.ContainsFunc(strings.Split(t.Locator, "/"), padded)
	}
	return false
}

// padded reports a path element led or trailed by a space, or only space,
// which the page shows as the element without it (#3901).
func padded(e string) bool { return strings.TrimSpace(e) != e }

// invisible reports a character the page cannot show: unprintable, or
// printable but default-ignorable (a joiner, a variation selector, a filler).
func invisible(c rune) bool {
	return !unicode.IsPrint(c) || unicode.Is(unicode.Other_Default_Ignorable_Code_Point, c) || unicode.Is(unicode.Variation_Selector, c)
}

// TargetsAdded is how many targets have been added: an add's anchor signs
// BackupTargetHash(TargetsAdded(), t).
func (s *State) TargetsAdded() int { return len(s.targets) }

// BackupTargets lists every target in the order added, removed ones marked.
func (s *State) BackupTargets() []KeptTarget { return slices.Clone(s.targets) }

// BackupsTaken lists every logged backup, by target in the order added,
// then in log order.
func (s *State) BackupsTaken() []BackupTaken {
	var out []BackupTaken
	for _, t := range s.targets {
		out = append(out, t.taken...)
	}
	return out
}

// SubjectsUpto is every subject opened at or below seq, erased or not, sorted.
func (s *State) SubjectsUpto(seq uint64) []string {
	var out []string
	for sub, st := range s.subjects {
		if st.seq <= seq {
			out = append(out, sub)
		}
	}
	slices.Sort(out)
	return out
}

// backupID reports whether id is a backup ID as broker/backup draws them:
// 16 bytes, lowercase hex.
func backupID(id string) bool {
	return len(id) == 32 && strings.Trim(id, "0123456789abcdef") == ""
}

// takenOK is the check a backup.taken at seq passes, live and on replay: a
// target the log added (removed or not), a backup ID not yet logged,
// recipient keys of their size, and a snapshot before the entry itself.
func (s *State) takenOK(b BackupTaken, seq uint64) error {
	if s.target(b.Target) == nil || !backupID(b.BackupID) || len(b.Recipient.X) != RecipientXLen ||
		len(b.Recipient.EK) != RecipientEKLen || b.Upto >= seq {
		return ErrBackupTaken
	}
	for _, t := range s.targets {
		for _, k := range t.taken {
			if k.BackupID == b.BackupID {
				return ErrBackupTaken
			}
		}
	}
	return nil
}

func (s *State) target(name string) *KeptTarget {
	for i := range s.targets {
		if s.targets[i].Name == name {
			return &s.targets[i]
		}
	}
	return nil
}

// targetOK is the check an add passes, live and on replay.
func (s *State) targetOK(b backupTarget) error {
	if !b.Target.shape() {
		return ErrTarget
	}
	if !key.In(s.Anchors, b.Cosign.By) || !b.Cosign.Over(BackupTargetHash(len(s.targets), b.Target)) {
		return ErrTargetSig
	}
	if s.target(b.Target.Name) != nil {
		return ErrTargetExists
	}
	return nil
}

// applyBackup folds a target entry. One that fails its check, written past
// the kernel, changes nothing, so an audit trusts no writer for it.
func (s *State) applyBackup(e Entry) error {
	switch e.Type {
	case TBackupTarget:
		b, err := body[backupTarget](e)
		if err != nil {
			return err
		}
		if s.targetOK(b) == nil {
			s.targets = append(s.targets, KeptTarget{BackupTarget: b.Target})
		}
	case TBackupUntarget:
		b, err := body[backupUntarget](e)
		if err != nil {
			return err
		}
		if t := s.target(b.Name); t != nil {
			t.Removed = true
		}
	case TBackupTaken:
		b, err := body[BackupTaken](e)
		if err != nil {
			return err
		}
		if s.takenOK(b, e.Seq) == nil {
			t := s.target(b.Target)
			t.taken = append(t.taken, b)
		}
	}
	return nil
}

// BackupTarget adds t on an anchor's signature c over
// BackupTargetHash(State.TargetsAdded(), t). It is a widening, so it anchors.
func (k *Kernel) BackupTarget(now int64, t BackupTarget, c key.Cosign) error {
	b := backupTarget{t, c}
	if err := k.s.targetOK(b); err != nil {
		return err
	}
	return k.owner(now, TBackupTarget, b)
}

// Untarget stops new backups to the current target name. It narrows, so it
// needs no signature; the target stays listed as removed.
func (k *Kernel) Untarget(now int64, name string) error {
	if t := k.s.target(name); t == nil || t.Removed {
		return ErrNoTarget
	}
	return k.owner(now, TBackupUntarget, backupUntarget{name})
}

// BackupTaken logs b before its key table leaves, then anchors the head,
// so a log rollback the anchor catches cannot drop it (LOG-4). The entry
// is not a widening, so Open keeps it unanchored too: an anchor error
// leaves it logged.
func (k *Kernel) BackupTaken(now int64, b BackupTaken) error {
	if err := k.s.takenOK(b, uint64(k.log.Len())+1); err != nil {
		return err
	}
	return k.owner(now, TBackupTaken, b)
}
