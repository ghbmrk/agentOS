package backup

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// Set is the box's older backups as an erase reaches them (D-168): it is
// the kernel's Backups, each backup named by its BackupID. Save persists a
// Record a Rewrap returned, and until it returns nil the Set keeps the old
// Record, so the next Reseal rewraps again. The kernel calls a Set under
// its lock; it is not safe for other concurrent use.
type Set struct {
	save    func(Record) error
	backups map[string]*member
}

type member struct {
	t   Target
	rec Record
}

var (
	ErrNoBackup  = errors.New("backup: no backup by that id in the set")
	ErrDuplicate = errors.New("backup: that backup is already in the set")
)

func NewSet(save func(Record) error) *Set {
	return &Set{save: save, backups: map[string]*member{}}
}

// Add puts a backup in the set: its Record as last saved and its target.
func (s *Set) Add(t Target, rec Record) error {
	if _, err := parseID(rec.BackupID); err != nil {
		return err
	}
	if s.backups[rec.BackupID] != nil {
		return ErrDuplicate
	}
	s.backups[rec.BackupID] = &member{t, rec}
	return nil
}

func (s *Set) List() []string { return slices.Sorted(maps.Keys(s.backups)) }

// Subjects is every subject a listed key table of backup may give.
func (s *Set) Subjects(backup string) []string {
	if m := s.backups[backup]; m != nil {
		return slices.Clone(m.rec.Subjects)
	}
	return nil
}

// Reseal rewraps backup's key table without the subjects st has erased,
// saving the new Record before it uses it. It returns nil once the target
// lists only a table without them (Rewrote, Unchanged), and otherwise the
// Result and its cause. When the new table is up but an older one remains
// (OldNotDeleted), the saved Record keeps the older table's subjects too,
// so the erased ones still read as given and the next Reseal, after a
// restart as well, writes and drops again.
func (s *Set) Reseal(backup string, keys kernel.Keys, st *kernel.State) error {
	m := s.backups[backup]
	if m == nil {
		return ErrNoBackup
	}
	next, out := Rewrap(m.t, m.rec, keys, st)
	if out.Result == OldNotDeleted {
		next.Subjects = slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(m.rec.Subjects), next.Subjects...))))
	}
	// Rewrap returns a new Record only with a new generation.
	if next.Generation != m.rec.Generation {
		if err := s.save(next); err != nil {
			return fmt.Errorf("backup: the re-sealed backup's record is not saved: %w", err)
		}
		m.rec = next
	}
	switch out.Result {
	case Rewrote, Unchanged:
		return nil
	}
	if out.Err != nil {
		return fmt.Errorf("%s: %w", out.Result, out.Err)
	}
	return errors.New(out.Result.String())
}
