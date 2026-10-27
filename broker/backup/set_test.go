package backup

// REQ: LOG-4, BAK-1

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// saved is a Set's Save that keeps every record and can be made to fail.
type saved struct {
	recs map[string]Record
	fail bool
}

func (s *saved) save(r Record) error {
	if s.fail {
		return errDown
	}
	s.recs[r.BackupID] = r
	return nil
}

func newSaved() *saved { return &saved{recs: map[string]Record{}} }

// held is backup's Record as set holds it.
func held(set *Set, backup string) (Record, bool) {
	if m := set.backups[backup]; m != nil {
		return m.rec, true
	}
	return Record{}, false
}

// setRig is a rig with three live subjects and one backup of them on each
// of the given targets, in a Set the kernel has open.
func setRig(t *testing.T, tgs ...Target) (*rig, []string, *Set, *saved, []Record) {
	t.Helper()
	r, subs, _ := threeLive(t)
	sv := newSaved()
	set := NewSet(sv.save)
	var recs []Record
	for _, tg := range tgs {
		rec, _ := r.backup(recipient(t, rk1), tg)
		must(t, set.Add(tg, rec))
		recs = append(recs, rec)
	}
	r.k.OpenBackups(set)
	return r, subs, set, sv, recs
}

// eraseNow erases sub as the kernel process does: the erase, then each
// backup re-seal it made due, then the confirmation again.
func (r *rig) eraseNow(now int64, sub string) (kernel.Confirmation, error) {
	c, err := r.k.Erase(now, sub)
	r.k.ResealBackups(now)
	return r.k.Confirm(c), err
}

// An erase through the kernel re-seals every backup it can rewrite, saves
// its new record and names the append-only one as still holding the
// subject (D-168, LOG-4).
func TestAnEraseResealsEveryBackupItCan(t *testing.T) {
	tg, ao := &MemTarget{}, &MemTarget{Append: true}
	r, subs, set, sv, recs := setRig(t, tg, ao)
	c, err := r.eraseNow(3, subs[1])
	must(t, err)
	if !reflect.DeepEqual(c.Resealed, []string{recs[0].BackupID}) ||
		!reflect.DeepEqual(c.StillHeld, []kernel.BackupHold{{Backup: recs[1].BackupID, Why: "append-only"}}) {
		t.Fatalf("confirmation %+v", c)
	}
	next, ok := held(set, recs[0].BackupID)
	if !ok || next.Generation != recs[0].Generation+1 || slices.Contains(next.Subjects, subs[1]) || !reflect.DeepEqual(sv.recs[next.BackupID], next) {
		t.Fatalf("record %+v, saved %+v", next, sv.recs[next.BackupID])
	}
	if g := tables(t, tg, next.BackupID); !slices.Equal(g, []uint64{next.Generation}) {
		t.Fatalf("target lists %v", g)
	}
	if got := unwrapped(t, tg, next, next.Generation, rk1); len(got.M) != 2 || got.M[subs[1]] != (kernel.SubjectKey{}) {
		t.Fatalf("the re-sealed table gives %d keys", len(got.M))
	}
	if _, ok := sv.recs[recs[1].BackupID]; ok {
		t.Fatal("the append-only backup's record changed")
	}
}

// A destination that is down is named with why, and re-sealed by a later
// Tick once it is back.
func TestADownDestinationIsResealedLater(t *testing.T) {
	tg := &target{failGet: true}
	r, subs, set, _, recs := setRig(t, tg)
	c, err := r.eraseNow(3, subs[0])
	must(t, err)
	if len(c.StillHeld) != 1 || !strings.HasPrefix(c.StillHeld[0].Why, "offline") {
		t.Fatalf("confirmation %+v", c)
	}
	tg.failGet = false
	must(t, r.k.Tick(3+kernel.RetryMin))
	if rec, _ := held(set, recs[0].BackupID); slices.Contains(rec.Subjects, subs[0]) {
		t.Fatal("not re-sealed once the destination is back")
	}
	if g := tables(t, tg, recs[0].BackupID); len(g) != 1 {
		t.Fatalf("target lists %v", g)
	}
}

// When the new table is up but the old one is not deleted, the saved
// record still lists the erased subject, so it is retried, after a
// restart too, until only the new table is left.
func TestAnOldTableLeftKeepsTheBackupOwing(t *testing.T) {
	tg := &target{failDelete: true}
	r, subs, set, sv, recs := setRig(t, tg)
	id := recs[0].BackupID
	c, err := r.eraseNow(3, subs[2])
	must(t, err)
	if len(c.StillHeld) != 1 || !strings.HasPrefix(c.StillHeld[0].Why, "old-not-deleted") {
		t.Fatalf("confirmation %+v", c)
	}
	rec := sv.recs[id]
	if rec.Generation != recs[0].Generation+1 || !slices.Contains(rec.Subjects, subs[2]) {
		t.Fatalf("saved %+v", rec)
	}
	// A restart: a fresh kernel, and a fresh Set from the saved record.
	tg.failDelete = false
	r.boot(r.log, r.keys)
	set = NewSet(sv.save)
	must(t, set.Add(tg, rec))
	r.k.OpenBackups(set)
	r.k.ResealBackups(4)
	rec, _ = held(set, id)
	if slices.Contains(rec.Subjects, subs[2]) || len(tables(t, tg, id)) != 1 || !reflect.DeepEqual(sv.recs[id], rec) {
		t.Fatalf("after the restart: %+v, tables %v", rec, tables(t, tg, id))
	}
}

// A record that cannot be saved is not used: the backup stays owing and
// the next try rewraps again and drops the table it put.
func TestAnUnsavedRecordIsNotUsed(t *testing.T) {
	tg := &MemTarget{}
	r, subs, set, sv, recs := setRig(t, tg)
	sv.fail = true
	c, err := r.eraseNow(3, subs[0])
	must(t, err)
	if len(c.StillHeld) != 1 || !strings.Contains(c.StillHeld[0].Why, "not saved") {
		t.Fatalf("confirmation %+v", c)
	}
	if rec, _ := held(set, recs[0].BackupID); !reflect.DeepEqual(rec, recs[0]) {
		t.Fatal("the set uses a record it could not save")
	}
	sv.fail = false
	must(t, r.k.Tick(3+kernel.RetryMin))
	rec, _ := held(set, recs[0].BackupID)
	if slices.Contains(rec.Subjects, subs[0]) || !slices.Equal(tables(t, tg, rec.BackupID), []uint64{rec.Generation}) {
		t.Fatalf("after the retry: %+v, tables %v", rec, tables(t, tg, rec.BackupID))
	}
}

func TestASetRefusesABadOrRepeatedBackup(t *testing.T) {
	set := NewSet(newSaved().save)
	if err := set.Add(&MemTarget{}, Record{BackupID: "nope"}); err == nil {
		t.Fatal("a bad id was added")
	}
	rec := Record{BackupID: strings.Repeat("ab", idLen)}
	must(t, set.Add(&MemTarget{}, rec))
	if err := set.Add(&MemTarget{}, rec); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("a repeated backup: %v", err)
	}
	if _, err := set.Prepare("cd", nil, nil); !errors.Is(err, ErrNoBackup) {
		t.Fatalf("an unknown backup: %v", err)
	}
}
