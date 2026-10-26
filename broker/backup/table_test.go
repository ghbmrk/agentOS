package backup

// REQ: BAK-1, LOG-4, REC-1

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/proc"
)

// spyKeys fails the test on any write to the live table, and can hide a
// listed key from Get.
type spyKeys struct {
	t *testing.T
	kernel.Keys
	hide string
}

func (s *spyKeys) Put(string, kernel.SubjectKey) error {
	s.t.Error("backup called Put on the live key table")
	return errDown
}

func (s *spyKeys) Delete(string) error {
	s.t.Error("backup called Delete on the live key table")
	return errDown
}

func (s *spyKeys) Get(sub string) (kernel.SubjectKey, bool, error) {
	if sub == s.hide {
		return kernel.SubjectKey{}, false, nil
	}
	return s.Keys.Get(sub)
}

// target is a MemTarget whose calls can be made to fail.
type target struct {
	MemTarget
	failPut, failGet, corruptGet, failDelete bool
	// keepOnDelete makes DeleteTable report success and keep the table.
	keepOnDelete bool
	puts         int
}

func (t *target) PutTable(id string, gen uint64, b []byte) error {
	t.puts++
	if t.failPut {
		return errDown
	}
	return t.MemTarget.PutTable(id, gen, b)
}

func (t *target) GetTable(id string, gen uint64) ([]byte, error) {
	if t.failGet {
		return nil, errDown
	}
	b, err := t.MemTarget.GetTable(id, gen)
	if t.corruptGet && len(b) > 0 {
		b[len(b)-1] ^= 1
	}
	return b, err
}

func (t *target) DeleteTable(id string, gen uint64) error {
	if t.failDelete {
		return errDown
	}
	if t.keepOnDelete {
		return nil
	}
	return t.MemTarget.DeleteTable(id, gen)
}

// threeLive is a rig with three live subjects, each with one mail item.
func threeLive(t *testing.T) (*rig, []string, []kernel.Hash) {
	r := newRig(t)
	var subs []string
	var items []kernel.Hash
	for i := range 3 {
		s := r.open()
		subs = append(subs, s)
		items = append(items, r.seal(s, "item "+string(rune('a'+i))))
	}
	return r, subs, items
}

func TestErasedAndUnnamedSubjectsAreLeftOut(t *testing.T) {
	r := newRig(t)
	live, gone := r.open(), r.open()
	r.keys.failDelete = true
	r.erase(gone)
	r.keys.failDelete = false
	if _, ok, _ := r.keys.Get(gone); !ok {
		t.Fatal("fixture: the erased subject's key should still be in the table")
	}
	unnamed := strings.Repeat("ab", 16)
	must(t, r.keys.Put(unnamed, kernel.SubjectKey{1}))

	tg := &MemTarget{}
	rec, _ := r.backup(recipient(t, rk1), tg)
	if !slices.Equal(rec.Subjects, []string{live}) {
		t.Fatalf("record subjects %v, want only %s", rec.Subjects, live)
	}
	got := unwrapped(t, tg, rec, rec.Generation, rk1)
	if l, _ := got.List(); !slices.Equal(l, []string{live}) {
		t.Fatalf("table holds %v, want only %s", l, live)
	}
	want, _, _ := r.keys.Get(live)
	if got.M[live] != want {
		t.Fatal("the live subject's key did not round-trip")
	}
}

func TestALiveMissingKeyFailsWrite(t *testing.T) {
	r, subs, _ := threeLive(t)
	in := r.input(recipient(t, rk1))
	in.Keys = &spyKeys{t: t, Keys: r.keys, hide: subs[1]}
	tg := &target{}
	var buf bytes.Buffer
	_, err := Write(&buf, tg, in)
	if !errors.Is(err, ErrLiveKeyMissing) || !strings.Contains(err.Error(), subs[1]) {
		t.Fatalf("Write: %v, want ErrLiveKeyMissing naming %s", err, subs[1])
	}
	if buf.Len() != 0 || tg.puts != 0 {
		t.Fatal("a refused backup wrote something")
	}
}

func TestTableNeverUsesTheLogKey(t *testing.T) {
	r, subs, _ := threeLive(t)
	r.erase(subs[0])
	in := r.input(recipient(t, rk1))
	spy := &spyKeys{t: t, Keys: r.keys}
	in.Keys = spy
	tg := &MemTarget{}
	rec, err := Write(&bytes.Buffer{}, tg, in)
	must(t, err)
	// Rewrap reads the live table through the spy too.
	r.erase(subs[1])
	rec2, out := Rewrap(tg, rec, spy, r.k.State())
	if out.Result != Rewrote {
		t.Fatalf("Rewrap: %v %v", out.Result, out.Err)
	}

	b, err := aes.NewCipher(logKeyCanary[:])
	must(t, err)
	logAEAD, err := cipher.NewGCM(b)
	must(t, err)
	dir := filepath.Join(t.TempDir(), "keys")
	fk, err := proc.OpenFileKeys(dir, logKeyCanary)
	must(t, err)
	for _, gen := range []uint64{rec.Generation, rec2.Generation} {
		obj, err := tg.GetTable(rec.BackupID, gen)
		if err != nil {
			continue // the old generation is gone
		}
		for off := 0; off+12+16 <= len(obj); off += 1 {
			if off > headerLen+64 {
				break
			}
			for _, sub := range append(slices.Clone(subs), "") {
				aad := []byte("agentos.keytable.v1\x00" + sub)
				if _, err := logAEAD.Open(nil, obj[off:off+12], obj[off+12:], aad); err == nil {
					t.Fatalf("a table opens under the log key at %d", off)
				}
			}
		}
		// As a FileKeys file, the table does not open either.
		must(t, os.WriteFile(filepath.Join(dir, subs[2]+".key"), obj, 0o600))
		if _, _, err := fk.Get(subs[2]); err == nil {
			t.Fatal("a table object opens as a FileKeys key")
		}
	}
}

func TestRewrapDropsTheSubjectAndTheOldTable(t *testing.T) {
	r, subs, _ := threeLive(t)
	tg := &MemTarget{}
	rec, _ := r.backup(recipient(t, rk1), tg)
	old, err := tg.GetTable(rec.BackupID, rec.Generation)
	must(t, err)
	r.erase(subs[1])

	next, out := Rewrap(tg, rec, r.keys, r.k.State())
	if out.Result != Rewrote || out.Err != nil {
		t.Fatalf("Rewrap: %v %v", out.Result, out.Err)
	}
	if next.Generation != rec.Generation+1 || !slices.Equal(next.Subjects, slices.Sorted(slices.Values([]string{subs[0], subs[2]}))) ||
		next.BackupID != rec.BackupID || next.ContentSum != rec.ContentSum {
		t.Fatalf("new record: generation %d, subjects %v", next.Generation, next.Subjects)
	}
	if g := tables(t, tg, rec.BackupID); !slices.Equal(g, []uint64{next.Generation}) {
		t.Fatalf("target lists %v", g)
	}
	if _, err := tg.GetTable(rec.BackupID, rec.Generation); err == nil {
		t.Fatal("the old table is still there")
	}
	for _, b := range tg.m[rec.BackupID] {
		if bytes.Equal(b, old) {
			t.Fatal("the old table's bytes are still there")
		}
	}
	got := unwrapped(t, tg, next, next.Generation, rk1)
	if _, ok := got.M[subs[1]]; ok || len(got.M) != 2 {
		t.Fatalf("the new table holds %v", slices.Sorted(maps.Keys(got.M)))
	}
	if b, _ := tg.GetTable(next.BackupID, next.Generation); sumHex(b) != next.TableSum {
		t.Fatal("the record's table sum is not the table's")
	}
}

func TestRewrapSealsToTheBackupsOwnRecipient(t *testing.T) {
	r, subs, _ := threeLive(t)
	tg := &MemTarget{}
	rec, _ := r.backup(recipient(t, rk1), tg)
	// The owner rotates the recovery key; the box now stores rk2's
	// recipient, but this backup's content opens only with rk1.
	_ = recipient(t, rk2)
	r.erase(subs[0])
	next, out := Rewrap(tg, rec, r.keys, r.k.State())
	if out.Result != Rewrote {
		t.Fatalf("Rewrap: %v %v", out.Result, out.Err)
	}
	b, err := tg.GetTable(next.BackupID, next.Generation)
	must(t, err)
	if _, err := UnwrapTable(bytes.NewReader(b), rk2, next.BackupID, kernel.NewMemKeys()); !errors.Is(err, ErrRecipient) {
		t.Fatalf("the new recovery key: %v, want ErrRecipient", err)
	}
	if n, err := UnwrapTable(bytes.NewReader(b), rk1, next.BackupID, kernel.NewMemKeys()); err != nil || n != 2 {
		t.Fatalf("the backup's own recovery key: %d, %v", n, err)
	}
}

func TestRewrapOutcomes(t *testing.T) {
	setup := func(t *testing.T) (*rig, []string, *target, Record) {
		r, subs, _ := threeLive(t)
		tg := &target{}
		rec, _ := r.backup(recipient(t, rk1), tg)
		return r, subs, tg, rec
	}
	holdsErased := func(t *testing.T, tg *target, rec Record, sub string) bool {
		for _, g := range tables(t, &tg.MemTarget, rec.BackupID) {
			if _, ok := unwrapped(t, &tg.MemTarget, rec, g, rk1).M[sub]; ok {
				return true
			}
		}
		return false
	}

	t.Run("unchanged", func(t *testing.T) {
		r, _, tg, rec := setup(t)
		puts := tg.puts
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != Unchanged || !sameRecord(next, rec) || tg.puts != puts {
			t.Fatalf("%v, wrote %d", out.Result, tg.puts-puts)
		}
	})
	failing := []struct {
		name string
		set  func(*target)
		want Result
	}{
		{"append-only", func(tg *target) { tg.Append = true }, AppendOnly},
		{"offline put", func(tg *target) { tg.failPut = true }, Offline},
		{"offline read-back", func(tg *target) { tg.failGet = true }, Offline},
		{"read-back mismatch", func(tg *target) { tg.corruptGet = true }, ReadBackMismatch},
	}
	for _, c := range failing {
		t.Run(c.name, func(t *testing.T) {
			r, subs, tg, rec := setup(t)
			r.erase(subs[1])
			puts := tg.puts
			c.set(tg)
			next, out := Rewrap(tg, rec, r.keys, r.k.State())
			if out.Result != c.want || !sameRecord(next, rec) {
				t.Fatalf("%v (%v), want %v and rec returned", out.Result, out.Err, c.want)
			}
			if c.want == AppendOnly && tg.puts != puts {
				t.Fatal("append-only target was written")
			}
		})
	}
	t.Run("live key missing", func(t *testing.T) {
		r, subs, tg, rec := setup(t)
		r.erase(subs[1])
		next, out := Rewrap(tg, rec, &spyKeys{t: t, Keys: r.keys, hide: subs[2]}, r.k.State())
		if out.Result != LiveKeyMissing || !sameRecord(next, rec) || !strings.Contains(out.Err.Error(), subs[2]) {
			t.Fatalf("%v %v", out.Result, out.Err)
		}
	})
	t.Run("old not deleted, then finished", func(t *testing.T) {
		r, subs, tg, rec := setup(t)
		r.erase(subs[1])
		tg.failDelete = true
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != OldNotDeleted || next.Generation != rec.Generation+1 || slices.Contains(next.Subjects, subs[1]) {
			t.Fatalf("%v, generation %d, subjects %v", out.Result, next.Generation, next.Subjects)
		}
		if !holdsErased(t, tg, rec, subs[1]) {
			t.Fatal("fixture: the old table should still hold the subject")
		}
		tg.failDelete = false
		again, out := Rewrap(tg, next, r.keys, r.k.State())
		if out.Result != Rewrote {
			t.Fatalf("second run: %v %v, want Rewrote", out.Result, out.Err)
		}
		if !sameRecord(again, next) || holdsErased(t, tg, rec, subs[1]) {
			t.Fatal("the erased subject is still in a listed table")
		}
		if g := tables(t, &tg.MemTarget, rec.BackupID); !slices.Equal(g, []uint64{next.Generation}) {
			t.Fatalf("lists %v", g)
		}
	})
	t.Run("strays only", func(t *testing.T) {
		r, _, tg, rec := setup(t)
		stray, err := tg.GetTable(rec.BackupID, rec.Generation)
		must(t, err)
		must(t, tg.MemTarget.PutTable(rec.BackupID, rec.Generation+1, stray))
		puts := tg.puts
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != Rewrote || !sameRecord(next, rec) || tg.puts != puts {
			t.Fatalf("%v %v, puts %d", out.Result, out.Err, tg.puts-puts)
		}
		if g := tables(t, &tg.MemTarget, rec.BackupID); !slices.Equal(g, []uint64{rec.Generation}) {
			t.Fatalf("lists %v", g)
		}
	})
	// A delete that reports success but keeps the table is caught by the
	// list after it: never Rewrote, since slice d shows that to the owner.
	t.Run("delete says done, table stays", func(t *testing.T) {
		r, subs, tg, rec := setup(t)
		r.erase(subs[1])
		tg.keepOnDelete = true
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != OldNotDeleted || out.Err == nil || next.Generation != rec.Generation+1 {
			t.Fatalf("%v %v, generation %d", out.Result, out.Err, next.Generation)
		}
		if !holdsErased(t, tg, rec, subs[1]) {
			t.Fatal("fixture: the old table should still hold the subject")
		}
	})
	t.Run("strays only, delete says done, stray stays", func(t *testing.T) {
		r, _, tg, rec := setup(t)
		stray, _ := tg.GetTable(rec.BackupID, rec.Generation)
		must(t, tg.MemTarget.PutTable(rec.BackupID, rec.Generation+1, stray))
		tg.keepOnDelete = true
		if _, out := Rewrap(tg, rec, r.keys, r.k.State()); out.Result != OldNotDeleted || out.Err == nil {
			t.Fatalf("%v %v", out.Result, out.Err)
		}
	})
	t.Run("generation spent", func(t *testing.T) {
		r, subs, tg, rec := setup(t)
		stray, _ := tg.GetTable(rec.BackupID, rec.Generation)
		must(t, tg.MemTarget.PutTable(rec.BackupID, math.MaxUint64, stray))
		r.erase(subs[1])
		puts := tg.puts
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != GenerationSpent || out.Err == nil || !sameRecord(next, rec) || tg.puts != puts {
			t.Fatalf("%v %v, puts %d", out.Result, out.Err, tg.puts-puts)
		}
		if out.Result.String() != "generation-spent" {
			t.Fatal(out.Result.String())
		}
	})
	t.Run("strays only, delete fails", func(t *testing.T) {
		r, _, tg, rec := setup(t)
		stray, _ := tg.GetTable(rec.BackupID, rec.Generation)
		must(t, tg.MemTarget.PutTable(rec.BackupID, rec.Generation+1, stray))
		tg.failDelete = true
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != OldNotDeleted || !sameRecord(next, rec) {
			t.Fatalf("%v", out.Result)
		}
	})
	t.Run("a stray at the next generation", func(t *testing.T) {
		r, subs, tg, rec := setup(t)
		stray, _ := tg.GetTable(rec.BackupID, rec.Generation)
		must(t, tg.MemTarget.PutTable(rec.BackupID, rec.Generation+1, stray))
		r.erase(subs[1])
		next, out := Rewrap(tg, rec, r.keys, r.k.State())
		if out.Result != Rewrote || next.Generation != rec.Generation+2 {
			t.Fatalf("%v, generation %d, want %d", out.Result, next.Generation, rec.Generation+2)
		}
		if g := tables(t, &tg.MemTarget, rec.BackupID); !slices.Equal(g, []uint64{next.Generation}) {
			t.Fatalf("lists %v", g)
		}
		if holdsErased(t, tg, rec, subs[1]) {
			t.Fatal("the erased subject is still in a listed table")
		}
	})
}

func sameRecord(a, b Record) bool {
	return a.BackupID == b.BackupID && a.Generation == b.Generation && slices.Equal(a.Subjects, b.Subjects) &&
		a.TableSum == b.TableSum && a.ContentSum == b.ContentSum && a.Recipient.ID() == b.Recipient.ID() && a.Created == b.Created
}

func TestACrashBetweenPutAndDeleteIsFinishedNextTime(t *testing.T) {
	r, subs, _ := threeLive(t)
	tg := &target{}
	rec, _ := r.backup(recipient(t, rk1), tg)
	r.erase(subs[0])
	// The target goes away after the put: the read-back fails, so the
	// caller keeps rec while generation 2 is already up.
	tg.failGet = true
	kept, out := Rewrap(tg, rec, r.keys, r.k.State())
	if out.Result == Rewrote || !sameRecord(kept, rec) {
		t.Fatalf("%v, want not Rewrote and rec", out.Result)
	}
	if g := tables(t, &tg.MemTarget, rec.BackupID); len(g) != 2 {
		t.Fatalf("fixture: lists %v", g)
	}
	tg.failGet = false
	next, out := Rewrap(tg, kept, r.keys, r.k.State())
	if out.Result != Rewrote || next.Generation != rec.Generation+2 {
		t.Fatalf("%v %v, generation %d", out.Result, out.Err, next.Generation)
	}
	if g := tables(t, &tg.MemTarget, rec.BackupID); !slices.Equal(g, []uint64{next.Generation}) {
		t.Fatalf("both older generations should be gone: %v", g)
	}
}

func TestUnwrapIntoAFreshFileKeys(t *testing.T) {
	r, subs, items := threeLive(t)
	tg := DirTarget{Dir: t.TempDir()}
	rec, content := r.backup(recipient(t, rk1), tg)
	m, _, err := Open(bytes.NewReader(content), rk1)
	must(t, err)

	// After the backup, subs[1] is erased: the restored log has the later
	// subject.erased appended.
	r.erase(subs[1])
	laterLog := &kernel.MemStore{B: bytes.Clone(r.log.B)}

	obj, err := tg.GetTable(rec.BackupID, rec.Generation)
	must(t, err)
	fk, err := proc.OpenFileKeys(filepath.Join(t.TempDir(), "keys"), logKeyCanary)
	must(t, err)
	n, err := UnwrapTable(bytes.NewReader(obj), rk1, m.BackupID, fk)
	if err != nil || n != 3 {
		t.Fatalf("UnwrapTable: %d, %v", n, err)
	}
	if _, ok, _ := fk.Get(subs[1]); !ok {
		t.Fatal("fixture: the backup's table should hold subs[1]")
	}
	rep := r.boot(laterLog, fk)
	if len(rep.Missing) != 0 {
		t.Fatalf("restored keys missing: %v", rep.Missing)
	}
	if _, ok, _ := fk.Get(subs[1]); ok {
		t.Fatal("OpenContent left the erased subject's key")
	}
	for _, i := range []int{0, 2} {
		if _, err := r.k.Read(items[i]); err != nil {
			t.Fatalf("subject %d's item does not read: %v", i, err)
		}
	}

	// A non-empty destination and another backup's table are refused.
	if _, err := UnwrapTable(bytes.NewReader(obj), rk1, m.BackupID, fk); !errors.Is(err, ErrNotEmpty) {
		t.Fatalf("non-empty dst: %v", err)
	}
	if _, err := UnwrapTable(bytes.NewReader(obj), rk1, strings.Repeat("0", 32), kernel.NewMemKeys()); !errors.Is(err, ErrOtherBackup) {
		t.Fatalf("another backup id: %v", err)
	}
	other, _ := r.backup(recipient(t, rk1), DirTarget{Dir: t.TempDir()})
	if _, err := UnwrapTable(bytes.NewReader(obj), rk1, other.BackupID, kernel.NewMemKeys()); !errors.Is(err, ErrOtherBackup) {
		t.Fatalf("another backup's id: %v", err)
	}
}

// tableObject seals a key table white-box: header generation gen, body
// generation bodyGen.
func tableObject(t *testing.T, rcp Recipient, id string, gen, bodyGen uint64, es []entry) []byte {
	t.Helper()
	bid, err := parseID(id)
	must(t, err)
	pt, err := json.Marshal(table{BackupID: id, Generation: bodyGen, Entries: es})
	must(t, err)
	return sealBytes(t, rcp, KindKeyTable, bid, gen, pt)
}

func TestUnwrapRefusesABadTable(t *testing.T) {
	rcp := recipient(t, rk1)
	id := strings.Repeat("cd", idLen)
	a, b := strings.Repeat("a", 32), strings.Repeat("b", 32)
	es := []entry{{a, kernel.SubjectKey{1}}, {b, kernel.SubjectKey{2}}}
	// The control: a well-formed table unwraps.
	dst := kernel.NewMemKeys()
	if n, err := UnwrapTable(bytes.NewReader(tableObject(t, rcp, id, 2, 2, es)), rk1, id, dst); err != nil || n != 2 {
		t.Fatalf("control: %d, %v", n, err)
	}
	cases := []struct {
		name         string
		gen, bodyGen uint64
		es           []entry
		want         error
	}{
		{"body generation is not the header's", 2, 1, es, ErrOtherBackup},
		{"header generation is not the body's", 1, 2, es, ErrOtherBackup},
		{"subject not hex", 2, 2, []entry{{a, kernel.SubjectKey{1}}, {"NOT-A-SUBJECT", kernel.SubjectKey{2}}}, nil},
		{"subject upper case", 2, 2, []entry{{strings.Repeat("A", 32), kernel.SubjectKey{1}}}, nil},
		{"subject repeated", 2, 2, []entry{{a, kernel.SubjectKey{1}}, {a, kernel.SubjectKey{2}}}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := kernel.NewMemKeys()
			n, err := UnwrapTable(bytes.NewReader(tableObject(t, rcp, id, c.gen, c.bodyGen, c.es)), rk1, id, dst)
			if err == nil || n != 0 || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("%d, %v, want %v", n, err, c.want)
			}
			if have, _ := dst.List(); len(have) != 0 {
				t.Fatalf("a refused table put %v", have)
			}
		})
	}
}
