package recovery

// REQ: CAP-3, A8

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// confirmable restores a backup holding forgets on a PC with no anchor
// for its log and returns where its state dir's log goes.
func unanchoredRestore(t *testing.T, opt Options, forgets ...time.Time) (string, *box) {
	t.Helper()
	x := newBox(t)
	pc := newPCCounter("host-a")
	for i, at := range forgets {
		forget(t, x, pc, "synthetic-goal-canary-"+string(rune('a'+i)), at)
	}
	bk := x.backup()
	rep, dst := restoreWith(t, bk, x.rk, opt)
	if rep.Pending != PendingUnanchored {
		t.Fatalf("pending %q", rep.Pending)
	}
	return filepath.Join(dst, lay.ForgetLog), x
}

func missingRestore(t *testing.T) string {
	t.Helper()
	x := newBox(t)
	must(t, x.b.V.Delete(ForgetLogName))
	rep, dst := restoreWith(t, x.backup(), x.rk, Options{Counter: newPCCounter("host-a")})
	if rep.Pending != PendingMissing {
		t.Fatalf("pending %q", rep.Pending)
	}
	return filepath.Join(dst, lay.ForgetLog)
}

// loadQ reads the question a held restore left at path, strictly, as
// agentosd does.
func loadQ(t *testing.T, path string) (Question, confirmFile) {
	t.Helper()
	if !held(t, path) {
		t.Fatal("not held")
	}
	f := readConfirm(t, path+ConfirmSuffix)
	q, err := f.question()
	must(t, err)
	return q, f
}

func readConfirm(t *testing.T, path string) confirmFile {
	t.Helper()
	raw, err := os.ReadFile(path)
	must(t, err)
	var f confirmFile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	must(t, d.Decode(&f))
	return f
}

// release does what agentosd does on the right answer (restoreconfirm.go):
// it hands the question's log on and lifts the hold.
func release(t *testing.T, path string, f confirmFile) {
	t.Helper()
	if f.Log != nil {
		must(t, os.WriteFile(path, f.Log, 0o600))
	}
	must(t, os.Remove(path+PendingSuffix))
	must(t, os.Remove(path+ConfirmSuffix))
}

func civil(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func held(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path + PendingSuffix)
	if err == nil {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("a held restore handed its log on: %v", err)
		}
		return true
	}
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return false
}

// D-065: a restore with no anchor asks the owner for the restored log's
// last-forget date among decoys, "later than all of these" and "never";
// the right date releases it and hands its log on for the replay.
func TestUnanchoredRestoreAsksForTheLastForgetDate(t *testing.T) {
	last := t0.Add(-100 * 24 * time.Hour)
	path, x := unanchoredRestore(t, Options{}, t0.Add(-300*24*time.Hour), last)
	q, f := loadQ(t, path)
	if q.Reason != PendingUnanchored || q.Closed || len(q.Dates) != 4 || q.Choices() != 6 ||
		q.Later() != 4 || q.Never() != 5 {
		t.Fatalf("question: %+v", q)
	}
	if !sort.SliceIsSorted(q.Dates, func(i, j int) bool { return q.Dates[i].Before(q.Dates[j]) }) {
		t.Fatalf("dates not in order: %v", q.Dates)
	}
	if f.Answer < 0 || f.Answer >= len(q.Dates) || !q.Dates[f.Answer].Equal(civil(last)) {
		t.Fatalf("answer %d of %v, want %v", f.Answer, q.Dates, civil(last))
	}
	for _, d := range q.Dates {
		if !d.Equal(civil(d)) || d.Location() != time.UTC {
			t.Fatalf("a date with more than day precision: %v", d)
		}
	}
	// The log the question hands on is the restored, authentic one.
	release(t, path, f)
	if gs := restoredGoals(t, x.rk, filepath.Dir(filepath.Dir(path))); len(gs) != 2 {
		t.Fatalf("handed on %v", gs)
	}
}

// D-071: a backup with no log (made before this release) gets the same
// confirmation under its own reason; its log holds no forget, so the
// right answer is "never".
func TestMissingLogRestoreAsksTheOwnerToo(t *testing.T) {
	path := missingRestore(t)
	q, f := loadQ(t, path)
	if q.Reason != PendingMissing || len(q.Dates) != 4 || f.Answer != q.Never() || f.Log != nil {
		t.Fatalf("question: %+v answer %d", q, f.Answer)
	}
}

// An unanchored log with no forget: "never" is right, and every date is
// a decoy.
func TestUnanchoredRestoreOfANeverForgotBox(t *testing.T) {
	path, _ := unanchoredRestore(t, Options{})
	q, f := loadQ(t, path)
	if len(q.Dates) != 4 || f.Answer != q.Never() {
		t.Fatalf("question: %+v answer %d", q, f.Answer)
	}
}

// D-071: the question carries the verified backups the restore command
// found that are newer than the restored one, newest first, so a wrong
// answer can offer one (agentosd's wrong-answer text).
func TestTheQuestionCarriesNewerVerifiedBackups(t *testing.T) {
	newer := []BackupEntry{
		{Destination: "Home NAS", Created: t0.Add(12 * time.Hour), Verified: true},
		{Destination: "Old USB", Created: t0.Add(-500 * 24 * time.Hour), Verified: true}, // older than this backup
		{Destination: "Spare drive", Created: t0.Add(30 * time.Hour)},                    // never read back
		{Destination: "Cloud box", Created: t0.Add(24 * time.Hour), Verified: true},
	}
	path, _ := unanchoredRestore(t, Options{Newer: newer}, t0.Add(-100*24*time.Hour))
	q, _ := loadQ(t, path)
	if len(q.Newer) != 2 || q.Newer[0].Destination != "Cloud box" || q.Newer[1].Destination != "Home NAS" {
		t.Fatalf("newer backups offered: %+v", q.Newer)
	}
	path = missingRestore(t)
	if q, _ := loadQ(t, path); len(q.Newer) != 0 {
		t.Fatalf("offered with none found: %+v", q.Newer)
	}
}

// L3 on #317 and D-065: the decoys are far apart, in the past, in the
// same format and precision, on both sides of the real date (so the real
// date is not always the latest), and in chronological order.
func TestDecoysAreFarApartAndOnBothSides(t *testing.T) {
	now := t0
	real := now.Add(-400 * 24 * time.Hour)
	l := forgetLog{Entries: []ForgetEntry{{At: real.Add(-90 * 24 * time.Hour)}, {At: real}}}
	positions := map[int]bool{}
	for seed := 0; seed < 64; seed++ {
		f, err := newQuestion(PendingUnanchored, l, true, now, nil, now, bytes.NewReader(bytes.Repeat([]byte{byte(seed * 37), byte(seed)}, 512)))
		must(t, err)
		q, err := f.question()
		must(t, err)
		if len(q.Dates) != 4 || !q.Dates[f.Answer].Equal(civil(real)) {
			t.Fatalf("seed %d: %v answer %d", seed, q.Dates, f.Answer)
		}
		positions[f.Answer] = true
		for i, d := range q.Dates {
			if d.After(civil(now)) {
				t.Fatalf("seed %d: a date after the restore: %v", seed, d)
			}
			if i > 0 && d.Sub(q.Dates[i-1]) < decoyGap*24*time.Hour {
				t.Fatalf("seed %d: dates too close: %v", seed, q.Dates)
			}
		}
	}
	if len(positions) != 4 {
		t.Fatalf("the real date sat only at %v", positions)
	}
	// A recent last forget leaves no room after it: the decoys go before.
	recent := forgetLog{Entries: []ForgetEntry{{At: now.Add(-24 * time.Hour)}}}
	f, err := newQuestion(PendingUnanchored, recent, true, now, nil, now, nil)
	must(t, err)
	if q, _ := f.question(); f.Answer != 3 || q.Dates[3].After(civil(now)) {
		t.Fatalf("recent: %v answer %d", q.Dates, f.Answer)
	}
}

// The dates are the owner's calendar days: the box's zone, not UTC.
func TestDatesAreTheBoxsCalendarDays(t *testing.T) {
	zone := time.FixedZone("UTC-8", -8*3600)
	at := time.Date(2026, 3, 15, 3, 0, 0, 0, time.UTC) // 14 Mar in that zone
	l := forgetLog{Entries: []ForgetEntry{{At: at}}}
	f, err := newQuestion(PendingUnanchored, l, true, t0.In(zone), nil, t0, nil)
	must(t, err)
	q, _ := f.question()
	if want := time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC); !q.Dates[f.Answer].Equal(want) {
		t.Fatalf("got %v, want %v", q.Dates[f.Answer], want)
	}
}

// Only the no-anchor and no-log cases are the owner's to confirm: a
// rolled-back or forged log stays held with no question.
func TestRolledBackOrForgedRestoresAskNothing(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	bk := x.backup()
	forget(t, x, pc, "goal-1", t0)
	dst := pendingRestore(t, bk, x.rk, Options{Counter: pc}, PendingRolledBack)
	path := filepath.Join(dst, lay.ForgetLog)
	if _, err := os.Stat(path + ConfirmSuffix); !os.IsNotExist(err) {
		t.Fatalf("a rolled-back restore asks: %v", err)
	}
}

// The unanchored restore keeps the longest authentic copy, so a confirmed
// restore replays forgets a newer destination copy holds, and the vault
// carries them on.
func TestUnanchoredRestoreKeepsTheNewestCopy(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	bk := x.backup()
	cp := forget(t, x, pc, "goal-1", t0.Add(-50*24*time.Hour))
	rep, dst := restoreWith(t, bk, x.rk, Options{ForgetLogs: [][]byte{cp}})
	if rep.Pending != PendingUnanchored {
		t.Fatalf("pending %q", rep.Pending)
	}
	path := filepath.Join(dst, lay.ForgetLog)
	_, f := loadQ(t, path)
	if f.Answer >= 4 {
		t.Fatalf("the copy's forget was dropped: answer %d", f.Answer)
	}
	nb := openAt(t, dst, x.rk)
	l, ok, err := loadForgetLog(nb.V)
	if err != nil || !ok || len(l.Entries) != 1 {
		t.Fatalf("vault log: %+v %v %v", l, ok, err)
	}
	nb.V.Close()
	release(t, path, f)
	if gs := restoredGoals(t, x.rk, dst); len(gs) != 1 || gs[0] != "goal-1" {
		t.Fatalf("handed on %v", gs)
	}
}

// The writer refuses a question that does not hold together, so agentosd
// never reads one that the restore made.
func TestTheWriterRefusesAMalformedQuestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forget-log.json")
	for _, f := range []confirmFile{
		{Format: "x", Reason: PendingMissing, Dates: []string{"2026-01-01"}, Answer: 2},
		{Format: confirmFmt, Reason: PendingForged, Dates: []string{"2026-01-01"}, Answer: 0},
		{Format: confirmFmt, Reason: PendingMissing, Dates: []string{"2026-02-01", "2026-01-01"}, Answer: 0},
		{Format: confirmFmt, Reason: PendingMissing, Dates: []string{"2026-01-01"}, Answer: 1}, // "later" is never right
		{Format: confirmFmt, Reason: PendingMissing, Dates: []string{"2026-01-01"}, Answer: 7},
	} {
		if err := writeQuestion(path, f); err == nil {
			t.Fatalf("%+v written", f)
		}
	}
}

// testdata/confirm-v1.json is the format agentosd's tests read
// (restoreconfirm_test.go): it decodes strictly here, holds together, and
// carries every field the writer emits, so the two sides cannot drift.
func TestTheConfirmFixtureIsTheWritersFormat(t *testing.T) {
	f := readConfirm(t, filepath.Join("testdata", "confirm-v1.json"))
	if _, err := f.question(); err != nil || f.Log == nil || len(f.Newer) == 0 {
		t.Fatalf("fixture: %v", err)
	}
	keys := func(v any) map[string]bool {
		raw, err := json.Marshal(v)
		must(t, err)
		var m map[string]json.RawMessage
		must(t, json.Unmarshal(raw, &m))
		out := map[string]bool{}
		for k := range m {
			out[k] = true
		}
		return out
	}
	path, _ := unanchoredRestore(t, Options{Newer: []BackupEntry{{Destination: "Cloud box", Created: t0.Add(time.Hour), Verified: true}}}, t0.Add(-100*24*time.Hour))
	_, w := loadQ(t, path)
	w.Closed = true
	raw, err := os.ReadFile(filepath.Join("testdata", "confirm-v1.json"))
	must(t, err)
	var fx map[string]json.RawMessage
	must(t, json.Unmarshal(raw, &fx))
	for k := range keys(w) {
		if _, ok := fx[k]; !ok {
			t.Errorf("the fixture lacks %q", k)
		}
	}
	nb := keys(w.Newer[0])
	for k := range keys(f.Newer[0]) {
		if !nb[k] {
			t.Errorf("the fixture's backup has %q, which the writer does not", k)
		}
	}
}

// D-071: a restore on the same PC, whose TPM counter anchors the log,
// needs no confirmation: no hold, no question.
func TestAnAnchoredRestoreAsksNothing(t *testing.T) {
	x := newBox(t)
	pc := newPCCounter("host-a")
	forget(t, x, pc, "synthetic-goal-canary-a", t0.Add(-100*24*time.Hour))
	rep, dst := restoreWith(t, x.backup(), x.rk, Options{Counter: pc})
	path := filepath.Join(dst, lay.ForgetLog)
	if rep.Pending != "" || held(t, path) {
		t.Fatalf("pending %q", rep.Pending)
	}
	if _, err := os.Stat(path + ConfirmSuffix); !os.IsNotExist(err) {
		t.Fatalf("an anchored restore asks: %v", err)
	}
}
