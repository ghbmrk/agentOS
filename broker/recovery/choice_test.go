package recovery

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: BAK-1

var tier4 = Auth{Code: true, Local: true}

// backedUp writes a backup, reads it back intact, and logs it.
func backedUp(t *testing.T, x *box, dest string, at time.Time) {
	t.Helper()
	var buf bytes.Buffer
	rc, err := BackupSum(x.b, x.roots(), &buf, at)
	must(t, err)
	e, err := RecordBackup(x.b, dest, rc, bytes.NewReader(buf.Bytes()))
	must(t, err)
	if !e.Verified {
		t.Fatal("an intact read-back is not verified")
	}
}

// A new box has no backup unless the owner chooses one, and says plainly
// that the drive is the only copy.
func TestNoBackupByDefaultAndTheDriveIsTheOnlyCopy(t *testing.T) {
	x := newBox(t)
	c, err := LoadBackupChoice(x.b)
	must(t, err)
	if c.Kind != BackupUnchosen || c.Destination != "" {
		t.Fatalf("a new box has a backup chosen: %+v", c)
	}
	n, err := OnlyCopyNotice(x.b)
	must(t, err)
	if n != NoticeUnchosen {
		t.Fatalf("notice: %q", n)
	}
	if !strings.Contains(n, "only copy") || !strings.Contains(n, "a second drive, or storage you already have") {
		t.Fatalf("notice is not plain about the choice: %q", n)
	}
}

// The owner chooses a second local drive or storage they already have;
// until a backup there is verified, the drive is still the only copy.
func TestOwnerChoosesADriveOrTheirOwnStorage(t *testing.T) {
	for _, k := range []BackupKind{BackupDrive, BackupUpload} {
		t.Run(string(k), func(t *testing.T) {
			x := newBox(t)
			ch := BackupChoice{Kind: k, Destination: "  Home NAS  "}
			for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: mustKey(t)}} {
				if _, err := ChooseBackup(x.b, ch, a, t0); !errors.Is(err, ErrNotAuthorized) {
					t.Fatalf("auth %+v: %v", a, err)
				}
			}
			n, err := ChooseBackup(x.b, ch, tier4, t0)
			must(t, err)
			want := "No backup has finished yet, so this drive is still the only copy of your box. If it is lost or fails, everything on it is gone. Backups go to Home NAS."
			if n != want {
				t.Fatalf("choice notice: %q", n)
			}
			c, err := LoadBackupChoice(x.b)
			must(t, err)
			if c.Kind != k || c.Destination != "Home NAS" || !c.Chosen.Equal(t0) {
				t.Fatalf("stored: %+v", c)
			}
			if n, _ := OnlyCopyNotice(x.b); n != want {
				t.Fatalf("notice before a backup: %q", n)
			}
			// A damaged read-back does not count.
			if _, err := RecordBackup(x.b, "Home NAS", Receipt{created: t0, sum: make([]byte, 32)}, strings.NewReader("x")); err != nil {
				t.Fatal(err)
			}
			if n, _ := OnlyCopyNotice(x.b); n != want {
				t.Fatalf("notice after an unverified backup: %q", n)
			}
			backedUp(t, x, "Home NAS", t0.Add(time.Hour))
			if n, err := OnlyCopyNotice(x.b); err != nil || n != "" {
				t.Fatalf("notice after a verified backup: %q %v", n, err)
			}
			// The recovery key opens it with the same choice in place.
			if _, err := ChooseBackup(x.b, ch, Auth{Recovery: x.rk}, t0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Choosing no backup is allowed, and the box says plainly what it means.
func TestChoosingNoBackupIsToldPlainly(t *testing.T) {
	x := newBox(t)
	n, err := ChooseBackup(x.b, BackupChoice{Kind: BackupNone}, tier4, t0)
	must(t, err)
	if n != NoticeNone {
		t.Fatalf("choice notice: %q", n)
	}
	if n, _ := OnlyCopyNotice(x.b); n != NoticeNone {
		t.Fatalf("notice: %q", n)
	}
	// A backup the owner makes anyway still counts.
	backedUp(t, x, "USB stick A", t0.Add(time.Hour))
	if n, _ := OnlyCopyNotice(x.b); n != "" {
		t.Fatalf("notice after a verified backup: %q", n)
	}
}

func TestBadBackupChoicesAreRefused(t *testing.T) {
	x := newBox(t)
	for _, c := range []BackupChoice{
		{},
		{Kind: "cloud", Destination: "X"},
		{Kind: BackupDrive},
		{Kind: BackupUpload, Destination: "   "},
		{Kind: BackupNone, Destination: "USB stick A"},
		{Kind: BackupDrive, Destination: strings.Repeat("a", 201)},
		{Kind: BackupDrive, Destination: "USB\nstick"},
		// A destination is a name, never a place to keep a password.
		{Kind: BackupUpload, Destination: "https://owner:CANARY-not-a-password@nas.local/backups"},
		// The name goes into the digest, so it must not look like a code.
		{Kind: BackupDrive, Destination: "USB stick PIN 482913"},
	} {
		if _, err := ChooseBackup(x.b, c, tier4, t0); !errors.Is(err, ErrBadBackupChoice) {
			t.Fatalf("%+v: %v", c, err)
		}
	}
	if c, _ := LoadBackupChoice(x.b); c.Kind != BackupUnchosen {
		t.Fatalf("a refused choice was stored: %+v", c)
	}
}

// After the recovery key changes, older backups open only with the old
// card, so the drive is the only copy the current card restores.
func TestOlderBackupsDoNotCountAfterTheRecoveryKeyChanges(t *testing.T) {
	x := newBox(t)
	_, err := ChooseBackup(x.b, BackupChoice{Kind: BackupDrive, Destination: "USB stick A"}, tier4, t0.Add(-72*time.Hour))
	must(t, err)
	backedUp(t, x, "USB stick A", t0.Add(-48*time.Hour))
	if n, _ := OnlyCopyNotice(x.b); n != "" {
		t.Fatalf("notice: %q", n)
	}
	p, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Recovery: x.rk}, Proof{}, testGen, nil, t0)
	must(t, err)
	_, err = p.Commit(x.b, p.answer, t0)
	must(t, err)
	if n, _ := OnlyCopyNotice(x.b); n != NoticeOldCard {
		t.Fatalf("notice after the key change: %q", n)
	}
	backedUp(t, x, "USB stick A", t0.Add(time.Hour))
	if n, _ := OnlyCopyNotice(x.b); n != "" {
		t.Fatalf("notice after a new backup: %q", n)
	}
}

// What counts is the key a backup was sealed to, not the box clock: a
// backup sealed before the recovery key changed stays old, whatever time
// it carries (security C1 on #80).
func TestABackupSealedToTheOldKeyNeverCountsWhateverItsTime(t *testing.T) {
	x := newBox(t)
	var buf bytes.Buffer
	rc, err := BackupSum(x.b, x.roots(), &buf, t0.Add(24*time.Hour)) // clock ahead
	must(t, err)
	p, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Recovery: x.rk}, Proof{}, testGen, nil, t0)
	must(t, err)
	_, err = p.Commit(x.b, p.answer, t0)
	must(t, err)
	e, err := RecordBackup(x.b, "USB stick A", rc, bytes.NewReader(buf.Bytes()))
	must(t, err)
	if !e.Verified {
		t.Fatal("an intact read-back is not verified")
	}
	if n, _ := OnlyCopyNotice(x.b); n != NoticeOldCard {
		t.Fatalf("an old-key backup cleared the notice: %q", n)
	}
	if _, ok, _ := OfferDelete(x.b, func(string) bool { return true }); ok {
		t.Fatal("an old-key backup opened the delete offer")
	}
	if n, _ := OldBackupsNote(x.b); !strings.Contains(n, "USB stick A") {
		t.Fatalf("an old-key backup is not named as old: %q", n)
	}
	backedUp(t, x, "USB stick A", t0.Add(-time.Hour)) // clock behind
	if n, _ := OnlyCopyNotice(x.b); n != "" {
		t.Fatalf("a current-key backup did not count: %q", n)
	}
}

// The digest repeats the notice: weekly while no backup is chosen or none
// has finished, monthly once the owner chose none, never with a backup.
func TestTheDigestRepeatsTheOnlyCopyNotice(t *testing.T) {
	x := newBox(t)
	day := 24 * time.Hour
	line := func(at time.Time) string {
		t.Helper()
		l, err := OnlyCopyDigestLine(x.b, at)
		must(t, err)
		return l
	}
	if l := line(t0); l != NoticeUnchosen {
		t.Fatalf("first digest: %q", l)
	}
	if l := line(t0.Add(6 * day)); l != "" {
		t.Fatalf("repeated within a week: %q", l)
	}
	if l := line(t0.Add(7 * day)); l != NoticeUnchosen {
		t.Fatalf("after a week: %q", l)
	}
	// Choosing none says it at once; the digest repeats it monthly.
	_, err := ChooseBackup(x.b, BackupChoice{Kind: BackupNone}, tier4, t0.Add(8*day))
	must(t, err)
	if l := line(t0.Add(15 * day)); l != "" {
		t.Fatalf("weekly after choosing none: %q", l)
	}
	if l := line(t0.Add(38 * day)); l != NoticeNone {
		t.Fatalf("monthly after choosing none: %q", l)
	}
	// A backup ends it.
	backedUp(t, x, "USB stick A", t0.Add(39*day))
	if l := line(t0.Add(80 * day)); l != "" {
		t.Fatalf("with a backup: %q", l)
	}
}

// The choice is a reserved entry: one of another kind fails closed, and
// the box still says the drive may be the only copy.
func TestAWrongKindChoiceFailsClosed(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Put(BackupChoiceName, "api_key", []byte(`{"format":"agentos-backup-choice-v1","kind":"none"}`)))
	if _, err := LoadBackupChoice(x.b); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("load: %v", err)
	}
	n, err := OnlyCopyNotice(x.b)
	if err == nil || n != NoticeUnchosen {
		t.Fatalf("notice: %q %v", n, err)
	}
	if _, err := ChooseBackup(x.b, BackupChoice{Kind: BackupNone}, tier4, t0); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("a choice replaced an entry of another kind: %v", err)
	}
}
