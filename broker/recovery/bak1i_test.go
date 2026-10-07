package recovery

import (
	"testing"
	"time"
)

// REQ: BAK-1
//
// BAK-1i (L3 on #80): log entries with no key ID read as old-card backups,
// never as a current verified backup that clears the only-copy notice.

func TestBAK1iEmptyKeyIsOldCard(t *testing.T) {
	x := newBox(t)
	_, err := ChooseBackup(x.b, BackupChoice{Kind: BackupDrive, Destination: "USB stick A"}, tier4, t0)
	must(t, err)
	backedUp(t, x, "USB stick A", t0)
	if n, _ := OnlyCopyNotice(x.b); n != "" {
		t.Fatalf("current backup should clear notice: %q", n)
	}
	l, err := loadLog(x.b)
	must(t, err)
	if len(l.Entries) == 0 || l.Entries[0].Key == "" {
		t.Fatalf("backedUp should set a key ID: %+v", l.Entries)
	}
	l.Entries[0].Key = "" // pre-key-ID log line
	must(t, saveLog(x.b, l))
	n, err := OnlyCopyNotice(x.b)
	must(t, err)
	if n != NoticeOldCard {
		t.Fatalf("empty key notice %q, want old-card", n)
	}
	// older() also lists empty-key entries once the key has changed.
	l.KeyChangedAt = t0.Add(time.Hour)
	must(t, saveLog(x.b, l))
	old := l.older(currentKey(x.b))
	if len(old) != 1 || old[0].Key != "" {
		t.Fatalf("older empty-key: %+v", old)
	}
}
