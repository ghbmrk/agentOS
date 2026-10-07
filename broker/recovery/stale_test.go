package recovery

import (
	"testing"
	"time"
)

// REQ: BAK-1
func TestBAK1staleOnlyCopyWhenBackupIsOld(t *testing.T) {
	x := newBox(t)
	now := time.Unix(2e9, 0).UTC()
	if n, err := StaleOnlyCopyNotice(x.b, now); err != nil || n != "" {
		t.Fatalf("no backup: %q %v", n, err)
	}
	backedUp(t, x, "USB stick A", now.Add(-40*24*time.Hour))
	n, err := StaleOnlyCopyNotice(x.b, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != NoticeStale {
		t.Fatalf("want stale notice, got %q", n)
	}
	backedUp(t, x, "USB stick A", now.Add(-24*time.Hour))
	if n, err := StaleOnlyCopyNotice(x.b, now); err != nil || n != "" {
		t.Fatalf("fresh backup still stale: %q %v", n, err)
	}
}
