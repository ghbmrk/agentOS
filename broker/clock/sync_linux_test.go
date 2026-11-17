package clock

// REQ: TIM-1, HW-8

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHW8RTCReadsSysfs(t *testing.T) {
	// The answer depends on the host; a host with a hardware clock gives a
	// time after 2000, read without privilege.
	if _, err := os.Stat("/sys/class/rtc/rtc0/since_epoch"); err != nil {
		t.Skip("no hardware clock here")
	}
	rtc, err := RTC()
	if err != nil || rtc.Year() < 2000 {
		t.Fatalf("RTC = %v, %v", rtc, err)
	}
}

func TestTIM1BootClock(t *testing.T) {
	a := bootElapsed()
	if a <= 0 || bootID() == "" {
		t.Fatalf("boot elapsed %v, id %q", a, bootID())
	}
	if b := bootElapsed(); b < a {
		t.Fatalf("CLOCK_BOOTTIME went back: %v then %v", a, b)
	}
}

// A missing since_epoch file is its read's error, and one that holds no
// whole number of seconds is an error, never the epoch; a number is that
// many seconds after it, as UTC.
func TestHW8RTCRefusesAnUnreadableValue(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		body string
		want time.Time
		ok   bool
	}{
		{"1700000000\n", time.Unix(1700000000, 0).UTC(), true},
		{"soon\n", time.Time{}, false},
		{"", time.Time{}, false},
	} {
		p := filepath.Join(dir, "since_epoch")
		if err := os.WriteFile(p, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := rtcAt(p)
		if (err == nil) != c.ok || !got.Equal(c.want) || got.Location() != time.UTC {
			t.Fatalf("rtcAt(%q) = %v, %v; want %v, ok %v", c.body, got, err, c.want, c.ok)
		}
	}
	if _, err := rtcAt(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("rtcAt of a missing file: %v, want not-exist", err)
	}
}
