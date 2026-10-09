package pubid

import (
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// REQ: OSS-6

// The default floor clock is CLOCK_BOOTTIME, which keeps counting through
// a suspend, not Go's monotonic clock, which stops (OSS-6c).
func TestOSS6FloorClockIsBoottime(t *testing.T) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		t.Skip("no CLOCK_BOOTTIME")
	}
	mono, _ := systemClock()
	m := mono()
	if d := m - time.Duration(ts.Nano()); d < 0 || d > time.Second {
		t.Fatalf("floor clock %v, boottime %v", m, time.Duration(ts.Nano()))
	}
}

// The floor clock never mixes sources (L3 on #180): a failed read after
// CLOCK_BOOTTIME worked holds the last value, so the floor stays shut,
// and it never goes back; a clock that fails from the start is replaced
// by Go's for good, even if it works later.
func TestOSS6FloorClockNeverMixesSources(t *testing.T) {
	var now time.Duration
	var fail bool
	read := func() (time.Duration, error) {
		if fail {
			return 0, unix.EINVAL
		}
		return now, nil
	}
	now = 100 * time.Hour
	c, _ := floorClock(read)
	if got := c(); got != now {
		t.Fatalf("boottime read %v, want %v", got, now)
	}
	fail = true
	if got := c(); got != 100*time.Hour {
		t.Fatalf("a failed read gave %v, want the last value", got)
	}
	fail, now = false, 130*time.Hour
	if got := c(); got != now {
		t.Fatalf("after recovery %v, want %v", got, now)
	}
	now = 120 * time.Hour
	if got := c(); got != 130*time.Hour {
		t.Fatalf("a read going back gave %v, want the last value", got)
	}

	fail, now = true, 500*time.Hour
	g, ok := floorClock(read)
	fail = false
	if ok {
		t.Fatal("a clock that failed at first was reported as working")
	}
	if got := g(); got > time.Minute {
		t.Fatalf("a clock that failed at first was used later: %v", got)
	}
}

// The system floor clock names the boot only when it is CLOCK_BOOTTIME:
// the fallback counts from the process start, so a count stamped by it
// must not be carried to a process that reads CLOCK_BOOTTIME (OSS-6e).
func TestOSS6BootClockNamesTheBootOnlyForBoottime(t *testing.T) {
	ok := func() (time.Duration, error) { return 7 * time.Hour, nil }
	bad := func() (time.Duration, error) { return 0, unix.EINVAL }
	id := func() string { return "b1" }
	if mono, boot := bootClock(ok, id); boot != "b1" || mono() != 7*time.Hour {
		t.Fatalf("boottime: boot %q, mono %v", boot, mono())
	}
	if _, boot := bootClock(bad, id); boot != "" {
		t.Fatalf("the fallback clock named boot %q", boot)
	}
	// One probe decides both: a read that fails only after the first
	// still names the boot, and the clock holds its last value.
	n := 0
	flaky := func() (time.Duration, error) {
		if n++; n > 1 {
			return 0, unix.EINVAL
		}
		return 7 * time.Hour, nil
	}
	if mono, boot := bootClock(flaky, id); boot != "b1" || mono() != 0 {
		t.Fatalf("flaky boottime: boot %q, mono %v", boot, mono())
	}
	if _, boot := bootClock(ok, func() string { return "" }); boot != "" {
		t.Fatalf("boot %q with no boot_id", boot)
	}
	if b, err := os.ReadFile("/proc/sys/kernel/random/boot_id"); err == nil {
		if _, boot := systemClock(); boot != strings.TrimSpace(string(b)) {
			t.Fatalf("system boot %q, kernel boot_id %q", boot, b)
		}
	}
}
