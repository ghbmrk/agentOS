package pubid

import (
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
	m := monoClock()()
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
	c := floorClock(read)
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
	g := floorClock(read)
	fail = false
	if got := g(); got > time.Minute {
		t.Fatalf("a clock that failed at first was used later: %v", got)
	}
}
