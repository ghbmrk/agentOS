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
