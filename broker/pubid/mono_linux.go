package pubid

import (
	"time"

	"golang.org/x/sys/unix"
)

// monoClock is CLOCK_BOOTTIME, which keeps counting while the box is
// suspended, so a suspend never holds the floor back (L3 on #163, OSS-6c).
// If it cannot be read, Go's monotonic clock stands in.
func monoClock() func() time.Duration {
	start := time.Now()
	return func() time.Duration {
		var ts unix.Timespec
		if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
			return time.Since(start)
		}
		return time.Duration(ts.Nano())
	}
}
