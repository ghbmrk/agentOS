package pubid

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// monoClock is CLOCK_BOOTTIME, which keeps counting while the box is
// suspended, so a suspend never holds the floor back (L3 on #163, OSS-6c).
func monoClock() func() time.Duration { return floorClock(boottime) }

func boottime() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

// floorClock picks its source once, on the first read, so it never mixes
// two clocks with different zeros (L3 on #180): read, if that works, else
// Go's monotonic clock for good. A later failed read returns the last
// value, so the floor holds rather than opens.
func floorClock(read func() (time.Duration, error)) func() time.Duration {
	if _, err := read(); err != nil {
		start := time.Now()
		return func() time.Duration { return time.Since(start) }
	}
	var mu sync.Mutex
	var last time.Duration
	return func() time.Duration {
		mu.Lock()
		defer mu.Unlock()
		if d, err := read(); err == nil && d > last {
			last = d
		}
		return last
	}
}
