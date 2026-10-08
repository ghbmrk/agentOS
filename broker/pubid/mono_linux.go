package pubid

import (
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// systemClock is CLOCK_BOOTTIME, which keeps counting while the box is
// suspended, so a suspend never holds the floor back (L3 on #163, OSS-6c),
// and the kernel's boot_id, which names the boot it counts from.
func systemClock() (func() time.Duration, string) { return bootClock(boottime, bootID) }

// bootClock is floorClock(read) and the boot it counts from: id() when
// read works, else "", since the fallback counts from the process start
// and a count it stamps means nothing to another process (OSS-6e).
func bootClock(read func() (time.Duration, error), id func() string) (func() time.Duration, string) {
	c, ok := floorClock(read)
	if !ok {
		return c, ""
	}
	return c, id()
}

func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func boottime() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

// floorClock picks its source once, on the first read, so it never mixes
// two clocks with different zeros (L3 on #180): read, if that works, else
// Go's monotonic clock for good; ok reports which. A later failed read
// returns the last value, so the floor holds rather than opens.
func floorClock(read func() (time.Duration, error)) (c func() time.Duration, ok bool) {
	if _, err := read(); err != nil {
		start := time.Now()
		return func() time.Duration { return time.Since(start) }, false
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
	}, true
}
