package main

import (
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// lastBoot is the last CLOCK_BOOTTIME reading, which bootTime returns if
// a read ever fails, so the rate clock never steps back.
var lastBoot atomic.Int64

// bootTime is the channel's rate clock (channel.Config.Elapsed, #4507):
// Linux's CLOCK_BOOTTIME, which never steps back and keeps counting while
// the box is suspended, so the channel's rates refill for the time the
// kernel's check, on the core's clock, saw pass (chancheck KRN-chan-4).
func bootTime() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Duration(lastBoot.Load())
	}
	n := ts.Nano()
	for {
		old := lastBoot.Load()
		if n <= old {
			return time.Duration(old)
		}
		if lastBoot.CompareAndSwap(old, n) {
			return time.Duration(n)
		}
	}
}
