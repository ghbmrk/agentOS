package main

import (
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// lastBoot is the largest CLOCK_BOOTTIME reading bootTime has returned,
// which it returns again if a read fails or comes back smaller, so the
// rate clock never steps back. bootMu guards it.
var (
	bootMu   sync.Mutex
	lastBoot time.Duration
)

// bootTime is the channel's rate clock (channel.Config.Elapsed, #4507):
// Linux's CLOCK_BOOTTIME, which never steps back and keeps counting while
// the box is suspended, so the channel's rates refill for the time the
// kernel's check, on the core's clock, saw pass (chancheck KRN-chan-4).
func bootTime() time.Duration {
	var ts unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	bootMu.Lock()
	defer bootMu.Unlock()
	if err == nil {
		lastBoot = max(lastBoot, time.Duration(ts.Nano()))
	}
	return lastBoot
}
