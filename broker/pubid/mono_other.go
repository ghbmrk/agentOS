//go:build !linux

package pubid

import "time"

// monoClock is Go's monotonic clock where CLOCK_BOOTTIME does not exist.
func monoClock() func() time.Duration {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }
}
