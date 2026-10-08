//go:build !linux

package pubid

import "time"

// systemClock is Go's monotonic clock where CLOCK_BOOTTIME does not exist.
// It counts from the process start, so it names no boot.
func systemClock() (func() time.Duration, string) {
	start := time.Now()
	return func() time.Duration { return time.Since(start) }, ""
}
