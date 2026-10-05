package clock

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// RTC reads the host's hardware clock as the kernel does (as if UTC),
// read-only from sysfs. It is never written (HW-8).
func RTC() (time.Time, error) {
	b, err := os.ReadFile("/sys/class/rtc/rtc0/since_epoch")
	if err != nil {
		return time.Time{}, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(n, 0).UTC(), nil
}

// bootElapsed is CLOCK_BOOTTIME: monotonic, counting suspend, and the same
// for every process of one boot, so an anchor survives a broker restart.
func bootElapsed() time.Duration {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// bootID names this boot; an anchor recorded in another boot is dropped.
func bootID() string {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
