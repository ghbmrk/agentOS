package clock

import (
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Synced reports whether NTP (systemd-timesyncd on the box) has set the
// kernel clock: adjtimex, read-only, answers TIME_ERROR while the clock is
// unsynchronized.
func Synced() (bool, error) {
	var tx unix.Timex // Modes 0: read only
	state, err := unix.Adjtimex(&tx)
	if err != nil {
		return false, err
	}
	return state != unix.TIME_ERROR && tx.Status&unix.STA_UNSYNC == 0, nil
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
