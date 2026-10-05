package clock

import "golang.org/x/sys/unix"

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
