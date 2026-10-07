// Command agentos-clock-boot sets the box's clock at boot, before the time
// service starts, to the host's hardware clock less the offset the broker
// learned at its last verified sync (HW-8; potency C1, security T7 on
// HOST-1b). A Windows PC keeps its hardware clock in local time, so the
// kernel's reading can be hours off; this brings it close until network or
// phone-network time confirms it. The clock stays unverified: the broker's
// floor still bounds it. With no offset learned on this PC (by its
// firmware's system UUID), or a state file not root-owned 0600, it does
// nothing.
//
//	agentos-clock-boot -state /var/lib/agentos/clock.json
//
// It sets only the system clock (settimeofday), which also leaves the
// kernel's clock unsynchronised, so nothing is copied into the hardware
// clock. It never fails the boot. The image (P2-1) runs it as a oneshot
// ordered Before=chronyd.service, After=local-fs.target.
//
// HOST-1b O1: the state path is opened once with O_NOFOLLOW; ownership and
// mode are checked on that fd, and only that fd is read.
package main

import (
	"flag"
	"io"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/clock"
)

type bootEnv struct {
	rtc    func() (time.Time, error)
	hostID func() string
	owner  uint32 // the uid the state file must belong to: root
	now    func() time.Time
	set    func(time.Time) error
	logf   func(string, ...any)
	// openState opens the state path; tests substitute a memory file.
	openState func(path string) (file, error)
}

// file is the subset of *os.File used after a safe open.
type file interface {
	io.ReadCloser
	Fd() uintptr
}

func main() {
	state := flag.String("state", "/var/lib/agentos/clock.json", "the broker's clock state file")
	flag.Parse()
	os.Exit(run(*state, bootEnv{
		rtc:    clock.RTC,
		hostID: clock.HostID,
		owner:  0,
		now:    time.Now,
		set: func(t time.Time) error {
			tv := unix.NsecToTimeval(t.UnixNano())
			return unix.Settimeofday(&tv)
		},
		logf:      log.Printf,
		openState: openStateNOFOLLOW,
	}))
}

func openStateNOFOLLOW(path string) (file, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func run(state string, e bootEnv) int {
	rtc, err := e.rtc()
	if err != nil {
		e.logf("agentos-clock-boot: hardware clock unreadable, clock left as is: %v", err)
		return 0
	}
	open := e.openState
	if open == nil {
		open = openStateNOFOLLOW
	}
	f, err := open(state)
	if err != nil {
		e.logf("agentos-clock-boot: no offset learned yet, clock left as the hardware clock set it")
		return 0
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		e.logf("agentos-clock-boot: state file unreadable, clock left as is: %v", err)
		return 0
	}
	if st.Uid != e.owner || st.Mode&0o077 != 0 {
		e.logf("agentos-clock-boot: state file not owned by root with mode 0600, clock left as is")
		return 0
	}
	b, err := io.ReadAll(f)
	if err != nil {
		e.logf("agentos-clock-boot: state file unreadable, clock left as is: %v", err)
		return 0
	}
	est, ok := clock.BootEstimateBytes(b, rtc, e.hostID())
	if !ok {
		e.logf("agentos-clock-boot: no offset learned yet, clock left as the hardware clock set it")
		return 0
	}
	if d := est.Sub(e.now()); d < time.Second && d > -time.Second {
		return 0
	}
	if err := e.set(est); err != nil {
		e.logf("agentos-clock-boot: clock not set: %v", err)
		return 0
	}
	e.logf("agentos-clock-boot: clock set to %s (hardware clock less the learned offset; unverified)", est.Format(time.RFC3339))
	return 0
}
