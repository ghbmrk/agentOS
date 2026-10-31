package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ghbmrk/agentos/broker/modem"
	"github.com/ghbmrk/agentos/broker/modem/at"
	"github.com/ghbmrk/agentos/broker/modem/atsim"
)

// Synthetic numbers from the reserved 555-01xx range.
const (
	phoneNum = "+15550000101"
	boxNum   = "+15550000100"
)

// pluggedModem is the AT simulator on a carrier line, behind a
// pseudo-terminal whose slave stands in for the modem's ttyUSB node.
type pluggedModem struct {
	Slave  string
	master *os.File
	hold   io.Closer
	dev    *atsim.Device
}

// plugModem starts a simulated SIM7600G-H on carrier's box line. A uid of
// 0 or more is given the slave, as the udev rule gives a qualified modem's
// node to the bridge's user.
func plugModem(carrier *modem.Carrier, uid int) (*pluggedModem, error) {
	// Non-blocking, so the runtime poller owns the master and Close
	// interrupts the copy goroutines' reads.
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	master := os.NewFile(uintptr(fd), "/dev/ptmx")
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, fmt.Errorf("unlock pty: %w", err)
	}
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, fmt.Errorf("pty number: %w", err)
	}
	slave := fmt.Sprintf("/dev/pts/%d", n)
	// Holding the slave open keeps the master readable while the bridge
	// restarts, and sets raw mode before the bridge's first open.
	hold, err := at.OpenSerial(slave)
	if err != nil {
		master.Close()
		return nil, err
	}
	if uid >= 0 {
		// Through the held descriptor, so no name is resolved.
		f, ok := hold.(*os.File)
		if !ok {
			hold.Close()
			master.Close()
			return nil, fmt.Errorf("pty slave %T is not a file", hold)
		}
		if err := f.Chown(uid, -1); err != nil {
			hold.Close()
			master.Close()
			return nil, err
		}
		if err := f.Chmod(0o600); err != nil {
			hold.Close()
			master.Close()
			return nil, err
		}
	}
	dev := atsim.New(at.SIMCom, "SIMCOM_SIM7600G-H", carrier.Line(boxNum), time.Millisecond)
	port := dev.Port()
	go io.Copy(port, master)
	go io.Copy(master, port)
	return &pluggedModem{Slave: slave, master: master, hold: hold, dev: dev}, nil
}

func (m *pluggedModem) Close() error {
	m.hold.Close()
	return m.master.Close()
}
