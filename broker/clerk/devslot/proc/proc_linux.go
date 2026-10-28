// Package proc is a driver binary's process entry (DEVSLOT-drivers part
// b2a): the only code apart from the slot that a driver links from this
// repository. It is apart from the slot so the slot itself imports no
// process or file package.
package proc

import (
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// HostUIDEnv names the environment variable that gives the host's uid to
// the driver's process; the driver's unit sets it (part b1, b2b).
const HostUIDEnv = "AGENTOS_DEVHOST_UID"

// connFD is the descriptor the driver's socket unit hands its instance:
// the host's connection, already open (Accept=yes).
const connFD = 3

// ErrPeer is a connection from a process that is not the host.
var ErrPeer = errors.New("devslot: peer is not the host")

// Main is a driver binary's whole main: func main() { proc.Main(drv) }.
// It makes the process non-dumpable, refuses a peer on descriptor 3 whose
// uid is not the host's, reads the device key the unit passed (keyLend),
// serves exactly one operation over the wire with it, and exits: 0 if the operation succeeded, 1 otherwise. It writes nothing to
// standard output or error. The sandbox itself is the unit's, applied
// before exec (DEVSLOT-host-lib-2).
func Main(drv devslot.Driver) {
	if err := serveMain(drv, connFD, os.Getenv(HostUIDEnv)); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// serveMain is Main up to its exit: the checks on fd, then the operation.
// The peer is checked before Declare, so a driver's code past its package
// initialisers runs only for the host.
func serveMain(drv devslot.Driver, fd int, hostUID string) error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); e != 0 {
		return e
	}
	uid, err := strconv.ParseUint(hostUID, 10, 32)
	if err != nil {
		return ErrPeer
	}
	cred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil || uint64(cred.Uid) != uid {
		return ErrPeer
	}
	// Non-blocking, so the file is pollable and its deadlines work.
	if err := syscall.SetNonblock(fd, true); err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "host")
	defer f.Close()
	lend, err := keyLend(os.Getenv, os.Getpid())
	if err != nil {
		return err
	}
	return devslot.ServeWireLend(context.Background(), drv, f, lend)
}
