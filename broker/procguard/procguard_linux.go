// Package procguard hardens a process that serves peer sockets apart from
// its callers. It sits outside sockets so agentosd, which imports sockets,
// does not link the prctl calls (daemon inference check).
package procguard

import (
	"fmt"
	"os"
	"syscall"
)

// Isolate hardens a process that serves peer sockets apart from its
// callers (the key holders and the CH-4 checker, SIM-split). It refuses to
// run as one of its own peers, since the uid check is then no boundary,
// and makes the process non-dumpable, so a peer under the same uid could
// not read its memory through ptrace or /proc/<pid>/mem either.
func Isolate(peers ...int) error {
	me := os.Getuid()
	for _, p := range peers {
		if p == me {
			return fmt.Errorf("procguard: running as peer uid %d; run as a uid of its own", me)
		}
	}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("procguard: set non-dumpable: %w", e)
	}
	return nil
}

// dumpable reports the process's dumpable flag (tests).
func dumpable() (bool, error) {
	r, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if e != 0 {
		return false, e
	}
	return r != 0, nil
}
