package peers

import (
	"net"
	"syscall"
)

// UID returns the uid of the process on the other end of a Unix
// connection (SO_PEERCRED), and false for any other connection.
func UID(c net.Conn) (int, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil || cerr != nil {
		return 0, false
	}
	return int(cred.Uid), true
}
