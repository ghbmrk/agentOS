package imapconn

import "syscall"

// Undumpable marks this process not dumpable (prctl PR_SET_DUMPABLE 0), so
// another process under the same uid, such as a concurrent session's, cannot
// open its /proc/<pid>/mem or fd entries, or take its descriptors with
// pidfd_getfd, whatever the kernel's Yama setting (#3880 Security point 1).
// The connection process's main calls it before it receives a session.
func Undumpable() error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); e != 0 {
		return e
	}
	return nil
}
