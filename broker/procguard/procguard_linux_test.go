package procguard

import "syscall"

// dumpable reports the process's dumpable flag (tests).
func dumpable() (bool, error) {
	r, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0, 0, 0, 0)
	if e != 0 {
		return false, e
	}
	return r != 0, nil
}
