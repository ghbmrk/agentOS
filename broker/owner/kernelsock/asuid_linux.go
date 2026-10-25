package kernelsock

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// asUID runs f on an OS thread locked to it whose effective uid is uid, so
// a socket f dials there carries uid as its peer (SO_PEERCRED reads the
// connecting thread's effective uid). Credentials are per thread on Linux,
// and the raw setresuid changes only this thread's effective uid: the real
// and saved uids stay root's, so no process under uid may signal or trace
// the broker, and the thread takes root back (with its capabilities) once f
// returns. Only then is it given back to the runtime; if root does not come
// back, it never is, and the runtime ends it with its goroutine, so no other
// goroutine ever runs under uid. f must dial on the goroutine it is called
// on: one it starts runs as root.
func asUID(uid int, f func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := setEUID(uid); err != nil {
			errc <- fmt.Errorf("%w: %v", errNoSeat, err)
			if setEUID(0) == nil {
				runtime.UnlockOSThread()
			}
			return
		}
		errc <- f()
		if setEUID(0) == nil {
			runtime.UnlockOSThread()
		}
	}()
	return <-errc
}

// setEUID sets this thread's effective uid alone and checks it took.
func setEUID(uid int) error {
	if _, _, e := unix.RawSyscall(unix.SYS_SETRESUID, ^uintptr(0), uintptr(uid), ^uintptr(0)); e != 0 {
		return e
	}
	if got, _, _ := unix.RawSyscall(unix.SYS_GETEUID, 0, 0, 0); int(got) != uid {
		return fmt.Errorf("effective uid %d, not %d", got, uid)
	}
	return nil
}
