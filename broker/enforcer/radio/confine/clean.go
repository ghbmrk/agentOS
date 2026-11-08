package confine

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const atRemovedir = 0x200 // AT_REMOVEDIR

// emptyPasses bounds the passes Empty makes over a directory. One pass
// empties a directory no process writes; a further pass removes a name a
// writer swapped mid-pass (a directory turned into a link), and names
// still there after that mean something is still writing, or refuses.
const emptyPasses = 4

// emptyRace, when set, runs after Empty finds name to be a directory and
// before it opens it: the test's window to swap the directory for a link.
var emptyRace func(name string)

// Empty removes everything inside a stack's writable directory (its
// state, run or storage directory) and keeps the directory itself, with
// its owner, mode and inode, which a view binds (#4459). The enforcer
// runs it as root on a directory the stack can write, so no symlink is
// ever followed: dir is opened with none in any of its components
// (openat2, RESOLVE_NO_SYMLINKS), and everything beneath it is reached
// through descriptors, each subdirectory opened O_NOFOLLOW from its
// parent's, so a link the stack planted is removed, never resolved. Call
// it once the stack and every process it started have exited; a
// directory still being written, or holding a name it cannot remove,
// fails rather than being chased.
func Empty(dir string) error {
	how := [3]uint64{syscall.O_RDONLY | syscall.O_DIRECTORY | syscall.O_NOFOLLOW | syscall.O_CLOEXEC, 0, resolveNoSymlinks} // struct open_how
	r, err := pathCall(sysOpenat2, dir, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(sysOpenat2, atFdcwd, s, uintptr(unsafe.Pointer(&how[0])), unsafe.Sizeof(how), 0, 0)
	})
	if err != nil {
		return fmt.Errorf("confine: empty %s: %w", dir, err)
	}
	if err := emptyAt(int(r)); err != nil {
		return fmt.Errorf("confine: empty %s: %w", dir, err)
	}
	return nil
}

// emptyAt removes every entry of the directory open at fd, and closes fd.
// It succeeds only on reading the directory empty: a name it could not
// remove (gone, swapped, or refused) is simply read again next pass, but a
// subdirectory that fails to empty fails it at once, so a deep tree that
// cannot be emptied costs one try per level, not emptyPasses^depth. That
// failure names one entry, the last its final pass could not remove, and
// is passed up unwrapped: a name added at every level would grow the error
// with the square of a depth the stack chooses.
func emptyAt(fd int) error {
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()
	var left error
	for range emptyPasses {
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
		names, err := f.Readdirnames(-1)
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return nil
		}
		left = nil
		for _, n := range names {
			why, err := removeAt(fd, n)
			if err != nil {
				return err
			}
			if why != nil {
				left = fmt.Errorf("entries remain after %d passes; removing %q failed: %w", emptyPasses, n, why)
			}
		}
	}
	if left == nil {
		left = fmt.Errorf("entries remain after %d passes", emptyPasses)
	}
	return left
}

// removeAt tries once to remove name from the directory open at fd: a
// file, socket, device or link by unlinkat (a link is the link, never its
// target); a directory by emptying it through a descriptor opened
// O_NOFOLLOW, then unlinkat AT_REMOVEDIR. A directory swapped for a link
// between the two steps fails the open and is unlinked next pass. why is
// what kept name in place (nil once it is gone); err is a subdirectory's
// failure to empty, as it is.
func removeAt(fd int, name string) (why, err error) {
	if why = unlinkat(fd, name, 0); why != syscall.EISDIR {
		return why, nil
	}
	if emptyRace != nil {
		emptyRace(name)
	}
	sub, open := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if open == nil {
		if err := emptyAt(sub); err != nil {
			return nil, err
		}
	}
	if why = unlinkat(fd, name, atRemovedir); why != nil && open != nil {
		why = open // the open's failure is why the directory is not empty
	}
	return why, nil
}

// unlinkat is unlinkat(2) with its flags, which syscall.Unlinkat lacks.
func unlinkat(fd int, name string, flags uintptr) error {
	_, err := pathCall(syscall.SYS_UNLINKAT, name, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(fd), s, flags)
	})
	return err
}
