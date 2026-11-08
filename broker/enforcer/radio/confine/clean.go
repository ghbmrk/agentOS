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
// cannot be emptied costs one try per level, not emptyPasses^depth.
func emptyAt(fd int) error {
	f := os.NewFile(uintptr(fd), "")
	defer f.Close()
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
		for _, n := range names {
			if err := removeAt(fd, n); err != nil {
				return err
			}
		}
	}
	return fmt.Errorf("entries remain after %d passes", emptyPasses)
}

// removeAt tries once to remove name from the directory open at fd: a
// file, socket, device or link by unlinkat (a link is the link, never its
// target); a directory by emptying it through a descriptor opened
// O_NOFOLLOW, then unlinkat AT_REMOVEDIR. A directory swapped for a link
// between the two steps fails the open and is unlinked next pass. Only a
// subdirectory that fails to empty is an error.
func removeAt(fd int, name string) error {
	if unlinkat(fd, name, 0) == syscall.EISDIR {
		if emptyRace != nil {
			emptyRace(name)
		}
		if sub, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0); err == nil {
			if err := emptyAt(sub); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
		_ = unlinkat(fd, name, atRemovedir)
	}
	return nil
}

// unlinkat is unlinkat(2) with its flags, which syscall.Unlinkat lacks.
func unlinkat(fd int, name string, flags uintptr) error {
	_, err := pathCall(syscall.SYS_UNLINKAT, name, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(syscall.SYS_UNLINKAT, uintptr(fd), s, flags)
	})
	return err
}
