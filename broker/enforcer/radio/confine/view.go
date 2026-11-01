package confine

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// SystemBus is the system bus's socket, the one file the BLE stack sees.
const SystemBus = "/run/dbus/system_bus_socket"

// ErrView refuses a view path that is not absolute and clean, is the root,
// or holds a newline, and a view on a profile with NetAdmin.
var ErrView = errors.New("confine: a view lists clean absolute paths other than /, and no NetAdmin")

// viewMount is where the view's tmpfs goes, in the stack's own mount
// namespace, before it becomes the root.
const viewMount = "/tmp"

const (
	capSysAdmin = 21
	oPath       = 0x200000 // O_PATH

	sysOpenTree     = 428
	sysMoveMount    = 429
	sysMountSetattr = 442
	sysExecveat     = 322

	atFdcwd              = ^uintptr(99) // AT_FDCWD, -100
	openTreeClone        = 1
	atEmptyPath          = 0x1000
	atRecursive          = 0x8000
	moveMountFEmptyPath  = 4
	mountAttrBind        = 0x1 | 0x2 | 0x4 // MOUNT_ATTR_RDONLY, NOSUID, NODEV
	prCapAmbient         = 47
	prCapAmbientClearAll = 4
	capV3                = 0x20080522
)

// checkView refuses a view Trampoline could not rebuild from its one
// newline-joined argument, or one that would replace the whole root.
func checkView(p Profile) error {
	if len(p.View) > 0 && p.NetAdmin {
		return ErrView
	}
	for _, v := range p.View {
		if !filepath.IsAbs(v) || filepath.Clean(v) != v || v == "/" || strings.ContainsRune(v, '\n') {
			return ErrView
		}
	}
	return nil
}

// enterView makes the calling process's root a read-only tmpfs holding
// only paths, each bound read-only, nosuid and nodev at its own
// path; a path that does not exist is left out. It returns exe opened
// O_PATH beforehand, since the stack's binary is not in the view. It needs
// CAP_SYS_ADMIN over the process's own mount namespace, which Start gives
// it in a user namespace of its own.
func enterView(paths []string, exe string) (int, error) {
	fd, err := syscall.Open(exe, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	// Nothing below propagates to the enforcer's namespace.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return -1, err
	}
	// Clone each path's mount before the tmpfs covers viewMount, which
	// may hold one of them.
	trees := make(map[string]int, len(paths))
	for _, p := range paths {
		t, err := openTree(p)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return -1, err
		}
		trees[p] = t
	}
	if err := syscall.Mount("tmpfs", viewMount, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"mode=0755,size=64k,nr_inodes=256"); err != nil {
		return -1, err
	}
	for _, p := range paths {
		t, ok := trees[p]
		if !ok {
			continue
		}
		if err := attach(t, viewMount+p); err != nil {
			return -1, err
		}
		syscall.Close(t)
	}
	if err := syscall.Mount("", viewMount, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY|
		syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC, ""); err != nil {
		return -1, err
	}
	// The old root goes on top of the new one and is then detached.
	if err := syscall.Chdir(viewMount); err != nil {
		return -1, err
	}
	if err := syscall.PivotRoot(".", "."); err != nil {
		return -1, err
	}
	if err := syscall.Unmount(".", syscall.MNT_DETACH); err != nil {
		return -1, err
	}
	return fd, syscall.Chdir("/")
}

// openTree clones the mount tree at p, detached, and marks every mount in
// it read-only, nosuid and nodev (not noexec: a test binary's loader runs
// from a view).
func openTree(p string) (int, error) {
	t, err := pathCall(sysOpenTree, p, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall(sysOpenTree, atFdcwd, s, openTreeClone|syscall.O_CLOEXEC|atRecursive)
	})
	if err != nil {
		return -1, err
	}
	attr := [4]uint64{mountAttrBind} // struct mount_attr: attr_set first
	empty := [1]byte{}
	if _, _, e := syscall.Syscall6(sysMountSetattr, uintptr(t), uintptr(unsafe.Pointer(&empty[0])),
		atEmptyPath|atRecursive, uintptr(unsafe.Pointer(&attr[0])), unsafe.Sizeof(attr), 0); e != 0 {
		syscall.Close(int(t))
		return -1, e
	}
	return int(t), nil
}

// attach makes a mount point at dst, a directory or an empty file as the
// tree's root is, with its parents, and moves the tree there.
func attach(tree int, dst string) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(tree, &st); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		if err := syscall.Mkdir(dst, 0o755); err != nil {
			return err
		}
	} else {
		f, err := syscall.Open(dst, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		syscall.Close(f)
	}
	empty := [1]byte{}
	_, err := pathCall(sysMoveMount, dst, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(sysMoveMount, uintptr(tree), uintptr(unsafe.Pointer(&empty[0])), atFdcwd, s,
			moveMountFEmptyPath, 0)
	})
	return err
}

// pathCall makes a call that takes the C string of p.
func pathCall(nr uintptr, p string, call func(uintptr) (uintptr, uintptr, syscall.Errno)) (uintptr, error) {
	s, err := syscall.BytePtrFromString(p)
	if err != nil {
		return 0, err
	}
	r, _, e := call(uintptr(unsafe.Pointer(s)))
	if e != 0 {
		return 0, e
	}
	return r, nil
}

// dropCaps clears the calling thread's ambient, effective, permitted and
// inheritable capabilities; the exec that follows on this thread keeps
// none.
func dropCaps() error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, prCapAmbientClearAll, 0, 0, 0, 0); e != 0 {
		return e
	}
	hdr := struct{ version, pid uint32 }{capV3, 0}
	var data [6]uint32 // two of struct { effective, permitted, inheritable }
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	return nil
}

// execFD execs the binary fd holds, which the view does not show.
func execFD(fd int, argv []string) error {
	av, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	env := []*byte{nil}
	empty := [1]byte{}
	_, _, e := syscall.RawSyscall6(sysExecveat, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
		uintptr(unsafe.Pointer(&av[0])), uintptr(unsafe.Pointer(&env[0])), atEmptyPath, 0)
	return e
}
