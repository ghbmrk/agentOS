package confine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// SystemBus is the system bus's socket, the one file the BLE stack sees.
const SystemBus = "/run/dbus/system_bus_socket"

// Kind is what a view entry is on the host: Trampoline opens the path
// without following a symlink anywhere in it and refuses the start unless
// the file found is of that kind, so a path swapped for a symlink or
// another file cannot widen the view (#4384).
type Kind byte

const (
	// Socket is a Unix socket, bound read-only, nosuid, nodev and noexec.
	Socket Kind = 's'
	// Dir is a directory and every mount under it, bound read-only, nosuid
	// and nodev (exec stays, for a test binary's loader), or with Write
	// read-write, nosuid, nodev and noexec.
	Dir Kind = 'd'
	// Device is a character device, bound nosuid and noexec but not nodev,
	// so it opens; read-only binds it still: a device's writes are not the
	// file system's.
	Device Kind = 'c'
	// Link is a symlink, made in the view with the same target, which must
	// be in the view itself to resolve: the loader's /lib64 on a usr-merged
	// host. A shipped stack lists none.
	Link Kind = 'l'
)

// Entry is one path a view shows, at its own path.
type Entry struct {
	Path  string
	Kind  Kind
	Write bool // a Dir the stack writes: its state
}

// ErrView refuses a view entry whose path is not absolute and clean, is the
// root, holds a newline, or is another entry's or under it, whose kind is
// not one of Kind's, or that writes and is not a Dir.
var ErrView = errors.New("confine: a view lists clean absolute paths other than /, none under another, each of a known kind, and only a Dir writes")

// viewMount is where the view's tmpfs goes, in the stack's own mount
// namespace, before it becomes the root.
const viewMount = "/tmp"

const (
	capSysAdmin = 21
	oPath       = 0x200000 // O_PATH

	sysOpenTree     = 428
	sysMoveMount    = 429
	sysOpenat2      = 437
	sysMountSetattr = 442
	sysExecveat     = 322

	atFdcwd             = ^uintptr(99) // AT_FDCWD, -100
	openTreeClone       = 1
	atEmptyPath         = 0x1000
	atRecursive         = 0x8000
	moveMountFEmptyPath = 4
	resolveNoSymlinks   = 0x04 // RESOLVE_NO_SYMLINKS, which also refuses magic links

	mountAttrRdonly = 0x1
	mountAttrNosuid = 0x2
	mountAttrNodev  = 0x4
	mountAttrNoexec = 0x8

	capV3 = 0x20080522
)

// fileType is the st_mode type each kind must find.
var fileType = map[Kind]uint32{Socket: syscall.S_IFSOCK, Dir: syscall.S_IFDIR, Device: syscall.S_IFCHR, Link: syscall.S_IFLNK}

// checkView refuses a view Trampoline could not rebuild from its one
// newline-joined argument, one that would replace the whole root, and one
// whose entries overlap, which Trampoline could not bind each at its path.
func checkView(p Profile) error {
	for i, e := range p.View {
		v := e.Path
		for _, o := range p.View[:i] {
			if o.Path == v || strings.HasPrefix(v, o.Path+"/") || strings.HasPrefix(o.Path, v+"/") {
				return ErrView
			}
		}
		if !filepath.IsAbs(v) || filepath.Clean(v) != v || v == "/" || strings.ContainsRune(v, '\n') {
			return ErrView
		}
		if _, ok := fileType[e.Kind]; !ok || e.Write && e.Kind != Dir {
			return ErrView
		}
	}
	return nil
}

// encodeView is the view as Trampoline's one argument: per entry, its kind,
// 'w' or 'r', and its path, one per line.
func encodeView(v []Entry) string {
	lines := make([]string, len(v))
	for i, e := range v {
		w := byte('r')
		if e.Write {
			w = 'w'
		}
		lines[i] = string([]byte{byte(e.Kind), w}) + e.Path
	}
	return strings.Join(lines, "\n")
}

// decodeView is encodeView's inverse, checked as Start checks.
func decodeView(s string) ([]Entry, error) {
	var v []Entry
	for l := range strings.SplitSeq(s, "\n") {
		if len(l) < 3 || l[1] != 'r' && l[1] != 'w' {
			return nil, ErrView
		}
		v = append(v, Entry{Path: l[2:], Kind: Kind(l[0]), Write: l[1] == 'w'})
	}
	return v, checkView(Profile{View: v})
}

// Loader is the dynamic loader's directories as this host has them, each
// a Dir or, on a usr-merged host, a Link to one, for a cgo-linked binary in
// a view: the tests' own. A shipped stack is static and lists none.
func Loader() []Entry {
	var v []Entry
	for _, p := range []string{"/lib", "/lib64", "/usr/lib", "/usr/lib64"} {
		var st syscall.Stat_t
		if syscall.Lstat(p, &st) != nil {
			continue
		}
		k := Dir
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			k = Link
		}
		v = append(v, Entry{Path: p, Kind: k})
	}
	return v
}

// enterView makes the calling process's root a read-only tmpfs holding
// only the entries, each at its own path; an entry whose path does not
// exist is left out, and one of another kind, or reached through a
// symlink, fails the view. It returns exe opened O_PATH beforehand, since
// the stack's binary is not in the view, and leaves the process in its
// working directory, which must be in the view. It needs CAP_SYS_ADMIN
// over the process's own mount namespace, which Start gives it in a user
// namespace of its own.
func enterView(entries []Entry, exe string) (int, error) {
	fd, err := syscall.Open(exe, oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	wd, err := syscall.Getwd()
	if err != nil {
		return -1, err
	}
	// Nothing below propagates to the enforcer's namespace, nor from it.
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return -1, err
	}
	// Open each entry before the tmpfs covers viewMount, which may hold one
	// of them.
	var fs []opened
	for _, e := range entries {
		f, err := openEntry(e)
		if errors.Is(err, syscall.ENOENT) {
			continue
		}
		if err != nil {
			return -1, fmt.Errorf("%s: %w", e.Path, err)
		}
		fs = append(fs, f)
	}
	if err := syscall.Mount("tmpfs", viewMount, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC,
		"mode=0755,size=64k,nr_inodes=256"); err != nil {
		return -1, err
	}
	for _, f := range fs {
		if err := attach(f, viewMount+f.e.Path); err != nil {
			return -1, fmt.Errorf("%s: %w", f.e.Path, err)
		}
		if f.fd != -1 {
			syscall.Close(f.fd)
		}
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
	if err := syscall.Chdir(wd); err != nil {
		return -1, fmt.Errorf("working directory %s: %w", wd, err)
	}
	return fd, nil
}

// opened is an entry Trampoline opened: a cloned tree, or a Link's target.
type opened struct {
	e      Entry
	fd     int
	target string
}

// openEntry opens e's path O_PATH with no symlink followed in any of its
// components (openat2, RESOLVE_NO_SYMLINKS), checks the file is e's kind,
// and clones the mount tree at that descriptor, detached, with e's mount
// attributes on every mount in it. A Link is read instead.
func openEntry(e Entry) (f opened, err error) {
	f.e = e
	how := [3]uint64{oPath | syscall.O_NOFOLLOW | syscall.O_CLOEXEC, 0, resolveNoSymlinks} // struct open_how
	r, err := pathCall(sysOpenat2, e.Path, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(sysOpenat2, atFdcwd, s, uintptr(unsafe.Pointer(&how[0])), unsafe.Sizeof(how), 0, 0)
	})
	if err != nil {
		return f, err
	}
	fd := int(r)
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return f, err
	}
	if st.Mode&syscall.S_IFMT != fileType[e.Kind] {
		return f, fmt.Errorf("not a %c (mode %#o)", e.Kind, st.Mode)
	}
	if e.Kind == Link {
		b := make([]byte, syscall.PathMax)
		empty := [1]byte{}
		n, _, en := syscall.Syscall6(syscall.SYS_READLINKAT, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
			uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
		if en != 0 {
			return f, en
		}
		f.fd, f.target = -1, string(b[:n])
		return f, nil
	}
	empty := [1]byte{}
	t, _, en := syscall.Syscall(sysOpenTree, uintptr(fd), uintptr(unsafe.Pointer(&empty[0])),
		openTreeClone|syscall.O_CLOEXEC|atRecursive|atEmptyPath)
	if en != 0 {
		return f, en
	}
	attr := [4]uint64{mountAttrs(e)} // struct mount_attr: attr_set first
	if _, _, en := syscall.Syscall6(sysMountSetattr, t, uintptr(unsafe.Pointer(&empty[0])),
		atEmptyPath|atRecursive, uintptr(unsafe.Pointer(&attr[0])), unsafe.Sizeof(attr), 0); en != 0 {
		syscall.Close(int(t))
		return f, en
	}
	f.fd = int(t)
	return f, nil
}

// mountAttrs is what an entry's mounts are set to: nosuid always, nodev
// unless a Device, read-only unless it writes, and noexec unless a
// read-only Dir (a test binary's loader runs from one).
func mountAttrs(e Entry) uint64 {
	a := uint64(mountAttrNosuid)
	if e.Kind != Device {
		a |= mountAttrNodev
	}
	if !e.Write {
		a |= mountAttrRdonly
	}
	if e.Kind != Dir || e.Write {
		a |= mountAttrNoexec
	}
	return a
}

// attach makes the entry at dst: a Link is made there; otherwise a mount
// point, a directory or an empty file as the tree's root is, with its
// parents, and the tree is moved there.
func attach(f opened, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if f.e.Kind == Link {
		return syscall.Symlink(f.target, dst)
	}
	if f.e.Kind == Dir {
		if err := syscall.Mkdir(dst, 0o755); err != nil {
			return err
		}
	} else {
		fd, err := syscall.Open(dst, syscall.O_CREAT|syscall.O_EXCL|syscall.O_WRONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		syscall.Close(fd)
	}
	empty := [1]byte{}
	_, err := pathCall(sysMoveMount, dst, func(s uintptr) (uintptr, uintptr, syscall.Errno) {
		return syscall.Syscall6(sysMoveMount, uintptr(f.fd), uintptr(unsafe.Pointer(&empty[0])), atFdcwd, s,
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

// dropSysAdmin clears CAP_SYS_ADMIN from the calling thread's effective,
// permitted and inheritable sets, which takes it out of the ambient set
// too, and keeps the rest: none for a stack with only a view, CAP_NET_ADMIN
// and CAP_NET_RAW for Thread. The exec that follows on this thread keeps
// what is left.
func dropSysAdmin() error {
	hdr := struct{ version, pid uint32 }{capV3, 0}
	var data [6]uint32 // two of struct { effective, permitted, inheritable }
	if _, _, e := syscall.RawSyscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return e
	}
	for i := range 3 {
		data[i] &^= 1 << capSysAdmin
	}
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
