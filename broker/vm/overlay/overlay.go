// Package overlay reads, copies, and edits overlayfs upper layers on the host
// (SPEC REV-1, REV-4).
//
// An agent machine's root file system is a read-only image (the lower layer)
// plus a writable upper layer that holds everything the guest changed,
// including whiteouts (deleted paths) and opaque directories. A file-system
// snapshot is a copy of the upper layer, taken while the guest is paused.
// Copies use reflinks where the file system supports them (btrfs, XFS), so a
// snapshot costs metadata only there; elsewhere they are byte copies.
//
// Layers live in broker-held directories that are never mounted into a guest.
package overlay

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Kind is what a path is in a layer or view.
type Kind uint8

const (
	Absent Kind = iota
	File
	Dir
	Symlink
	Whiteout // overlayfs deletion marker: a 0/0 character device
	Other    // fifo, socket, or device node: compared by mode only
)

func (k Kind) String() string {
	return [...]string{"absent", "file", "dir", "symlink", "whiteout", "other"}[k]
}

// Entry describes one path.
type Entry struct {
	Kind     Kind
	Mode     fs.FileMode // permission and special bits
	Uid, Gid uint32
	Size     int64
	Sum      [32]byte // SHA-256 over a file's data extents and size
	Target   string   // symlink target
	Opaque   bool     // directory hides the layers below it
	Xattrs   string   // canonical list of non-overlay xattrs (e.g. file capabilities)
}

// Same reports whether two entries look the same to a guest.
func (e Entry) Same(o Entry) bool {
	if e.Kind != o.Kind {
		return false
	}
	switch e.Kind {
	case Absent, Whiteout:
		return true
	case File:
		return e.Mode == o.Mode && e.owner() == o.owner() && e.Xattrs == o.Xattrs && e.Size == o.Size && e.Sum == o.Sum
	case Symlink:
		return e.Target == o.Target && e.owner() == o.owner()
	default:
		return e.Mode == o.Mode && e.owner() == o.owner() && e.Xattrs == o.Xattrs
	}
}

func (e Entry) owner() [2]uint32 { return [2]uint32{e.Uid, e.Gid} }

const (
	overlayXattrs = "trusted.overlay."
	opaqueXattr   = overlayXattrs + "opaque"
)

// ErrUnsafe is returned for paths and objects the broker will not handle.
var ErrUnsafe = errors.New("overlay: unsafe path or object")

// split checks rel and returns its components.
func split(rel string) ([]string, error) {
	rel = filepath.Clean(rel)
	if rel == "." || filepath.IsAbs(rel) {
		return nil, fmt.Errorf("%w: %q", ErrUnsafe, rel)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	for _, p := range parts {
		if p == ".." {
			return nil, fmt.Errorf("%w: %q", ErrUnsafe, rel)
		}
	}
	return parts, nil
}

// Stat describes path rel inside layer root, resolving it beneath root
// without following any symlink: a path whose parent is a symlink or any
// other non-directory is Absent, as it is for the kernel's overlay. An
// image's absolute symlink (Debian's /var/run -> /run) therefore never
// leads into the host.
func Stat(root, rel string) (Entry, error) {
	parts, err := split(rel)
	if err != nil {
		return Entry{}, err
	}
	p := root
	for i, part := range parts {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return Entry{}, nil
		}
		if err != nil {
			return Entry{}, err
		}
		if i == len(parts)-1 {
			return describe(p, fi)
		}
		if !fi.IsDir() {
			return Entry{}, nil
		}
	}
	return Entry{}, nil
}

func describe(p string, fi fs.FileInfo) (Entry, error) {
	e := Entry{Mode: fi.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.Uid, e.Gid = st.Uid, st.Gid
	}
	switch m := fi.Mode(); {
	case m.IsRegular():
		e.Kind, e.Size = File, fi.Size()
		f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return e, err
		}
		h := sha256.New()
		fmt.Fprintf(h, "size %d\n", e.Size)
		err = dataExtents(f, e.Size, func(off, n int64) error {
			fmt.Fprintf(h, "extent %d %d\n", off, n)
			_, err := io.Copy(h, io.NewSectionReader(f, off, n))
			return err
		})
		f.Close()
		if err != nil {
			return e, err
		}
		copy(e.Sum[:], h.Sum(nil))
		e.Xattrs = guestXattrs(p)
	case m.IsDir():
		e.Kind = Dir
		var buf [8]byte
		n, err := syscall.Getxattr(p, opaqueXattr, buf[:])
		e.Opaque = err == nil && n == 1 && buf[0] == 'y'
		e.Xattrs = guestXattrs(p)
	case m&fs.ModeSymlink != 0:
		e.Kind = Symlink
		t, err := os.Readlink(p)
		if err != nil {
			return e, err
		}
		e.Target = t
	case m&fs.ModeCharDevice != 0 && isWhiteoutDev(fi):
		e.Kind = Whiteout
	default:
		e.Kind = Other
	}
	return e, nil
}

// dataExtents calls fn for each data extent of f, skipping holes, so a
// sparse file costs only its data to hash or copy.
func dataExtents(f *os.File, size int64, fn func(off, n int64) error) error {
	const seekData, seekHole = 3, 4
	for off := int64(0); off < size; {
		start, err := f.Seek(off, seekData)
		if errors.Is(err, syscall.ENXIO) {
			return nil // only a hole remains
		}
		if errors.Is(err, syscall.EINVAL) {
			return fn(off, size-off) // no SEEK_DATA support: all data
		}
		if err != nil {
			return err
		}
		end, err := f.Seek(start, seekHole)
		if err != nil {
			return err
		}
		if end > size {
			end = size
		}
		if err := fn(start, end-start); err != nil {
			return err
		}
		off = end
	}
	return nil
}

// guestXattrs lists the extended attributes a guest sees (overlayfs's own
// are excluded), canonically, so ownership-like changes such as setcap
// count as changes.
func guestXattrs(p string) string {
	names := listXattrs(p)
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, overlayXattrs) {
			continue
		}
		if v, ok := getXattr(p, n); ok {
			out = append(out, n+"="+hex.EncodeToString(v))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ";")
}

func listXattrs(p string) []string {
	sz, err := syscall.Listxattr(p, nil)
	if err != nil || sz == 0 {
		return nil
	}
	buf := make([]byte, sz)
	sz, err = syscall.Listxattr(p, buf)
	if err != nil {
		return nil
	}
	var out []string
	for _, n := range strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00") {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

func getXattr(p, name string) ([]byte, bool) {
	sz, err := syscall.Getxattr(p, name, nil)
	if err != nil {
		return nil, false
	}
	v := make([]byte, sz)
	sz, err = syscall.Getxattr(p, name, v)
	if err != nil {
		return nil, false
	}
	return v[:sz], true
}

func isWhiteoutDev(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

// Scan lists every path in a layer, relative to root, with its entry. It
// never follows symlinks.
func Scan(root string) (map[string]Entry, error) {
	out := map[string]Entry{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		e, err := describe(p, fi)
		if err != nil {
			return err
		}
		out[rel] = e
		return nil
	})
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	return out, err
}

// Usage is what a layer costs on disk: allocated bytes (holes are free)
// and inodes, each hardlinked inode counted once.
type Usage struct{ Bytes, Inodes int64 }

// FreeBytes is the space available to the broker on the file system that
// holds path.
func FreeBytes(path string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

// MaxTreeDepth is how deeply Measure follows nested directories: as deep as
// a worker's deletes go (CAP-8c's too_deep), with one open directory
// handle per level.
const MaxTreeDepth = 256

// ErrTooDeep is a layer nested deeper than MaxTreeDepth. Callers treat it as
// over the layer's cap: never as no use.
var ErrTooDeep = errors.New("directories nest more than 256 deep; flatten them")

// Measure returns a layer's usage without following symlinks. It may run
// on a live layer: files that vanish mid-walk are skipped. It walks by
// directory handles, never by host path, so a layer nested past the host's
// path limit is still counted (security R4 on #166); one nested deeper
// than MaxTreeDepth is ErrTooDeep.
func Measure(root string) (Usage, error) {
	w := measurer{seen: map[[2]uint64]bool{}}
	// Errors name no host path: they can reach a guest's text (security
	// N2 on #174).
	fd, err := syscall.Open(root, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return w.u, fmt.Errorf("overlay: measure: %w", err)
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		syscall.Close(fd)
		if err == nil {
			err = syscall.ENOTDIR // a layer is a directory, never a link to one
		}
		return w.u, fmt.Errorf("overlay: measure: %w", err)
	}
	if err = w.handle(fd, 0); err != nil && !errors.Is(err, ErrTooDeep) {
		err = fmt.Errorf("overlay: measure: %w", err)
	}
	return w.u, err
}

// oPath is O_PATH, which syscall leaves undefined on amd64: a handle that
// can be stat'd and opened relative to, but not read, so an entry is
// never opened as a device or FIFO to learn what it is.
const oPath = 0x200000

type measurer struct {
	u    Usage
	seen map[[2]uint64]bool
}

// handle counts the entry O_PATH handle fd names, depth levels below the
// root, and what it holds if it is a directory; it closes fd.
func (w *measurer) handle(fd, depth int) error {
	var st syscall.Stat_t
	err := syscall.Fstat(fd, &st)
	key := [2]uint64{uint64(st.Dev), st.Ino}
	dir := err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR && !w.seen[key]
	if err == nil && !w.seen[key] {
		w.seen[key] = true
		w.u.Inodes++
		w.u.Bytes += st.Blocks * 512
	}
	if dir && depth > MaxTreeDepth {
		err = ErrTooDeep
	}
	if !dir || err != nil {
		syscall.Close(fd)
		return err
	}
	// "." through the handle is the directory just stat'd, whatever its
	// name now points at. One handle per level stays open below here.
	dfd, err := syscall.Openat(fd, ".", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	syscall.Close(fd)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(dfd), "")
	defer f.Close()
	for {
		ents, err := f.ReadDir(256)
		for _, e := range ents {
			cfd, err := syscall.Openat(dfd, e.Name(), oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
			if errors.Is(err, syscall.ENOENT) {
				continue // removed since its directory was read
			}
			if err != nil {
				return err
			}
			if err := w.handle(cfd, depth+1); err != nil {
				return err
			}
		}
		switch {
		case err == io.EOF:
			return nil
		case depth > 0 && errors.Is(err, syscall.ENOENT):
			return nil // removed while it was read
		case err != nil:
			return err
		}
	}
}

// View is what a guest sees: an upper layer over a lower one.
type View struct{ Lower, Upper string }

// Lookup returns the entry the guest sees at rel, and the layer root it
// comes from ("" when absent).
func (v View) Lookup(rel string) (Entry, string, error) {
	parts, err := split(rel)
	if err != nil {
		return Entry{}, "", err
	}
	lowerHidden := false
	for i := 1; i < len(parts); i++ {
		e, err := Stat(v.Upper, filepath.Join(parts[:i]...))
		if err != nil {
			return Entry{}, "", err
		}
		switch {
		case e.Kind == Whiteout, e.Kind != Absent && e.Kind != Dir:
			return Entry{}, "", nil
		case e.Kind == Dir && e.Opaque:
			lowerHidden = true
		}
	}
	e, err := Stat(v.Upper, rel)
	if err != nil {
		return Entry{}, "", err
	}
	switch {
	case e.Kind == Whiteout:
		return Entry{}, "", nil
	case e.Kind != Absent:
		e.Opaque = false // a view has no layers below it
		return e, v.Upper, nil
	case lowerHidden:
		return Entry{}, "", nil
	}
	e, err = Stat(v.Lower, rel)
	if err != nil || e.Kind == Absent {
		return Entry{}, "", err
	}
	return e, v.Lower, nil
}

// Change is one path that differs between two views.
type Change struct {
	Path     string
	From, To Entry
}

// Op names the change: added, removed, or modified.
func (c Change) Op() string {
	switch {
	case c.From.Kind == Absent:
		return "added"
	case c.To.Kind == Absent:
		return "removed"
	}
	return "modified"
}

// Diff lists the paths whose view differs between a and b, sorted. Both
// views must share a lower layer (the machine image).
func Diff(a, b View) ([]Change, error) {
	paths := map[string]bool{}
	for _, v := range []View{a, b} {
		ents, err := Scan(v.Upper)
		if err != nil {
			return nil, err
		}
		for rel, e := range ents {
			paths[rel] = true
			// An opaque directory or a whiteout hides lower paths beneath it;
			// those count as changes too.
			if (e.Kind == Dir && e.Opaque) || e.Kind == Whiteout {
				le, err := Stat(v.Lower, rel)
				if err != nil {
					return nil, err
				}
				if le.Kind != Dir {
					continue
				}
				low, err := Scan(filepath.Join(v.Lower, rel))
				if err != nil {
					return nil, err
				}
				for r := range low {
					paths[filepath.Join(rel, r)] = true
				}
			}
		}
	}
	var out []Change
	for rel := range paths {
		ea, _, err := a.Lookup(rel)
		if err != nil {
			return nil, err
		}
		eb, _, err := b.Lookup(rel)
		if err != nil {
			return nil, err
		}
		if !ea.Same(eb) {
			out = append(out, Change{Path: rel, From: ea, To: eb})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Put makes dst's view show at rel what src's view shows there. dst must not
// be mounted. Parent directories missing from dst's upper layer are created
// with the modes src's view gives them.
func Put(dst, src View, rel string) error {
	e, from, err := src.Lookup(rel)
	if err != nil {
		return err
	}
	seen, _, err := dst.Lookup(rel)
	if err != nil {
		return err
	}
	if e.Kind == Absent && seen.Kind == Absent {
		return nil
	}
	if err := ensureParents(dst, src, rel); err != nil {
		return err
	}
	if e.Kind == Absent {
		// Putting a parent may already have removed rel.
		if now, _, err := dst.Lookup(rel); err != nil || now.Kind == Absent {
			return err
		}
	}
	p := filepath.Join(dst.Upper, rel)
	cur, err := Stat(dst.Upper, rel)
	if err != nil {
		return err
	}
	if cur.Kind != Absent && !(cur.Kind == Dir && e.Kind == Dir) {
		if err := os.RemoveAll(p); err != nil {
			return err
		}
	}
	lower, err := Stat(dst.Lower, rel)
	if err != nil {
		return err
	}
	switch e.Kind {
	case Absent:
		if lower.Kind != Absent {
			return syscall.Mknod(p, syscall.S_IFCHR, 0)
		}
		return nil
	case Dir:
		if err := os.Mkdir(p, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		// The directory's own metadata is part of the change: owner, then
		// mode (chown clears setgid), then guest xattrs.
		if err := os.Lchown(p, int(e.Uid), int(e.Gid)); err != nil {
			return err
		}
		if err := os.Chmod(p, e.Mode); err != nil {
			return err
		}
		syncGuestXattrs(filepath.Join(from, rel), p)
		if seen.Kind != Dir && lower.Kind != Absent {
			// The guest saw no directory here, so what the image has below
			// must stay hidden.
			return syscall.Setxattr(p, opaqueXattr, []byte("y"), 0)
		}
		return nil
	default:
		return copyOne(filepath.Join(from, rel), p)
	}
}

func ensureParents(dst, src View, rel string) error {
	parts, err := split(rel)
	if err != nil {
		return err
	}
	for i := 1; i < len(parts); i++ {
		r := filepath.Join(parts[:i]...)
		cur, err := Stat(dst.Upper, r)
		if err != nil {
			return err
		}
		if cur.Kind == Dir {
			continue
		}
		if err := Put(dst, src, r); err != nil {
			return err
		}
	}
	return nil
}

// Copy copies layer src to a new directory dst. It keeps modes, owners,
// whiteouts, opaque markers, symlinks, guest xattrs, holes, and hardlinks,
// so a copy costs what the source costs on disk. It refuses device nodes,
// FIFOs, and sockets, and drops overlayfs xattrs other than a valid opaque
// marker (redirect, metacopy, origin).
func Copy(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("overlay: %s already exists", dst)
	}
	links := map[[2]uint64]string{}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		return copyObj(p, filepath.Join(dst, rel), links)
	})
}

// copyOne copies a single file-system object (not a directory's contents).
func copyOne(src, dst string) error { return copyObj(src, dst, nil) }

func copyObj(src, dst string, links map[[2]uint64]string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnsafe, src)
	}
	switch m := fi.Mode(); {
	case m.IsDir():
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
	case m.IsRegular():
		key := [2]uint64{uint64(st.Dev), st.Ino}
		if prev, ok := links[key]; ok && st.Nlink > 1 {
			return os.Link(prev, dst) // same inode: owner, mode, xattrs shared
		}
		if err := copyFile(src, dst, fi.Size()); err != nil {
			return err
		}
		if links != nil && st.Nlink > 1 {
			links[key] = dst
		}
	case m&fs.ModeSymlink != 0:
		t, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(t, dst); err != nil {
			return err
		}
		return os.Lchown(dst, int(st.Uid), int(st.Gid))
	case m&fs.ModeCharDevice != 0 && st.Rdev == 0:
		if err := syscall.Mknod(dst, syscall.S_IFCHR, 0); err != nil { // whiteout
			return err
		}
		return os.Lchown(dst, int(st.Uid), int(st.Gid))
	default:
		return fmt.Errorf("%w: %s is a %v; only files, directories, symlinks and whiteouts are kept", ErrUnsafe, src, m.Type())
	}
	if err := os.Lchown(dst, int(st.Uid), int(st.Gid)); err != nil {
		return err
	}
	if err := os.Chmod(dst, fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
		return err
	}
	if err := copyXattrs(src, dst); err != nil {
		return err
	}
	at := syscall.NsecToTimespec(syscall.TimespecToNsec(st.Atim))
	mt := syscall.NsecToTimespec(syscall.TimespecToNsec(st.Mtim))
	return syscall.UtimesNano(dst, []syscall.Timespec{at, mt})
}

const ficlone = 0x40049409 // FICLONE ioctl: share extents (reflink)

// copyFile copies a regular file, by reflink where the file system has it,
// otherwise extent by extent so holes stay holes.
func copyFile(src, dst string, size int64) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, out.Fd(), ficlone, in.Fd()); e == 0 {
		return out.Close()
	}
	err = dataExtents(in, size, func(off, n int64) error {
		_, err := io.Copy(io.NewOffsetWriter(out, off), io.NewSectionReader(in, off, n))
		return err
	})
	if err == nil {
		err = out.Truncate(size)
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyXattrs copies guest xattrs and a valid opaque marker. Other overlayfs
// xattrs (redirect, metacopy, origin) would let a layer point the kernel
// at paths the broker never checked, so they are dropped.
func copyXattrs(src, dst string) error {
	for _, name := range listXattrs(src) {
		v, ok := getXattr(src, name)
		if !ok {
			continue
		}
		if strings.HasPrefix(name, overlayXattrs) {
			if name != opaqueXattr || string(v) != "y" {
				continue
			}
			if err := syscall.Setxattr(dst, name, v, 0); err != nil {
				return fmt.Errorf("overlay: opaque marker on %s: %w", dst, err)
			}
			continue
		}
		syscall.Setxattr(dst, name, v, 0) // best effort, as cp -a does
	}
	return nil
}

// syncGuestXattrs makes dst's guest xattrs those of src, best effort as
// copyXattrs is. Overlay xattrs on either side are left alone: whether dst
// is opaque is decided by Put, not taken from another layer.
func syncGuestXattrs(src, dst string) {
	want := map[string][]byte{}
	for _, n := range listXattrs(src) {
		if strings.HasPrefix(n, overlayXattrs) {
			continue
		}
		if v, ok := getXattr(src, n); ok {
			want[n] = v
		}
	}
	for _, n := range listXattrs(dst) {
		if _, ok := want[n]; !ok && !strings.HasPrefix(n, overlayXattrs) {
			syscall.Removexattr(dst, n)
		}
	}
	for n, v := range want {
		syscall.Setxattr(dst, n, v, 0)
	}
}

// MountOptions are the overlayfs options for a machine's root: features
// that follow xattr pointers to other paths are off.
func MountOptions(lower, upper, work string) string {
	return "lowerdir=" + lower + ",upperdir=" + upper + ",workdir=" + work +
		",redirect_dir=off,metacopy=off,index=off"
}
