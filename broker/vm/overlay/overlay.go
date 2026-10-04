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
	Kind   Kind
	Mode   fs.FileMode // permission and special bits
	Size   int64
	Sum    [32]byte // SHA-256 of a file's content
	Target string   // symlink target
	Opaque bool     // directory hides the layers below it
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
		return e.Mode == o.Mode && e.Size == o.Size && e.Sum == o.Sum
	case Symlink:
		return e.Target == o.Target
	default:
		return e.Mode == o.Mode
	}
}

const opaqueXattr = "trusted.overlay.opaque"

// Stat describes path rel inside layer root. A missing path is Absent.
func Stat(root, rel string) (Entry, error) {
	p := filepath.Join(root, rel)
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return Entry{}, nil
	}
	if err != nil {
		return Entry{}, err
	}
	return describe(p, fi)
}

func describe(p string, fi fs.FileInfo) (Entry, error) {
	e := Entry{Mode: fi.Mode() & (fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky)}
	switch m := fi.Mode(); {
	case m.IsRegular():
		e.Kind, e.Size = File, fi.Size()
		f, err := os.Open(p)
		if err != nil {
			return e, err
		}
		h := sha256.New()
		_, err = io.Copy(h, f)
		f.Close()
		if err != nil {
			return e, err
		}
		copy(e.Sum[:], h.Sum(nil))
	case m.IsDir():
		e.Kind = Dir
		var buf [8]byte
		n, err := syscall.Getxattr(p, opaqueXattr, buf[:])
		e.Opaque = err == nil && n == 1 && buf[0] == 'y'
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

func isWhiteoutDev(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && st.Rdev == 0
}

// Scan lists every path in a layer, relative to root, with its entry.
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

// View is what a guest sees: an upper layer over a lower one.
type View struct{ Lower, Upper string }

// Lookup returns the entry the guest sees at rel, and the layer root it
// comes from ("" when absent).
func (v View) Lookup(rel string) (Entry, string, error) {
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
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
				low, err := Scan(filepath.Join(v.Lower, rel))
				if err != nil && !errors.Is(err, syscall.ENOTDIR) {
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
		if err := os.Chmod(p, e.Mode); err != nil {
			return err
		}
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
	parts := strings.Split(filepath.Clean(rel), string(filepath.Separator))
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

// Copy copies layer src to a new directory dst, keeping modes, owners,
// whiteouts, opaque markers, symlinks, and other extended attributes.
func Copy(src, dst string) error {
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("overlay: %s already exists", dst)
	}
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		return copyOne(p, filepath.Join(dst, rel))
	})
}

// copyOne copies a single file-system object (not a directory's contents).
func copyOne(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	st, _ := fi.Sys().(*syscall.Stat_t)
	switch m := fi.Mode(); {
	case m.IsDir():
		if err := os.Mkdir(dst, 0o700); err != nil {
			return err
		}
	case m.IsRegular():
		if err := copyFile(src, dst); err != nil {
			return err
		}
	case m&fs.ModeSymlink != 0:
		t, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(t, dst); err != nil {
			return err
		}
	default:
		if st == nil {
			return fmt.Errorf("overlay: cannot copy %s", src)
		}
		if err := syscall.Mknod(dst, st.Mode, int(st.Rdev)); err != nil {
			return err
		}
	}
	if st != nil {
		if err := os.Lchown(dst, int(st.Uid), int(st.Gid)); err != nil {
			return err
		}
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		if err := os.Chmod(dst, fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky)); err != nil {
			return err
		}
		if err := copyXattrs(src, dst); err != nil {
			return err
		}
	}
	if st != nil && fi.Mode()&fs.ModeSymlink == 0 {
		at := syscall.NsecToTimespec(syscall.TimespecToNsec(st.Atim))
		mt := syscall.NsecToTimespec(syscall.TimespecToNsec(st.Mtim))
		syscall.UtimesNano(dst, []syscall.Timespec{at, mt})
	}
	return nil
}

const ficlone = 0x40049409 // FICLONE ioctl: share extents (reflink)

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, out.Fd(), ficlone, in.Fd()); e != 0 {
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
	}
	return out.Close()
}

func copyXattrs(src, dst string) error {
	sz, err := syscall.Listxattr(src, nil)
	if err != nil || sz == 0 {
		return nil // no xattr support or none set
	}
	buf := make([]byte, sz)
	sz, err = syscall.Listxattr(src, buf)
	if err != nil {
		return nil
	}
	for _, name := range strings.Split(strings.TrimRight(string(buf[:sz]), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		vsz, err := syscall.Getxattr(src, name, nil)
		if err != nil {
			continue
		}
		v := make([]byte, vsz)
		if vsz, err = syscall.Getxattr(src, name, v); err != nil {
			continue
		}
		if err := syscall.Setxattr(dst, name, v[:vsz], 0); err != nil && strings.HasPrefix(name, "trusted.overlay.") {
			// Losing an overlay marker would change what the guest sees.
			return fmt.Errorf("overlay: %s on %s: %w", name, dst, err)
		}
	}
	return nil
}
