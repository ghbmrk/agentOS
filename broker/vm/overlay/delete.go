package overlay

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Delete outcomes, one per path asked (CAP-8c, security R-DEL3, R-DEL5).
const (
	Removed       = "removed"           // gone from the upper layer
	RemovedBase   = "removed_base_back" // gone, and the base image's version shows again
	NotFound      = "not_found"         // the guest sees nothing there
	BaseImage     = "base_image"        // only in the base image: nothing to free
	NotEmpty      = "not_empty"         // a directory, and recursive was not asked
	SymlinkInPath = "symlink_in_path"   // a parent is a symlink: name the real path
	MountPoint    = "mount_point"       // another file system: refused
	BadPath       = "bad_path"          // not a clean absolute path below /
	MoreRemains   = "more_remains"      // the entry budget ran out part way
	TooDeep       = "too_deep"          // nested deeper than MaxTreeDepth: delete a deeper path first
	DeleteFailed  = "delete_failed"     // the broker could not finish: nothing more is said to the guest
)

// ErrDeleteFailed is Delete's only error: the cause, which may name host
// paths, is DeleteResult.Fault, for the broker's log (L3 S1 on #166).
var ErrDeleteFailed = errors.New("overlay: delete_failed")

// MaxTreeDepth bounds how deep a recursive delete descends: each level
// holds a directory handle, so a worker's deep chain of directories must
// not exhaust the broker's handles or memory (L3 MUST-1 on #166). A
// deeper tree is shortened by deleting a deeper path first.
const MaxTreeDepth = 256

// deleteTimeout bounds one Delete's wall-clock time; what remains is
// more_remains (security on #166). clock is the time; tests replace both.
var (
	deleteTimeout = 10 * time.Second
	clock         = time.Now
)

// unlinkat removes a non-directory entry; tests inject failures.
var unlinkat = syscall.Unlinkat

// DeleteResult is what Delete did: a code per path, in order, and counts.
// It names no file beyond the paths asked.
type DeleteResult struct {
	Codes []string
	Files int   // entries removed (files, links, directories)
	Bytes int64 // bytes of blocks freed, counting files with no other link
	More  bool  // the budget or the time ran out; asking again continues
	// Fault is the first failure behind a delete_failed code or
	// ErrDeleteFailed. It may name host paths: log it, never answer it.
	Fault error
}

const (
	oPath      = 0x200000 // O_PATH: a handle on the entry itself, opens nothing
	maxPathLen = 4096
	maxNameLen = 255
)

// Delete removes paths, as the guest names them, from the upper layer of
// a stopped machine whose base image is lower, removing at most
// maxEntries entries (security R-DEL2 on CAP-8c).
//
// It works from a handle on upper and resolves each path one component at
// a time with O_NOFOLLOW, refusing a symlinked parent and any component
// that is a mount point (by the mount table, which also lists bind mounts
// from the same file system; a device check backs it up for a mount made
// after the table was read), the effect of openat2's RESOLVE_IN_ROOT,
// NO_SYMLINKS, NO_MAGICLINKS and NO_XDEV with the standard library alone
// (ARC-2 keeps unsafe and third-party code out of the machine plane).
// Entries go with unlinkat, so a symlink is removed itself and never
// followed; the recursive walk is relative to directory handles. Nothing
// is created in upper: no whiteout, opaque marker or xattr. So a path
// only in the base image is refused, and removing an upper copy may bring
// the base version back, which the code says.
//
// A path that fails part way gets delete_failed and the next path is
// tried; a failure before any path (upper or the mount table unreadable)
// is ErrDeleteFailed. Either way the cause is only in Fault, so nothing
// the guest sees names a host path or an errno (L3 S1 on #166).
func Delete(upper, lower string, paths []string, recursive bool, maxEntries int) (DeleteResult, error) {
	out, err := deleteAll(upper, lower, paths, recursive, maxEntries)
	if err != nil {
		out.Fault = err
		return out, ErrDeleteFailed
	}
	return out, nil
}

func deleteAll(upper, lower string, paths []string, recursive bool, maxEntries int) (DeleteResult, error) {
	root, err := syscall.Open(upper, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return DeleteResult{}, &os.PathError{Op: "open", Path: upper, Err: err}
	}
	defer syscall.Close(root)
	var st syscall.Stat_t
	if err := syscall.Fstat(root, &st); err != nil {
		return DeleteResult{}, err
	}
	mounts, base, err := mountsUnder(upper)
	if err != nil {
		return DeleteResult{}, err
	}
	d := &deleter{v: View{Lower: lower, Upper: upper}, root: root, dev: st.Dev, left: maxEntries, mounts: mounts, base: base,
		deadline: clock().Add(deleteTimeout)}
	out := DeleteResult{Codes: make([]string, len(paths))}
	for i, p := range paths {
		if d.spent() {
			out.Codes[i], out.More = MoreRemains, true
			continue
		}
		code, err := d.one(p, recursive)
		if err != nil {
			code = DeleteFailed
			if out.Fault == nil {
				out.Fault = err
			}
		}
		out.Codes[i] = code
		out.More = out.More || code == MoreRemains
	}
	out.Files, out.Bytes = d.files, d.bytes
	return out, nil
}

type deleter struct {
	v      View
	root   int
	dev    uint64
	left   int
	files  int
	bytes  int64
	mounts map[string]bool // mount points below upper, by host path
	base   string          // upper's host path, as mountinfo names it

	deadline time.Time
}

// spent says the entry budget or the time ran out.
func (d *deleter) spent() bool {
	return d.left <= 0 || clock().After(d.deadline)
}

// mounted says whether the entry at parts is a mount point. A bind mount
// from the same file system keeps its device number, so the device check
// alone would miss it (RESOLVE_NO_XDEV refuses any mount).
func (d *deleter) mounted(parts []string) bool {
	return len(d.mounts) > 0 && d.mounts[filepath.Join(append([]string{d.base}, parts...)...)]
}

// mountsUnder lists the mount points strictly below dir from
// /proc/self/mountinfo, failing closed when it cannot be read.
func mountsUnder(dir string) (map[string]bool, string, error) {
	base, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, "", err
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, "", err
	}
	out := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := unescapeMount(f[4])
		if strings.HasPrefix(mp, base+"/") {
			out[mp] = true
		}
	}
	return out, base, nil
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// guestParts checks a guest path and returns its components below /.
func guestParts(p string) ([]string, bool) {
	if len(p) > maxPathLen || !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) || filepath.Clean(p) != p || p == "/" {
		return nil, false
	}
	parts := strings.Split(p[1:], "/")
	for _, c := range parts {
		if len(c) > maxNameLen {
			return nil, false
		}
	}
	// Room for a recursive walk's names, so descending never copies.
	return append(make([]string, 0, len(parts)+MaxTreeDepth+1), parts...), true
}

func (d *deleter) one(p string, recursive bool) (string, error) {
	parts, ok := guestParts(p)
	if !ok {
		return BadPath, nil
	}
	code, err := d.oneParts(parts, recursive)
	if errors.Is(err, syscall.ENAMETOOLONG) {
		return BadPath, nil // the host path is too long for the kernel
	}
	return code, err
}

func (d *deleter) oneParts(parts []string, recursive bool) (string, error) {
	dir, code, err := d.parent(parts[:len(parts)-1])
	if err != nil || code == SymlinkInPath || code == MountPoint {
		return code, err
	}
	if code == "" {
		defer syscall.Close(dir)
	}
	switch layer, err := d.v.visible(parts); {
	case err != nil:
		return "", err
	case layer == "":
		return NotFound, nil
	case layer == d.v.Lower:
		return BaseImage, nil
	case code != "":
		return code, nil // shown from upper yet its parent is missing: never
	}
	name := parts[len(parts)-1]
	st, err := statAt(dir, name)
	if err != nil {
		return "", err
	}
	if st.Dev != d.dev || d.mounted(parts) {
		return MountPoint, nil
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		if !recursive {
			if err := rmdirAt(dir, name); errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
				return NotEmpty, nil
			} else if err != nil {
				return "", err
			}
			d.files++
			d.left--
			return d.after(parts)
		}
		done, code, err := d.removeTree(dir, name, parts, 1)
		if err != nil || code != "" {
			return code, err
		}
		if !done {
			return MoreRemains, nil
		}
		return d.after(parts)
	}
	if err := d.unlink(dir, name, st); err != nil {
		return "", err
	}
	return d.after(parts)
}

// after says whether the base image's version shows once the upper copy
// is gone.
func (d *deleter) after(parts []string) (string, error) {
	layer, err := d.v.visible(parts)
	if err != nil {
		return "", err
	}
	if layer == d.v.Lower {
		return RemovedBase, nil
	}
	return Removed, nil
}

// parent opens the upper directory holding a path, one component at a
// time beneath the root handle, following no symlink and leaving no file
// system.
func (d *deleter) parent(parts []string) (int, string, error) {
	cur, err := syscall.Dup(d.root)
	if err != nil {
		return -1, "", err
	}
	for i, c := range parts {
		if d.mounted(parts[:i+1]) {
			syscall.Close(cur)
			return -1, MountPoint, nil
		}
		next, err := syscall.Openat(cur, c, oPath|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			code := ""
			if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
				if st, serr := statAt(cur, c); serr == nil && st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
					code = SymlinkInPath
				} else {
					code = NotFound
				}
			} else if errors.Is(err, syscall.ENOENT) {
				code = NotFound
			}
			syscall.Close(cur)
			if code != "" {
				return -1, code, nil
			}
			return -1, "", err
		}
		syscall.Close(cur)
		cur = next
		var st syscall.Stat_t
		if err := syscall.Fstat(cur, &st); err != nil {
			syscall.Close(cur)
			return -1, "", err
		}
		if st.Dev != d.dev {
			syscall.Close(cur)
			return -1, MountPoint, nil
		}
	}
	return cur, "", nil
}

// removeTree empties and removes directory name under dir, within the
// entry budget. done is false when the budget ran out first.
func (d *deleter) removeTree(dir int, name string, parts []string, depth int) (done bool, code string, err error) {
	if depth > MaxTreeDepth {
		return false, TooDeep, nil
	}
	fd, err := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false, "", err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return false, "", err
	}
	if st.Dev != d.dev {
		return false, MountPoint, nil
	}
	for {
		ents, rerr := f.ReadDir(256)
		for _, e := range ents {
			if d.spent() {
				return false, "", nil
			}
			cst, err := statAt(fd, e.Name())
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return false, "", err
			}
			// parts has room for the walk's names (guestParts), so this
			// writes in place: each level owns only its own last slot.
			child := append(parts, e.Name())
			if cst.Dev != d.dev || d.mounted(child) {
				return false, MountPoint, nil
			}
			if cst.Mode&syscall.S_IFMT == syscall.S_IFDIR {
				ok, code, err := d.removeTree(fd, e.Name(), child, depth+1)
				if err != nil || code != "" || !ok {
					return false, code, err
				}
				continue
			}
			if err := d.unlink(fd, e.Name(), cst); err != nil {
				return false, "", err
			}
		}
		if rerr == io.EOF || len(ents) == 0 {
			break
		}
		if rerr != nil {
			return false, "", rerr
		}
	}
	if d.spent() {
		return false, "", nil
	}
	if err := rmdirAt(dir, name); err != nil {
		return false, "", err
	}
	d.files++
	d.left--
	return true, "", nil
}

func (d *deleter) unlink(dir int, name string, st syscall.Stat_t) error {
	if err := unlinkat(dir, name); err != nil {
		return err
	}
	d.files++
	d.left--
	if st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Nlink == 1 {
		d.bytes += st.Blocks * 512
	}
	return nil
}

// statAt describes entry name in dir without following it: an O_PATH,
// O_NOFOLLOW handle on the entry itself (a symlink's handle is the link).
func statAt(dir int, name string) (syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, err := syscall.Openat(dir, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return st, &os.PathError{Op: "openat", Path: name, Err: err}
	}
	defer syscall.Close(fd)
	err = syscall.Fstat(fd, &st)
	return st, err
}

// rmdirAt removes empty directory name in dir. The standard library has
// no unlinkat(AT_REMOVEDIR), so it names the directory through dir's own
// handle (/proc/self/fd), which resolves to dir itself; rmdir never
// follows its last component.
func rmdirAt(dir int, name string) error {
	return syscall.Rmdir("/proc/self/fd/" + strconv.Itoa(dir) + "/" + name)
}

// visible is the layer a guest path shows from: upper, lower, or "" when
// the guest sees nothing there. It reads kinds only, never contents, so
// large files cost nothing (View.Lookup hashes them).
func (v View) visible(parts []string) (string, error) {
	lowerHidden := false
	for i := 1; i <= len(parts); i++ {
		k, opaque, err := kindAt(v.Upper, parts[:i])
		if err != nil {
			return "", err
		}
		last := i == len(parts)
		switch {
		case k == Whiteout:
			return "", nil
		case last && k != Absent:
			return v.Upper, nil
		case !last && k != Absent && k != Dir:
			return "", nil
		case k == Dir && opaque:
			lowerHidden = true
		}
	}
	if lowerHidden {
		return "", nil
	}
	k, _, err := kindAt(v.Lower, parts)
	if err != nil || k == Absent {
		return "", err
	}
	return v.Lower, nil
}

// kindAt is what parts names beneath root, with no symlink followed: a
// path under a symlink or other non-directory is Absent.
func kindAt(root string, parts []string) (Kind, bool, error) {
	p := root
	for i, part := range parts {
		p = filepath.Join(p, part)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return Absent, false, nil
		}
		if err != nil {
			return Absent, false, err
		}
		if i < len(parts)-1 {
			if !fi.IsDir() {
				return Absent, false, nil
			}
			continue
		}
		switch m := fi.Mode(); {
		case m&fs.ModeCharDevice != 0 && isWhiteoutDev(fi):
			return Whiteout, false, nil
		case m.IsDir():
			var buf [8]byte
			n, err := syscall.Getxattr(p, opaqueXattr, buf[:])
			return Dir, err == nil && n == 1 && buf[0] == 'y', nil
		case m&fs.ModeSymlink != 0:
			return Symlink, false, nil
		case m.IsRegular():
			return File, false, nil
		default:
			return Other, false, nil
		}
	}
	return Absent, false, nil
}
