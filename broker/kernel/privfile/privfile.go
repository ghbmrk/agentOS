// Package privfile holds a process's own private files: a check that a path
// is this uid's alone, and a write that a crash leaves whole. The kernel's
// process (broker/kernel/proc) and the clerks' (broker/clerk/run) both use it;
// it was split out of broker/clerk/run so the kernel links no clerk code
// (KRN-2 split, #2892). The error texts keep their run: prefix.
package privfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// Check checks that path is this uid's own, open to no other uid, and not a
// symlink.
func Check(path string, dir bool) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return ownOnly(path, fi, dir)
}

// CheckFile is Check for an open file.
func CheckFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	return ownOnly(f.Name(), fi, false)
}

func ownOnly(path string, fi os.FileInfo, dir bool) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		return fmt.Errorf("run: %s: no owner", path)
	case dir && !fi.IsDir(), !dir && !fi.Mode().IsRegular():
		return fmt.Errorf("run: %s: not a plain %s", path, map[bool]string{true: "directory", false: "file"}[dir])
	case int(st.Uid) != os.Geteuid():
		return fmt.Errorf("run: %s: owned by uid %d, not this clerk's", path, st.Uid)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("run: %s: open to other uids (%v)", path, fi.Mode().Perm())
	}
	return nil
}

// WriteAtomic replaces the file name in dir with b so that a crash at any
// point leaves one whole form, the old or the new (#2643 c): write name.tmp,
// fsync it, rename it over the old one, fsync the directory. A temporary left
// by a crash is never read and is replaced here. stop, for tests only, ends
// the write after step i as a crash would; nil runs every step.
//
// dir is opened once, not followed if it is a link, and refused unless no
// other uid can write it (openDir); the removal, create and rename then work
// on that open directory, so another uid can neither swap name.tmp for a link
// that the rename installs at name nor swap dir itself (#3954).
func WriteAtomic(dir, name string, b []byte, stop func(i int) bool) error {
	d, err := openDir(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	fd, tmp := int(d.Fd()), name+".tmp"
	var f *os.File
	steps := []func() error{
		func() error {
			if err := unix.Unlinkat(fd, tmp, 0); err != nil && !errors.Is(err, unix.ENOENT) {
				return &os.PathError{Op: "remove", Path: filepath.Join(dir, tmp), Err: err}
			}
			t, err := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
			if err != nil {
				return &os.PathError{Op: "open", Path: filepath.Join(dir, tmp), Err: err}
			}
			f = os.NewFile(uintptr(t), filepath.Join(dir, tmp))
			return nil
		},
		func() error { _, err := f.Write(b); return err },
		func() error { return f.Sync() },
		func() error { return f.Close() },
		func() error {
			if err := unix.Renameat(fd, tmp, fd, name); err != nil { // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the new core cannot list here; this is sealed content, not a lifecycle, and the next step syncs the directory
				return &os.LinkError{Op: "rename", Old: filepath.Join(dir, tmp), New: filepath.Join(dir, name), Err: err}
			}
			return nil
		},
		func() error {
			if err := SyncDir(dir); err != nil {
				return fmt.Errorf("%w: %w", ErrUnsynced, err)
			}
			return nil
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			if f != nil && i < 3 {
				f.Close()
			}
			return err
		}
		if stop != nil && stop(i) {
			if f != nil && i < 3 {
				f.Close()
			}
			return ErrStopped
		}
	}
	return nil
}

// openDir opens dir without following a link at it, and refuses it unless
// it is a directory that no other uid can write: owned by this uid or root,
// with no group or other write bit. That is weaker than Check, which also
// refuses a readable directory, because some callers' directories are
// legitimately 0755 (agentosd's StateDirectoryMode). ACLs are not read.
func openDir(dir string) (*os.File, error) {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fi, err := d.Stat()
	if err != nil {
		d.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !ok:
		err = fmt.Errorf("run: %s: no owner", dir)
	case int(st.Uid) != os.Geteuid() && st.Uid != 0:
		err = fmt.Errorf("run: %s: owned by uid %d, not this uid or root", dir, st.Uid)
	case fi.Mode().Perm()&0o022 != 0:
		err = fmt.Errorf("run: %s: other uids can write it (%v)", dir, fi.Mode().Perm())
	}
	if err != nil {
		d.Close()
		return nil, err
	}
	return d, nil
}

// ErrStopped ends a write that its stop hook stopped, as a crash would.
var ErrStopped = errors.New("run: write stopped")

// ErrUnsynced is a write whose rename succeeded but whose directory sync
// failed: the new form is in place, and may or may not survive a crash, so
// the write neither failed nor took effect for certain (#2742 item 7).
var ErrUnsynced = errors.New("run: written, but the directory sync failed")

// SyncDir syncs dir; a variable so a test can fail it. It opens dir with
// O_DIRECTORY and O_NOFOLLOW, so a link planted at dir, or a FIFO or device
// node there, fails at once rather than hanging root or opening a device.
var SyncDir = func(dir string) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
