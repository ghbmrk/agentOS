// Package privfile holds a process's own private files: a check that a path
// is this uid's alone, and a write that a crash leaves whole. The kernel's
// process (broker/kernelproc) and the clerks' (broker/clerk/run) both use it;
// it was split out of broker/clerk/run so the kernel links no clerk code
// (KRN-2 split, #2892). The error texts keep their run: prefix.
package privfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
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
func WriteAtomic(dir, name string, b []byte, stop func(i int) bool) error {
	tmp, dst := filepath.Join(dir, name+".tmp"), filepath.Join(dir, name)
	var f *os.File
	steps := []func() error{
		func() error {
			if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			var err error
			f, err = os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
			return err
		},
		func() error { _, err := f.Write(b); return err },
		func() error { return f.Sync() },
		func() error { return f.Close() },
		func() error { return os.Rename(tmp, dst) }, // durable:exempt lifecycle:exempt durable is old core (tools/old_core.txt), so the new core cannot list here; this is sealed content, not a lifecycle, and the next step syncs the directory
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

// ErrStopped ends a write that its stop hook stopped, as a crash would.
var ErrStopped = errors.New("run: write stopped")

// ErrUnsynced is a write whose rename succeeded but whose directory sync
// failed: the new form is in place, and may or may not survive a crash, so
// the write neither failed nor took effect for certain (#2742 item 7).
var ErrUnsynced = errors.New("run: written, but the directory sync failed")

// SyncDir syncs dir; a variable so a test can fail it.
var SyncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
