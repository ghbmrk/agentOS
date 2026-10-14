// Package durable is the broker's one way to replace a file or move one into
// place so that a crash or power cut leaves the old state or the new one,
// never part of one, and a write that returned nil stays written (OP-4,
// RES-4).
//
// A rename is durable only once the directory holding the new name is
// fsynced; a file's data only once the file is fsynced before the rename.
// Every rename in the broker goes through this package: TestNoBareRename
// fails on os.Rename elsewhere unless the line says `durable:exempt <reason>`.
package durable

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrDirSync marks an error from the directory sync after a rename: the new
// name is in place but may not survive a power cut. A caller that holds a
// handle on the replaced file swaps it before returning this error.
var ErrDirSync = errors.New("durable: directory sync after rename failed")

// TempPrefix starts the name of every temporary file WriteFile creates;
// SweepTemp removes files with it.
const TempPrefix = ".durable-"

// file is the part of *os.File WriteFile uses.
type file interface {
	Name() string
	Write([]byte) (int, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}

// fsys is the file system seam: tests swap it to record the order of
// writes, fsyncs and renames, or to fail one of them.
var fsys = struct {
	createTemp func(dir, pattern string) (file, error)
	rename     func(oldpath, newpath string) error
	remove     func(name string) error
	syncDir    func(dir string) error
}{
	createTemp: func(dir, pattern string) (file, error) { return os.CreateTemp(dir, pattern) },
	rename:     os.Rename,
	remove:     os.Remove,
	syncDir:    syncDir,
}

// WriteFile replaces path with data and mode perm: a temporary file in the
// same directory is written and fsynced, renamed over path, and the
// directory fsynced. On error before the rename, path is unchanged and the
// temporary file removed; after it, a failed directory sync returns an
// error wrapping ErrDirSync and path holds data.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := fsys.createTemp(dir, TempPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := writeSync(tmp, data, perm); err != nil {
		fsys.remove(name)
		return err
	}
	if err := fsys.rename(name, path); err != nil {
		fsys.remove(name)
		return err
	}
	return dirSynced(dir)
}

func writeSync(f file, data []byte, perm os.FileMode) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(perm)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Rename moves oldpath to newpath and fsyncs the directory of newpath, and
// that of oldpath when it differs, so the move survives a power cut. The
// caller has already fsynced whatever it moves.
func Rename(oldpath, newpath string) error {
	if err := fsys.rename(oldpath, newpath); err != nil {
		return err
	}
	from, to := filepath.Dir(oldpath), filepath.Dir(newpath)
	if err := dirSynced(to); err != nil || from == to {
		return err
	}
	return dirSynced(from)
}

func dirSynced(dir string) error {
	if err := fsys.syncDir(dir); err != nil {
		return fmt.Errorf("%w: %w", ErrDirSync, err)
	}
	return nil
}

// SyncDir fsyncs dir, making the creation, removal or renaming of its
// entries durable.
func SyncDir(dir string) error { return fsys.syncDir(dir) }

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// SweepTemp removes temporary files a crash left in dir. Call it only when
// no WriteFile into dir can be in flight, such as when the one process that
// owns dir opens it at start.
func SweepTemp(dir string) error {
	names, err := filepath.Glob(filepath.Join(dir, TempPrefix+"*"))
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := os.Remove(n); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
