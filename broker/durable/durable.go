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

// TempPrefix starts the name of every temporary file WriteFile creates,
// and of PublishDir's stages; SweepTemp removes the files.
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
	mkdir      func(name string, perm os.FileMode) error
	syncFile   func(name string) error
}{
	createTemp: func(dir, pattern string) (file, error) { return os.CreateTemp(dir, pattern) },
	rename:     os.Rename,
	remove:     os.Remove,
	syncDir:    syncDir,
	mkdir:      os.Mkdir,
	syncFile:   syncFile,
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

// StageDir is where PublishDir fills dir before publishing it: beside dir,
// named TempPrefix and dir's name. A caller that bounds path lengths under
// dir bounds them under this longer root too.
func StageDir(dir string) string {
	return filepath.Join(filepath.Dir(dir), TempPrefix+filepath.Base(dir))
}

// PublishDir creates directory dir, with mode perm, holding what fill
// writes, so that a crash or power cut leaves either no dir or all of it.
// fill writes into StageDir(dir); then every regular file and directory in
// the stage is fsynced, directories bottom-up, the stage renamed to dir,
// and dir's parent fsynced. Nothing is at dir until all of it is durable.
//
// dir must not exist, nor its stage: a stage a crash left is the caller's
// to remove at start, as an unpublished one. On error before the rename,
// dir does not exist and the stage is removed; after it, a failed sync of
// the parent returns an error wrapping ErrDirSync, and dir is complete but
// its name may not survive a power cut.
func PublishDir(dir string, perm os.FileMode, fill func(stage string) error) error {
	if _, err := os.Lstat(dir); err == nil {
		return fmt.Errorf("durable: publish %s: %w", dir, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	stage := StageDir(dir)
	if err := fsys.mkdir(stage, perm); err != nil {
		return err
	}
	err := fill(stage)
	if err == nil {
		err = syncTree(stage)
	}
	if err == nil {
		err = fsys.rename(stage, dir)
	}
	if err != nil {
		os.RemoveAll(stage)
		return err
	}
	return dirSynced(filepath.Dir(dir))
}

// syncTree fsyncs every regular file under root, then every directory,
// deepest first and root last. Links, devices (overlay whiteouts among
// them), fifos and sockets have no data of their own: their entries and
// metadata are made durable by the sync of the directory holding them.
func syncTree(root string) error {
	var dirs []string
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case d.IsDir():
			dirs = append(dirs, p)
		case d.Type().IsRegular():
			return fsys.syncFile(p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	// The walk visits a directory before anything in it.
	for i := len(dirs) - 1; i >= 0; i-- {
		if err := fsys.syncDir(dirs[i]); err != nil {
			return err
		}
	}
	return nil
}

func syncFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
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
