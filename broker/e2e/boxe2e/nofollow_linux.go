package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// The harness runs as root (image/e2e/agentos-e2e.service), so every file
// it opens goes through openRaw, and a file in a worker's layer through
// rootOpen; the source test refuses any other open, and any other way to
// make a link (TestJournalIsReadOnlyByNamedReaders, ASSUMPTIONS E8). They
// decide on what the open reached, never on how its path is spelled:
//   - a regular file that starts with the journal's magic is refused, so
//     only readJournal's journalctl reads a journal;
//   - a write (O_WRONLY, O_RDWR, O_CREAT or O_TRUNC) of a regular file, or
//     a new link, is allowed only where its resolved path is under
//     writeDirs or is one of writeFiles, so no unit, preload or program
//     is planted for another process to run.
//
// readNoFollow and writeNoFollow also refuse a link at the final name
// (REV-CHK-links, #3946): some files sit in directories another uid owns,
// such as agentos-localui's card latch.

// journalMagic begins every journal file (systemd's journal-def.h).
const journalMagic = "LPKSHHRH"

var (
	errJournal = errors.New("refused: a journal file is read only through readJournal")
	errWrite   = errors.New("refused: the driver writes only under writeDirs and to writeFiles")
	errKind    = errors.New("refused: the driver opens only regular files off procfs and sysfs, directories and /dev/ptmx")
)

// writeDirs are the directories the driver writes in and writeFiles the
// files it writes elsewhere, each as its resolved path; tests add their
// own temporary directories.
var (
	writeDirs  = []string{"/run/agentos-e2e", "/run/agentos-e2e-sysroot"}
	writeFiles = []string{pageDropIn}
)

// mayWrite says whether the resolved path real is one the driver writes.
func mayWrite(real string) bool {
	return slices.Contains(writeFiles, real) || slices.ContainsFunc(writeDirs, func(d string) bool { return strings.HasPrefix(real, d+"/") })
}

// fdPath is the resolved path of the file fd is open on.
func fdPath(fd int) (string, error) {
	return os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
}

// inDir opens path's directory without following anything at path's own
// name and says whether a new name there may be written: the directory's
// resolved path decides, and the caller acts on the name relative to the
// returned descriptor, so the checked directory is the one used.
func inDir(path string) (dir int, base string, err error) {
	dir, err = unix.Open(filepath.Dir(path), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	real, err := fdPath(dir)
	base = filepath.Base(path)
	if err == nil && !mayWrite(filepath.Join(real, base)) {
		err = errWrite
	}
	if err != nil {
		unix.Close(dir)
		return -1, "", err
	}
	return dir, base, nil
}

// ptmx is /dev/ptmx's device number, the one device the driver opens
// (plugModem); any other device, a FIFO or a socket is refused, so no
// block device's raw sectors, /dev/mem or /dev/null is reached.
var ptmx = unix.Mkdev(5, 2)

// checkFD refuses what an open reached unless it is /dev/ptmx, a
// directory, or a regular file that is not on
// procfs or sysfs (no /proc/<pid>/mem, environ or kcore), is not a
// journal, and if open for writing is where the driver writes.
func checkFD(fd int, write bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFCHR:
		if st.Rdev == ptmx {
			return nil
		}
		return errKind
	case unix.S_IFDIR: // the kernel opens a directory for reading only
		return nil
	case unix.S_IFREG:
	default:
		return errKind
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if fs.Type == unix.PROC_SUPER_MAGIC || fs.Type == unix.SYSFS_MAGIC {
		return errKind
	}
	if write {
		real, err := fdPath(fd)
		if err != nil {
			return err
		}
		if !mayWrite(real) {
			return errWrite
		}
	}
	b := make([]byte, len(journalMagic))
	// A descriptor open only for writing cannot be read; nothing it does
	// reaches the console.
	if n, err := unix.Pread(fd, b, 0); err == nil && string(b[:n]) == journalMagic {
		return errJournal
	}
	return nil
}

// openRaw opens path as unix.Open does, close-on-exec, and refuses what
// checkFD refuses. An open that could make or empty a file checks its
// directory first (inDir).
func openRaw(path string, flag int, perm uint32) (int, error) {
	flag |= unix.O_CLOEXEC
	write := flag&(unix.O_WRONLY|unix.O_RDWR|unix.O_CREAT|unix.O_TRUNC) != 0
	var fd int
	var err error
	if flag&(unix.O_CREAT|unix.O_TRUNC) != 0 {
		dir, base, derr := inDir(path)
		if derr != nil {
			return -1, derr
		}
		// No link is followed at the name, so what is made or emptied is
		// the name inDir checked.
		fd, err = unix.Openat(dir, base, flag|unix.O_NOFOLLOW, perm)
		unix.Close(dir)
	} else {
		fd, err = unix.Open(path, flag, perm)
	}
	if err != nil {
		return -1, err
	}
	if err := checkFD(fd, write); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// rootOpen opens name in r for reading, refusing a link at its final name
// and a journal file.
func rootOpen(r *os.Root, name string) (*os.File, error) {
	f, err := r.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	sc, err := f.SyscallConn()
	if err == nil {
		if cerr := sc.Control(func(fd uintptr) { err = checkFD(int(fd), false) }); err == nil {
			err = cerr
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

// symlink makes name a link to target where the driver writes (inDir).
func symlink(target, name string) error {
	dir, base, err := inDir(name)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return unix.Symlinkat(target, dir, base)
}

// readNoFollow reads path, refusing a link at its final name.
func readNoFollow(path string) ([]byte, error) {
	fd, err := openRaw(path, unix.O_RDONLY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return io.ReadAll(f)
}

// writeNoFollow writes b to path as os.WriteFile does, refusing a link at
// its final name.
func writeNoFollow(path string, b []byte, perm os.FileMode) error {
	fd, err := openRaw(path, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_NOFOLLOW, uint32(perm.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
