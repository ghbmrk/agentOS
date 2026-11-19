package backup

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Target is where a backup's key-table objects live. Each call is durable
// when it returns. DeleteTable of an absent generation succeeds. A target
// that cannot delete (an append-only store) says so through AppendOnly.
// Storage adapters are later rows.
type Target interface {
	PutTable(backupID string, gen uint64, b []byte) error
	GetTable(backupID string, gen uint64) ([]byte, error)
	DeleteTable(backupID string, gen uint64) error
	Tables(backupID string) ([]uint64, error) // sorted
	AppendOnly() bool
}

var (
	ErrNoTable = errors.New("backup: no such key table")
	ErrExists  = errors.New("backup: that key table generation is already there")
)

// DirTarget keeps key tables as files <backup id>.table.<generation> in a
// directory. Put writes a temporary file, syncs it and links it into place,
// so a generation is never overwritten; Put and Delete sync the directory.
type DirTarget struct{ Dir string }

const tableExt = ".table."

func (d DirTarget) path(id string, gen uint64) (string, error) {
	if _, err := parseID(id); err != nil {
		return "", err
	}
	return filepath.Join(d.Dir, id+tableExt+strconv.FormatUint(gen, 10)), nil
}

func (d DirTarget) syncDir() error {
	f, err := os.OpenFile(d.Dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (d DirTarget) PutTable(id string, gen uint64, b []byte) error {
	p, err := d.path(id, gen)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(d.Dir, ".tmp-table-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Link(tmp, p); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrExists
		}
		return err
	}
	return d.syncDir()
}

func (d DirTarget) GetTable(id string, gen uint64) ([]byte, error) {
	p, err := d.path(id, gen)
	if err != nil {
		return nil, err
	}
	b, err := readFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoTable
	}
	return b, err
}

func (d DirTarget) DeleteTable(id string, gen uint64) error {
	p, err := d.path(id, gen)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return d.syncDir()
}

func (d DirTarget) Tables(id string) ([]uint64, error) {
	if _, err := parseID(id); err != nil {
		return nil, err
	}
	des, err := os.ReadDir(d.Dir)
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, de := range des {
		g, ok := strings.CutPrefix(de.Name(), id+tableExt)
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(g, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != g {
			return nil, fmt.Errorf("backup: unexpected file %q", de.Name())
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

func (DirTarget) AppendOnly() bool { return false }

// sealedSize is the length n > 0 bytes of plaintext seal to: the header
// and one tag per chunk, a full last chunk still one chunk, so it is
// headerLen + n + ceil(n/chunkSize)*tagSize (an empty body is one empty
// chunk, which this does not count). A target holds no key table
// longer than sealedSize(maxTable), the largest table UnwrapTable accepts.
func sealedSize(n int64) int64 {
	return int64(headerLen) + n + (n+chunkSize-1)/chunkSize*tagSize
}

// readFile reads the key table at p: a regular file of at most sealedSize(maxTable) bytes.
func readFile(p string) ([]byte, error) {
	f, st, err := OpenRegular(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readTable(f, st.Size(), sealedSize(maxTable), p)
}

const oPath = 0x200000 // Linux's O_PATH, absent from syscall; a test pins it to x/sys/unix's

// OpenRegular opens the regular file at p, which another uid may have planted, for
// reading, and gives its fstat (REV-CHK-links, #6014). The O_PATH open follows no
// link and reaches no FIFO or driver; its fstat refuses what is not regular; the
// reopen through /proc/self/fd is of that same inode, whatever the name holds by then.
func OpenRegular(p string) (*os.File, fs.FileInfo, error) {
	pf, err := os.OpenFile(p, oPath|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	defer pf.Close()
	st, err := pf.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("backup: %s is a %s, not a regular file", p, typeName(st.Mode()))
	}
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open("/proc/self/fd/" + strconv.Itoa(int(pf.Fd())))
	return f, st, err
}

// readTable reads the key table r, named p in its errors: one over limit by its
// fstat's size is refused unread, and the read stops one byte past limit, for a
// file that grows after its fstat.
func readTable(r io.Reader, size, limit int64, p string) ([]byte, error) {
	if size > limit {
		return nil, fmt.Errorf("backup: %s is %d bytes, over the %d a key table can be", p, size, limit)
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("over the %d bytes a key table can be", limit)
	}
	if err != nil {
		return nil, fmt.Errorf("backup: %s: %w", p, err)
	}
	return b, nil
}

func typeName(m fs.FileMode) string {
	switch {
	case m&fs.ModeNamedPipe != 0:
		return "named pipe"
	case m&fs.ModeSocket != 0:
		return "socket"
	case m&fs.ModeCharDevice != 0:
		return "character device"
	case m&fs.ModeDevice != 0:
		return "block device"
	case m.IsDir():
		return "directory"
	}
	return "non-regular file"
}
