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

// sealedSize is the length n bytes of plaintext seal to: the header and
// one tag per chunk, a full last chunk still one chunk, so it is
// headerLen + n + ceil(n/chunkSize)*tagSize. A target holds no key table
// longer than sealedSize(maxTable), the largest table UnwrapTable accepts.
func sealedSize(n int64) int64 {
	return int64(headerLen) + n + (n+chunkSize-1)/chunkSize*tagSize
}

// readFile reads a key table at p, refusing what a table is never
// (REV-CHK-links, #3945, #3998). The directory is the owner's choice and
// the read runs as root, so another uid may have planted the name: a link
// is refused by O_NOFOLLOW; a FIFO, socket, device or directory by the
// type of the open descriptor, O_NONBLOCK keeping the open of a FIFO from
// waiting for a writer; and a file over sealedSize(maxTable) unread. A regular
// file's reads never block, so O_NONBLOCK stays set. O_NOCTTY keeps a
// planted terminal from becoming the daemon's controlling terminal; os.OpenFile
// sets O_CLOEXEC itself.
func readFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if errors.Is(err, syscall.ENXIO) {
		return nil, fmt.Errorf("backup: %s is a socket or a device with no driver, not a regular file: %w", p, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readTable(f, p)
}

// readTable reads the key table open at f, named p in its errors: the
// checks readFile makes on the descriptor it opened.
func readTable(f *os.File, p string) ([]byte, error) {
	st, err := f.Stat() // fstat of the descriptor opened, not of the name
	if err != nil {
		return nil, err
	}
	if m := st.Mode(); !m.IsRegular() {
		return nil, fmt.Errorf("backup: %s is a %s, not a regular file", p, typeName(m))
	}
	limit := sealedSize(maxTable)
	if st.Size() > limit {
		return nil, fmt.Errorf("backup: %s is %d bytes, over the %d a key table can be", p, st.Size(), limit)
	}
	b, err := readBounded(f, limit)
	if err != nil {
		return nil, fmt.Errorf("backup: %s: %w", p, err)
	}
	return b, nil
}

// readBounded reads r to its end, refusing more than n bytes: a file can
// grow between its fstat and its read.
func readBounded(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("over the %d bytes a key table can be", n)
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
