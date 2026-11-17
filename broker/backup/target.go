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

// maxSealedTable is the largest table UnwrapTable accepts, sealed: header,
// maxTable bytes and one tag per chunk (a full last chunk is one chunk).
const maxSealedTable = int64(headerLen + maxTable + (maxTable+chunkSize-1)/chunkSize*tagSize)

var fileKinds = map[fs.FileMode]string{fs.ModeNamedPipe: "named pipe", fs.ModeSocket: "socket", fs.ModeDevice: "device", fs.ModeDir: "directory"}

// readFile reads a key table at p as root, refusing what a planted name may be
// (REV-CHK-links, #3945, #3998): a link (O_NOFOLLOW); a FIFO, socket, device or
// directory, by the descriptor's type (O_NONBLOCK keeps a FIFO's open from
// waiting, O_NOCTTY a terminal from becoming the daemon's); a file over
// maxSealedTable, unread.
func readFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
	if errors.Is(err, syscall.ENXIO) {
		err = fmt.Errorf("backup: %s is a socket or a device with no driver: %w", p, err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err == nil && !st.Mode().IsRegular() {
		err = fmt.Errorf("backup: %s is a %s, not a regular file", p, fileKinds[st.Mode().Type()&^fs.ModeCharDevice])
	} else if err == nil && st.Size() > maxSealedTable {
		err = fmt.Errorf("backup: %s is %d bytes, over the %d a key table can be", p, st.Size(), maxSealedTable)
	}
	if err != nil {
		return nil, err
	}
	return readBounded(f, maxSealedTable)
}

// readBounded reads r to its end, refusing over n bytes: a file can grow
// between its fstat and its read.
func readBounded(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err == nil && int64(len(b)) > n {
		return nil, fmt.Errorf("backup: over the %d bytes a key table can be", n)
	}
	return b, err
}
