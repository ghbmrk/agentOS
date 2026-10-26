package backup

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
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

// MemTarget is a Target in memory, for tests.
type MemTarget struct {
	Append bool // AppendOnly
	mu     sync.Mutex
	m      map[string]map[uint64][]byte
}

func (t *MemTarget) PutTable(id string, gen uint64, b []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]map[uint64][]byte{}
	}
	if t.m[id] == nil {
		t.m[id] = map[uint64][]byte{}
	}
	if _, ok := t.m[id][gen]; ok {
		return ErrExists
	}
	t.m[id][gen] = slices.Clone(b)
	return nil
}

func (t *MemTarget) GetTable(id string, gen uint64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.m[id][gen]
	if !ok {
		return nil, ErrNoTable
	}
	return slices.Clone(b), nil
}

func (t *MemTarget) DeleteTable(id string, gen uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.Append {
		return errors.New("backup: append-only target")
	}
	delete(t.m[id], gen)
	return nil
}

func (t *MemTarget) Tables(id string) ([]uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Sorted(maps.Keys(t.m[id])), nil
}

func (t *MemTarget) AppendOnly() bool { return t.Append }

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
	f, err := os.Open(d.Dir)
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
	b, err := os.ReadFile(p)
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
