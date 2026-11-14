package backup

import (
	"errors"
	"maps"
	"slices"
	"sync"
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
