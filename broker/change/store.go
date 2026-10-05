package change

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Store holds the pipeline's state. Load returns nil, nil when nothing has
// been saved yet. Save must be atomic: after a crash, Load returns either
// the old state or the new one.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// MemStore is a Store in memory, for tests.
type MemStore struct {
	mu   sync.Mutex
	data []byte
	Fail error // when set, Save returns it
}

func (m *MemStore) Load() ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		return nil, nil
	}
	return append([]byte(nil), m.data...), nil
}

func (m *MemStore) Save(b []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	m.data = append([]byte(nil), b...)
	return nil
}

// FileStore saves to one file by write, fsync, and rename.
type FileStore struct{ Path string }

func (f FileStore) Load() ([]byte, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (f FileStore) Save(b []byte) error {
	tmp := f.Path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		return err
	}
	if err := fh.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, f.Path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(f.Path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
