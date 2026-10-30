package change

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ghbmrk/agentos/broker/durable"
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
	mu     sync.Mutex
	data   []byte
	Fail   error // when set, Save returns it
	bodies *MemContent
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
	b, err := readFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (f FileStore) Save(b []byte) error {
	return durable.WriteFile(f.Path, b, 0o600)
}

// Content holds named bodies beside the bulk state: an adoption's files
// and the qualified proposals waiting for their intent (OP-11). Get
// returns nil, nil for a name never put or deleted. Put must be atomic
// like Store.Save.
type Content interface {
	Get(name string) ([]byte, error)
	Put(name string, b []byte) error
	Delete(name string) error
}

// MemContent is Content in memory, for tests.
type MemContent struct {
	mu   sync.Mutex
	m    map[string][]byte
	Fail error // when set, Put returns it
}

func (c *MemContent) Get(name string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.m[name]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), b...), nil
}

func (c *MemContent) Put(name string, b []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Fail != nil {
		return c.Fail
	}
	if c.m == nil {
		c.m = map[string][]byte{}
	}
	c.m[name] = append([]byte(nil), b...)
	return nil
}

func (c *MemContent) Delete(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, name)
	return nil
}

// Bodies is the content kept with this store, so a reopened pipeline over
// the same MemStore finds it.
func (m *MemStore) Bodies() Content {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.bodies == nil {
		m.bodies = &MemContent{}
	}
	return m.bodies
}

// DirContent keeps each body in its own file in Dir, named by the hash of
// its name, written like FileStore.
type DirContent struct{ Dir string }

func (d DirContent) path(name string) string {
	h := sha256.Sum256([]byte(name))
	return filepath.Join(d.Dir, hex.EncodeToString(h[:]))
}

func (d DirContent) Get(name string) ([]byte, error) {
	b, err := readFile(d.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (d DirContent) Put(name string, b []byte) error {
	if err := os.MkdirAll(d.Dir, 0o700); err != nil {
		return err
	}
	return durable.WriteFile(d.path(name), b, 0o600)
}

func (d DirContent) Delete(name string) error {
	err := os.Remove(d.path(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// Bodies is the directory beside the state file, Path with ".d" added.
func (f FileStore) Bodies() Content { return DirContent{Dir: f.Path + ".d"} }

// readFile is os.ReadFile refusing a link at p (REV-CHK-links, #3945): a
// state file or body is never a link, so one there was planted.
func readFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
