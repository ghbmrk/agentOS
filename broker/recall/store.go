package recall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/ghbmrk/agentos/broker/durable"
)

// Store is the durable medium under the index (and under the event bus).
// Append must not return nil until the line is durable. Rewrite atomically
// replaces the whole content, so a deletion leaves no copy of the deleted
// data in the live file (CAP-3).
type Store interface {
	Append(line []byte) error
	ReadAll() ([]byte, error)
	Rewrite(data []byte) error
}

// ErrLocked means another process holds the store.
var ErrLocked = errors.New("recall: store is locked by another process")

// FileStore is a Store backed by one append-only file, readable by its owner
// only. Rewrite writes a sibling file, fsyncs it, renames it over the old
// one, and fsyncs the directory.
type FileStore struct {
	mu   sync.Mutex
	path string
	f    storeFile
	lock *os.File
	// broken is set when a rewrite renamed the new file into place but
	// could not reopen it, so appends fail rather than go to the old,
	// unlinked file; and when a failed append could not be cut back off
	// the file, so the next line is not joined onto its remains. A
	// Rewrite that works, or a reopen, clears it.
	broken error
}

// storeFile is the part of *os.File the store uses (tests fault it).
type storeFile interface {
	Write([]byte) (int, error)
	Sync() error
	Truncate(int64) error
	Stat() (os.FileInfo, error)
	Close() error
}

// OpenFile opens or creates the store at path. A lock file next to it keeps
// two brokers from sharing one store; it survives Rewrite's rename.
func OpenFile(path string) (*FileStore, error) {
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %v", ErrLocked, err)
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		lock.Close()
		return nil, err
	}
	// A file created by an older build or by hand is tightened to owner-only.
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		lock.Close()
		return nil, err
	}
	if err := durable.SyncDir(filepath.Dir(path)); err != nil {
		f.Close()
		lock.Close()
		return nil, err
	}
	return &FileStore{path: path, f: f, lock: lock}, nil
}

func (s *FileStore) Append(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.broken != nil {
		return s.broken
	}
	fi, err := s.f.Stat()
	if err != nil {
		return err
	}
	_, err = s.f.Write(line)
	if err == nil {
		err = s.f.Sync()
	}
	if err == nil {
		return nil
	}
	// A failed append can leave part of the line, or all of it unsynced.
	// Cut the file back to where the append began, so the caller's "not
	// written" holds and the next line does not join the remains into one
	// line a reader skips (SEC-backs-append-latch). If the cut fails,
	// refuse appends until Rewrite or a reopen, which reads the remains as
	// a torn tail.
	if terr := s.f.Truncate(fi.Size()); terr != nil {
		s.broken = fmt.Errorf("recall: store append failed and could not be cut back: %w", terr)
	} else if serr := s.f.Sync(); serr != nil {
		s.broken = fmt.Errorf("recall: store append failed and its cut could not be synced: %w", serr)
	}
	return err
}

func (s *FileStore) ReadAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.ReadFile(s.path)
}

func (s *FileStore) Rewrite(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	werr := durable.WriteFile(s.path, data, 0o600)
	if werr != nil && !errors.Is(werr, durable.ErrDirSync) {
		return werr
	}
	// The old handle now points at an unlinked file: swap it even when
	// only the directory sync failed.
	f, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND, 0o600)
	s.f.Close()
	if err != nil {
		s.broken = fmt.Errorf("recall: store reopen after rewrite: %w", err)
		return s.broken
	}
	s.f = f
	s.broken = nil
	return werr
}

// Close releases the file and the lock.
func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.f.Close()
	s.lock.Close()
	return err
}

// MemStore is an in-memory Store for tests and simulations.
type MemStore struct {
	mu   sync.Mutex
	data []byte
}

func (s *MemStore) Append(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = append(s.data, line...)
	return nil
}

func (s *MemStore) ReadAll() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.data), nil
}

func (s *MemStore) Rewrite(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = bytes.Clone(data)
	return nil
}

// Lines splits stored content into complete JSON lines. A final segment
// without a newline is a torn write and is reported as torn so the caller
// can rewrite the store without it.
func Lines(data []byte) (lines [][]byte, torn bool) {
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return lines, true
		}
		if i > 0 {
			lines = append(lines, data[:i])
		}
		data = data[i+1:]
	}
	return lines, false
}
