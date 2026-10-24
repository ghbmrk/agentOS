package kernelproc

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/privfile"
)

// FileStore is the log on disk: a kernel.Store whose Append returns only once
// the bytes are synced. The file is locked for as long as it is open, so a
// second kernel process cannot open the same log and fork it (LOG-1).
type FileStore struct{ f *os.File }

var ErrLogInUse = errors.New("run: the log is open in another kernel process")

// OpenFileStore opens or creates the log file at path, mode 0600, and takes
// its lock.
func OpenFileStore(path string) (*FileStore, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := privfile.CheckFile(f); err != nil {
		f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLogInUse
		}
		return nil, err
	}
	return &FileStore{f}, nil
}

// Append writes b at the end of the file and syncs it. A short write leaves
// a torn frame, which kernel.Open trims.
func (s *FileStore) Append(b []byte) error {
	end, err := s.f.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	if _, err := s.f.WriteAt(b, end); err != nil {
		return err
	}
	return s.f.Sync()
}

func (s *FileStore) ReadAll() ([]byte, error) {
	fi, err := s.f.Stat()
	if err != nil {
		return nil, err
	}
	b := make([]byte, fi.Size())
	if _, err := s.f.ReadAt(b, 0); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return b, nil
}

func (s *FileStore) Truncate(n int) error {
	fi, err := s.f.Stat()
	if err != nil {
		return err
	}
	if n < 0 || int64(n) > fi.Size() {
		return fmt.Errorf("run: truncate to %d of %d: %w", n, fi.Size(), kernel.ErrCorrupt)
	}
	if err := s.f.Truncate(int64(n)); err != nil {
		return err
	}
	return s.f.Sync()
}

// Close releases the lock.
func (s *FileStore) Close() error { return s.f.Close() }
