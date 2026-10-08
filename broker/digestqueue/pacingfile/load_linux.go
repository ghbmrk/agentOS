package pacingfile

import (
	"errors"
	"os"
	"syscall"

	"github.com/ghbmrk/agentos/broker/grants"
)

// O_NOFOLLOW refuses the final symlink. O_NONBLOCK prevents a FIFO open from
// waiting for a writer before descriptor metadata rejects non-regular input.
// Neither flag protects writable parent components or bounds filesystem latency.
func (s Store) Load() ([]byte, error) {
	fd, err := syscall.Open(s.Path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), s.Path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() > int64(grants.MaxPacingStateBytes) {
		return nil, ErrStorage
	}
	// The descriptor may grow after Stat: cap the actual stream as well.
	return readBounded(f)
}
