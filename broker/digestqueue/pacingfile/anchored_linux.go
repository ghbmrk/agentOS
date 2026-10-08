//go:build linux

package pacingfile

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/grants"
)

// These internal operations require the lease I/O mutex and a verified live
// lease. All ledger/temp/rename/sync operations use the already held directory,
// not its mutable pathname. The outer checks still observe named custody.
func (s *ExclusiveStore) loadAnchored() ([]byte, error) {
	fd, err := syscall.Openat(int(s.dir.Fd()), filepath.Base(s.store.Path), syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "accounting ledger")
	defer f.Close()
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || !privateFile(&st) || st.Size > int64(grants.MaxPacingStateBytes) {
		return nil, ErrStorage
	}
	return readBounded(f)
}

func (s *ExclusiveStore) saveAnchored(b []byte) error {
	if len(b) > grants.MaxPacingStateBytes || s.unavailable.Load() {
		return ErrStorage
	}
	root := int(s.dir.Fd())
	name := filepath.Base(s.store.Path)
	temp := name + ".tmp"
	// Never truncate or adopt an existing temporary, even a private regular file.
	// Crash residue is a recovery hold requiring trusted cleanup after full drain.
	fd, err := syscall.Openat(root, temp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ErrStorage
	}
	f := os.NewFile(uintptr(fd), "accounting temporary")
	var created syscall.Stat_t
	if syscall.Fstat(fd, &created) != nil || !privateFile(&created) {
		f.Close()
		return ErrStorage
	}
	n, err := f.Write(b)
	if err != nil || n != len(b) {
		f.Close()
		return ErrStorage
	}
	if f.Sync() != nil {
		f.Close()
		return ErrStorage
	}
	if f.Close() != nil {
		return ErrStorage
	}
	// A same-UID mutator can still race this observation and Renameat. Descriptor
	// anchoring is not hostile-name custody or lock-inode/restore qualification.
	current, err := privateAt(root, temp, false)
	if err != nil || !sameID(current, &created) || s.unavailable.Load() {
		return ErrStorage
	}
	if syscall.Renameat(root, temp, root, name) != nil {
		return ErrStorage
	}
	// A failed directory sync is uncertain persistence, never a permission/refund.
	if s.dir.Sync() != nil {
		return ErrStorage
	}
	return nil
}
