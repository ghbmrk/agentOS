package pacingfile

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
)

// ExclusiveStore holds one cooperating process lease. Do not copy it or use
// one instance for multiple Gates. Quiesce its sole Gate before Close; releasing
// a filesystem lease does not revoke already returned permissions.
type ExclusiveStore struct {
	mu            sync.Mutex
	store         Store
	dir, lock     *os.File
	dirID, lockID syscall.Stat_t
	trustedOwners []uint32 // nil retains legacy ancestry behavior; copied on acquisition
	closed        bool
	unavailable   atomic.Bool
}

// OpenExclusive neither provisions nor loads the ledger. The dedicated parent
// must be owner-private 0700; lock/ledger/temp files must be owner-private 0600,
// regular, single-link objects. Ancestor/same-UID custody remains external.
func OpenExclusive(path string) (*ExclusiveStore, error) { return openExclusive(path, nil) }

// OpenExclusiveProtected additionally observes every root/ancestor UID and write
// mode during the same nofollow acquisition and later custody walks. Supply a
// separately trusted owner policy; no UID/root discovery establishes trust.
// Empty/duplicate/overbound sets refuse before I/O. Ordinary OpenExclusive is
// unchanged. This is not atomic hostile-path/root/mount/ACL/restore qualification,
// Session/manifest/daemon adoption, cancellation, activation or a deadline.
func OpenExclusiveProtected(path string, trustedOwners []uint32) (*ExclusiveStore, error) {
	if len(trustedOwners) == 0 || len(trustedOwners) > 16 {
		return nil, ErrStorage
	}
	copied := append([]uint32(nil), trustedOwners...)
	for i, uid := range copied {
		for _, earlier := range copied[:i] {
			if uid == earlier {
				return nil, ErrStorage
			}
		}
	}
	return openExclusive(path, copied)
}
func openExclusive(path string, owners []uint32) (*ExclusiveStore, error) {
	dir, err := openLeaseParentProtected(path, owners)
	if err != nil {
		return nil, ErrStorage
	}
	fd := int(dir.Fd())
	s := &ExclusiveStore{store: Store{Path: path}, dir: dir, trustedOwners: owners}
	fail := func() (*ExclusiveStore, error) { s.Close(); return nil, ErrStorage }
	if syscall.Fstat(fd, &s.dirID) != nil || !privateDir(&s.dirID) {
		return fail()
	}
	lockFD, err := syscall.Openat(fd, filepath.Base(path)+".lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return fail()
	}
	s.lock = os.NewFile(uintptr(lockFD), path+".lock")
	if syscall.Fstat(lockFD, &s.lockID) != nil || !privateFile(&s.lockID) || syscall.Flock(lockFD, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return fail()
	}
	if s.verifyLocked() != nil {
		return fail()
	}
	return s, nil
}
func privateDir(st *syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == uint32(os.Geteuid())
}
func privateFile(st *syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink == 1
}
func sameID(a, b *syscall.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func privateAt(dir int, name string, optional bool) (*syscall.Stat_t, error) {
	fd, err := syscall.Openat(dir, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == syscall.ENOENT && optional {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStorage
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || !privateFile(&st) {
		return nil, ErrStorage
	}
	return &st, nil
}

// Observation checks cannot close a race against an actor who can mutate the
// same UID's private paths. They detect displaced custody and fail closed, not
// qualify adversarial path safety or an authenticated restore history.
func (s *ExclusiveStore) verifyLocked() error {
	if s.closed || s.unavailable.Load() || s.dir == nil || s.lock == nil {
		return ErrStorage
	}
	named, err := openLeaseParentProtected(s.store.Path, s.trustedOwners)
	if err != nil {
		s.unavailable.Store(true)
		return ErrStorage
	}
	var st syscall.Stat_t
	e := syscall.Fstat(int(named.Fd()), &st)
	closed := named.Close()
	if e != nil || closed != nil || !privateDir(&st) || !sameID(&st, &s.dirID) {
		s.unavailable.Store(true)
		return ErrStorage
	}
	root := int(s.dir.Fd())
	name := filepath.Base(s.store.Path)
	lock, err := privateAt(root, name+".lock", false)
	if err != nil || !sameID(lock, &s.lockID) {
		s.unavailable.Store(true)
		return ErrStorage
	}
	for _, n := range []string{name, name + ".tmp"} {
		if _, err = privateAt(root, n, true); err != nil {
			s.unavailable.Store(true)
			return ErrStorage
		}
	}
	return nil
}
func (s *ExclusiveStore) Load() ([]byte, error) {
	if s == nil {
		return nil, ErrStorage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyLocked() != nil {
		return nil, ErrStorage
	}
	b, err := s.loadAnchored()
	if err != nil {
		s.unavailable.Store(true)
		return nil, ErrStorage
	}
	if s.verifyLocked() != nil {
		return nil, ErrStorage
	}
	return b, nil
}
func (s *ExclusiveStore) Save(b []byte) error {
	if s == nil {
		return ErrStorage
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyLocked() != nil {
		return ErrStorage
	}
	if s.saveAnchored(b) != nil {
		s.unavailable.Store(true)
		return ErrStorage
	}
	return s.verifyLocked()
}

// Close waits for this instance's synchronous I/O, marks it closed and releases
// only the advisory lease. Never unlink the lock inode, even on acquisition
// failure: contenders must keep naming the same inode. No authority is resumed.
func (s *ExclusiveStore) Close() error {
	if s == nil {
		return nil
	}
	s.unavailable.Store(true) // Publish retirement before waiting for synchronous I/O.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	failed := false
	if s.lock != nil {
		if syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN) != nil {
			failed = true
		}
		if s.lock.Close() != nil {
			failed = true
		}
	}
	if s.dir != nil && s.dir.Close() != nil {
		failed = true
	}
	if failed {
		return ErrStorage
	}
	return nil
}

// PacingHealth reads only immutable handles and atomic lifecycle state, never
// the I/O mutex or filesystem. It is an observation, not path/restore validation.
func (s *ExclusiveStore) PacingHealth() error {
	if s == nil || s.dir == nil || s.lock == nil || s.unavailable.Load() {
		return ErrStorage
	}
	return nil
}
