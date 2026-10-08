//go:build linux

package pacingfile

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"syscall"

	"github.com/ghbmrk/agentos/broker/grants"
)

// DiscardDuplicateTemporary is an explicitly invoked trusted recovery operation,
// not part of Save/startup. Call only after complete registered AND downstream
// quiescence, with trusted ledger pin/source and stable private names. It acquires
// a new advisory lease, refuses any nonidentical/unsafe residue, and never writes,
// renames or removes ledger/lock. Pin equality does not authenticate or attest
// freshness/schema. A matching older image is replayable.
//
// One optional pinned settings binds this exact ledger; v2 uses protected
// acquisition/later custody checks, v1/default remains legacy. Never downgrade
// malformed policy. Existing call syntax remains; function-value signatures change.
//
// Named metadata checks are observations: hostile same-UID replacement can race
// the final check and Unlinkat. Release requires independently qualified custody.
// Any error (including after unlink/sync/close) is uncertain recovery: do not
// restart until trusted recovery determines persistence/custody. All I/O is
// synchronous and can hang; there is no activation, refund, retry or deadline.
func DiscardDuplicateTemporary(path string, expectedLedger [32]byte, settings ...*ManifestSettings) error {
	owners, err := manifestRecoveryOwners(path, settings)
	if err != nil {
		return ErrStorage
	}
	return discardDuplicateTemporary(path, expectedLedger, owners)
}

// The owner policy was copied before admission; do not reread caller settings.
func discardDuplicateTemporary(path string, expectedLedger [32]byte, owners []uint32) (err error) {
	if expectedLedger == ([32]byte{}) {
		return ErrStorage
	}
	s, e := openExclusive(path, owners)
	if e != nil {
		return ErrStorage
	}
	defer func() {
		if s.Close() != nil {
			err = ErrStorage
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyLocked() != nil {
		return ErrStorage
	}
	root := int(s.dir.Fd())
	name := filepath.Base(path)
	ledger, ledgerID, e := readRecoveryFile(root, name)
	if e != nil || sha256.Sum256(ledger) != expectedLedger {
		return ErrStorage
	}
	temporary, tempID, e := readRecoveryFile(root, name+".tmp")
	if e != nil || !bytes.Equal(ledger, temporary) {
		return ErrStorage
	}
	if s.verifyLocked() != nil || !recoveryNameMatches(root, name, &ledgerID) || !recoveryNameMatches(root, name+".tmp", &tempID) {
		return ErrStorage
	}
	if syscall.Unlinkat(root, name+".tmp") != nil {
		return ErrStorage
	}
	// Nothing repairs a post-unlink failure or authorizes a restart on that error.
	if s.dir.Sync() != nil || s.verifyLocked() != nil || !recoveryNameMatches(root, name, &ledgerID) {
		return ErrStorage
	}
	return nil
}

// Called under a fresh recovery lease; bounded descriptor reads reuse the normal
// accounting cap/probe. Both images must be present, nonempty, private and stable
// across the read. Never follow the name or open a FIFO in blocking mode.
func readRecoveryFile(root int, name string) (image []byte, st syscall.Stat_t, err error) {
	fd, e := syscall.Openat(root, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, st, ErrStorage
	}
	f := os.NewFile(uintptr(fd), "accounting recovery image")
	defer func() {
		if f.Close() != nil {
			err = ErrStorage
		}
	}()
	if syscall.Fstat(fd, &st) != nil || !privateFile(&st) || st.Size <= 0 || st.Size > int64(grants.MaxPacingStateBytes) {
		return nil, st, ErrStorage
	}
	image, e = readBounded(f)
	if e != nil {
		return nil, st, ErrStorage
	}
	var after syscall.Stat_t
	if syscall.Fstat(fd, &after) != nil || !sameRecoveryVersion(&st, &after) || int64(len(image)) != st.Size {
		return nil, st, ErrStorage
	}
	return image, st, nil
}
func sameRecoveryVersion(a, b *syscall.Stat_t) bool {
	return sameID(a, b) && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func recoveryNameMatches(root int, name string, want *syscall.Stat_t) bool {
	got, e := privateAt(root, name, false)
	return e == nil && sameRecoveryVersion(want, got)
}
