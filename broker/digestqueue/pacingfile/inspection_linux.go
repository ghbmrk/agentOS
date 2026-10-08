//go:build linux

package pacingfile

import (
	"bytes"
	"crypto/sha256"
	"path/filepath"
)

// InspectTemporary is explicit trusted review after total consumer drain, not
// automatic recovery or an agent tool. It acquires a NEW advisory lease and
// compares bounded private nofollow descriptor images without changing ledger or
// temporary. The stable lock inode may be created. Supply a separately trusted
// nonzero ledger pin BEFORE reads; matching old bytes can replay. Nonempty malformed
// images can compare without being valid accounting. A report never permits
// cleanup, refund, repair, activation or restart. Names/metadata are observations,
// not atomic hostile-same-UID/lock/restore custody. All I/O/Close may hang forever.
// Any read/custody/Close fault returns fixed ErrStorage and ZERO report.
func InspectTemporary(path string, expectedLedger [32]byte) (report TemporaryReport, err error) {
	if expectedLedger == ([32]byte{}) {
		return TemporaryReport{}, ErrStorage
	}
	s, e := OpenExclusive(path)
	if e != nil {
		return TemporaryReport{}, ErrStorage
	}
	defer func() {
		if s.Close() != nil {
			report = TemporaryReport{}
			err = ErrStorage
		}
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.verifyLocked() != nil {
		return TemporaryReport{}, ErrStorage
	}
	root := int(s.dir.Fd())
	name := filepath.Base(path)
	ledger, ledgerID, e := readRecoveryFile(root, name)
	if e != nil || sha256.Sum256(ledger) != expectedLedger {
		return TemporaryReport{}, ErrStorage
	}
	report = TemporaryReport{State: TemporaryAbsent, LedgerDigest: expectedLedger, LedgerBytes: len(ledger)}
	tempMeta, e := privateAt(root, name+".tmp", true)
	if e != nil {
		return TemporaryReport{}, ErrStorage
	}
	if tempMeta == nil {
		// Confirm observed absence and ledger version after the complete read.
		if s.verifyLocked() != nil || !recoveryNameMatches(root, name, &ledgerID) {
			return TemporaryReport{}, ErrStorage
		}
		if st, e := privateAt(root, name+".tmp", true); e != nil || st != nil {
			return TemporaryReport{}, ErrStorage
		}
		return report, nil
	}
	temp, tempID, e := readRecoveryFile(root, name+".tmp")
	if e != nil || !sameRecoveryVersion(tempMeta, &tempID) || s.verifyLocked() != nil || !recoveryNameMatches(root, name, &ledgerID) || !recoveryNameMatches(root, name+".tmp", &tempID) {
		return TemporaryReport{}, ErrStorage
	}
	report.State = TemporaryDifferent
	if bytes.Equal(ledger, temp) {
		report.State = TemporaryDuplicate
	}
	report.TemporaryDigest = sha256.Sum256(temp)
	report.TemporaryBytes = len(temp)
	return report, nil
}
