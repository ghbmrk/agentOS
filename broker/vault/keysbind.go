package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
)

// The keys file is bound to the vault (V6, security review of #45, F1).
// The keys file is plaintext beside the vault, so without this an earlier
// copy of it put back beside the current vault would undo a passphrase
// replacement or a trusted-host removal: the old slot still wraps the same
// data key. The vault therefore records the SHA-256 of the keys file it
// goes with, inside the seal, and OpenSealed refuses any other keys file
// (ErrRolledBack). Every slot change is a vault write, so on an anchored
// PC it also advances the rollback counter, and an earlier vault with its
// own earlier keys file is caught there (rollback.go).
//
// A slot change writes three times so that a crash never leaves a pair
// that refuses itself: the vault accepting the current and the next keys
// file, then the next keys file, then the vault accepting only it.
// OpenSealed finishes an interrupted change by keeping the one that is on
// the drive.

func keysHash(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}

// slotsForChange reads the keys file for a slot change on an open vault,
// refusing one this vault did not record or one mid re-encryption. Caller
// holds mu.
func (v *Vault) slotsForChange() (*keyFile, error) {
	if v.closed {
		return nil, ErrClosed
	}
	if v.key == nil {
		return nil, errors.New("vault: not opened through its key slots")
	}
	raw, err := readFile(v.keysPath)
	if err != nil {
		return nil, err
	}
	if !v.acceptsKeys(raw) {
		return nil, ErrRolledBack
	}
	kf, err := parseKeys(raw)
	if err != nil {
		return nil, err
	}
	if _, err := kf.keyID(); err != nil {
		return nil, err
	}
	return kf, nil
}

func (v *Vault) acceptsKeys(raw []byte) bool {
	h := keysHash(raw)
	for _, k := range v.keysOK {
		if bytes.Equal(k, h) {
			return true
		}
	}
	return false
}

// replaceKeys writes kf as the keys file, recording it in the vault first.
// Caller holds mu.
func (v *Vault) replaceKeys(kf *keyFile) error {
	raw, err := json.Marshal(kf)
	if err != nil {
		return err
	}
	cur, err := readFile(v.keysPath)
	if err != nil {
		return err
	}
	prev := v.keysOK
	v.keysOK = [][]byte{keysHash(cur), keysHash(raw)}
	if err := v.save(); err != nil {
		v.keysOK = prev
		return err
	}
	if err := writeAtomic(v.keysPath, raw); err != nil {
		v.keysOK = [][]byte{keysHash(cur)}
		v.save()
		return err
	}
	v.keysOK = [][]byte{keysHash(raw)}
	// If this last write fails, the vault still accepts both files and
	// the next OpenSealed keeps the one on the drive.
	v.save()
	return nil
}

// checkKeys is OpenSealed's check of the keys file raw (parsed as kf)
// against the vault opened under key ID want. A vault from before the
// binding records none and adopts the file it was opened with. Caller
// does not hold mu.
func (v *Vault) checkKeys(raw []byte, kf *keyFile, want []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.keysOK) > 0 && !v.acceptsKeys(raw) {
		return ErrRolledBack
	}
	if _, err := kf.keyID(); err != nil {
		// An interrupted re-encryption: keep the slots for the key the
		// vault is sealed under (reencrypt.go).
		return v.replaceKeys(&keyFile{Magic: kf.Magic, Version: kf.Version, Slots: slotsFor(kf, want)})
	}
	if len(v.keysOK) != 1 {
		v.keysOK = [][]byte{keysHash(raw)}
		return v.save()
	}
	return nil
}

func slotsFor(kf *keyFile, id []byte) []Slot {
	var out []Slot
	for _, s := range kf.Slots {
		if bytes.Equal(s.KeyID, id) {
			out = append(out, s)
		}
	}
	return out
}
