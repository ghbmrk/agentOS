package vault

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
// A slot change first seals the whole next keys file into the vault
// (L3 review round 2 of #45): from then the change is decided and only
// rolls forward. The next file is staged at keysPath+nextSuffix before
// that seal, so a factor whose slot only the next file holds can open the
// vault mid-change. The change then writes the keys file, records the next
// file's hash, clears it, and removes the staged copy. A crash anywhere leaves the vault either
// before the change or holding the next file; OpenSealed then writes the
// next file over whichever keys file is on the drive, and opens only if
// the slot that opened is one the next file keeps, so a slot the change
// removed, put back with the file before, opens nothing.

// crashKeysSealed is the crashPoint after a slot change sealed the next
// keys file and before it wrote it (tests).
const crashKeysSealed = 3

// nextSuffix names the staged copy of the next keys file, written beside
// the keys file before the seal (defect fix in P2-4d). Without it, a
// Rekey interrupted after the seal left only the file before on the
// drive: the old passphrase's slot is not in the next file, and the new
// passphrase's slot was in no file, so neither opened the vault. The
// staged file counts only when it is the next file the vault sealed.
const nextSuffix = ".next"

func keysHash(raw []byte) []byte {
	h := sha256.Sum256(raw)
	return h[:]
}

// slotsForChange reads the keys file for a slot change on an open vault,
// finishing a change still under way first, and refusing one this vault
// did not record or one mid re-encryption. Caller holds mu.
func (v *Vault) slotsForChange() (*keyFile, error) {
	if v.closed {
		return nil, ErrClosed
	}
	if v.key == nil {
		return nil, errors.New("vault: not opened through its key slots")
	}
	if v.nextKeys != nil {
		if err := v.finishKeys(); err != nil {
			return nil, err
		}
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
	return len(v.keysOK) == 1 && bytes.Equal(v.keysOK[0], keysHash(raw))
}

// replaceKeys moves the vault to kf as its keys file. Once the first write
// has landed the change is decided: a later failure returns an error, and
// the change completes at the next slot change or OpenSealed. Caller
// holds mu.
func (v *Vault) replaceKeys(kf *keyFile) error {
	raw, err := json.Marshal(kf)
	if err != nil {
		return err
	}
	cur, cerr := readKeys(v.keysPath)
	if err := writeAtomic(v.keysPath+nextSuffix, raw); err != nil {
		return err
	}
	v.nextKeys = raw
	if err := v.save(); err != nil {
		// The staged file stays: save can fail after the vault file
		// landed (a failed directory sync), and then the drive needs it.
		// A leftover copy is inert (stagedKeys, dropStaleStaged).
		v.nextKeys = nil
		return err
	}
	// Sealed, so decided: a change of the passphrase replaces any that
	// never took effect (P2-4g).
	if cerr == nil && passphraseChanged(cur, kf) {
		v.unfinished = false
	}
	if err := crashPoint(crashKeysSealed); err != nil {
		return err
	}
	if err := v.finishKeys(); err != nil {
		return fmt.Errorf("vault: slot change not finished; it completes when the vault next opens: %w", err)
	}
	return nil
}

// finishKeys writes the pending next keys file to the drive if it is not
// there, then records it as the one this vault goes with. Caller holds mu.
func (v *Vault) finishKeys() error {
	next := v.nextKeys
	if cur, err := readFile(v.keysPath); err != nil || !bytes.Equal(cur, next) {
		if err := writeAtomic(v.keysPath, next); err != nil {
			return err
		}
	}
	prev := v.keysOK
	v.keysOK, v.nextKeys = [][]byte{keysHash(next)}, nil
	if err := v.save(); err != nil {
		v.keysOK, v.nextKeys = prev, next
		return err
	}
	// A staged copy left behind opens nothing (stagedKeys), so failing to
	// remove it is not an error.
	os.Remove(v.keysPath + nextSuffix)
	return nil
}

// dropStaleStaged removes a staged next keys file left beside the keys
// file once no slot change is under way, and reports whether it changed
// the passphrase: a passphrase change that never took effect (P2-4g). It
// opens nothing (stagedKeys), so this is housekeeping and a failure is
// ignored. It assumes one open
// Vault per keys path, as the vault process keeps: a second Vault mid
// change on the same path would lose its staged file. Caller does not
// hold mu.
func (v *Vault) dropStaleStaged() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.nextKeys != nil {
		return false
	}
	changed := false
	if nraw, err := os.ReadFile(v.keysPath + nextSuffix); err == nil {
		cur, cerr := readKeys(v.keysPath)
		nkf, nerr := parseKeys(nraw)
		changed = cerr == nil && nerr == nil && passphraseChanged(cur, nkf)
		os.Remove(v.keysPath + nextSuffix)
	}
	return changed
}

// stagedKeys reports whether raw, read from the staged next keys file,
// is the next file this vault sealed. Caller does not hold mu.
func (v *Vault) stagedKeys(raw []byte) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.nextKeys != nil && bytes.Equal(raw, v.nextKeys)
}

// checkKeys is OpenSealed's check of the keys file raw (parsed as kf),
// whose slot opened the vault under key ID want. A vault that records no
// keys file (made by Create, not CreateSealed) accepts none. Caller does
// not hold mu.
func (v *Vault) checkKeys(raw []byte, kf *keyFile, want []byte, opened Slot) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.nextKeys != nil {
		// A slot change under way: the drive holds the file before or
		// the file after. Roll forward, and only for a slot the next
		// file keeps.
		if !v.acceptsKeys(raw) && !bytes.Equal(raw, v.nextKeys) {
			return ErrRolledBack
		}
		nkf, err := parseKeys(v.nextKeys)
		if err != nil {
			return err
		}
		if !nkf.has(opened) {
			if opened.Kind == SlotPassphrase && passphraseChanged(kf, nkf) {
				// The change replaced this passphrase (P2-4g).
				return ErrChangeInterrupted
			}
			return ErrNoSlotOpens
		}
		if err := v.finishKeys(); err != nil {
			return err
		}
		kf = nkf
	} else if !v.acceptsKeys(raw) {
		return ErrRolledBack
	}
	if _, err := kf.keyID(); err != nil {
		// An interrupted re-encryption: keep the slots for the key the
		// vault is sealed under (reencrypt.go).
		return v.replaceKeys(&keyFile{Magic: kf.Magic, Version: kf.Version, Slots: slotsFor(kf, want)})
	}
	return nil
}

// passphraseChanged reports whether the slot change from cur to next is a
// passphrase change: both files wrap the same data key, and next drops a
// passphrase slot of cur and adds one of its own. A re-encryption re-wraps
// every slot under a new key ID, and an added passphrase slot keeps the
// old one, so neither counts (security R2 on #93).
func passphraseChanged(cur, next *keyFile) bool {
	a, err := cur.keyID()
	if err != nil {
		return false
	}
	b, err := next.keyID()
	if err != nil || !bytes.Equal(a, b) {
		return false
	}
	return dropsPassphrase(cur, next) && dropsPassphrase(next, cur)
}

// dropsPassphrase reports whether from holds a passphrase slot to lacks.
func dropsPassphrase(from, to *keyFile) bool {
	for _, s := range from.Slots {
		if s.Kind == SlotPassphrase && !to.has(s) {
			return true
		}
	}
	return false
}

// has reports whether the file holds slot s unchanged.
func (kf *keyFile) has(s Slot) bool {
	want, err := json.Marshal(s)
	if err != nil {
		return false
	}
	for _, t := range kf.Slots {
		if got, err := json.Marshal(t); err == nil && bytes.Equal(got, want) {
			return true
		}
	}
	return false
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
