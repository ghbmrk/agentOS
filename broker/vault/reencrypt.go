package vault

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
)

// Re-encryption (REC-4, CRED-8; recovery R10a). Rekey replaces a slot but
// keeps the data key, so whoever learned the data key once (a lost card
// plus an earlier keys file or backup) keeps opening every later copy of
// the drive. Reencrypt moves the vault to a fresh data key and rewraps the
// slots the caller can prove, so after a rotation that replaced the lost
// factors, later copies are out of the old key's reach. Copies taken
// before stay readable with the old key, as CRED-8 says of any rotation.

// ErrReencryptPending: a re-encryption was interrupted, so the keys file
// holds slots for two data keys. OpenSealed finishes it.
var ErrReencryptPending = errors.New("vault: a re-encryption is unfinished; open the vault to finish it")

// ErrSlotNotProven: a passphrase or recovery slot could not be rewrapped
// because no factor given opens it. Reencrypt changes nothing then: those
// slots are how the owner gets in, and dropping one silently would lock
// the card out.
var ErrSlotNotProven = errors.New("vault: every passphrase and recovery slot needs its factor to re-encrypt")

// crashPoint lets tests stop Reencrypt between its writes, as a crash
// would. Tests set it; nothing else may.
var crashPoint = func(step int) error { return nil }

// newKeyID names a data key without revealing anything about it.
func newKeyID(key []byte) []byte {
	h := sha256.New()
	h.Write([]byte("agentos-vault-key-id/v1\x00"))
	h.Write(key)
	return h.Sum(nil)[:16]
}

// fileKeyID reads the key ID from a vault file's envelope (no decryption).
func fileKeyID(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("vault: not a vault file this version can read")
	}
	return env.KeyID, nil
}

// finishReencrypt keeps only the slots for key ID want: the vault file is
// sealed under that key, so the others open nothing current.
func finishReencrypt(keysPath string, kf *keyFile, want []byte) error {
	out := kf.Slots[:0:0]
	for _, s := range kf.Slots {
		if bytes.Equal(s.KeyID, want) {
			out = append(out, s)
		}
	}
	kf.Slots = out
	return writeKeys(keysPath, kf)
}

// Reencrypt seals the open vault under a fresh data key and rewraps every
// slot one of factors opens, each under its existing key-encryption key,
// so no factor changes. A passphrase or recovery slot no factor opens
// refuses the whole call (ErrSlotNotProven), changing nothing. A TPM slot
// no factor opens (another PC's, or a boot-PIN slot without its PIN) is
// dropped, and the count is returned so the owner can be told to trust
// that PC again (CRED-9).
//
// Rewrapping keeps each slot's key-encryption key, so a factor the owner
// lost must be replaced (Rekey) before Reencrypt, or the new key is wrapped
// under it again. The vault process supplies the TPM factor for this PC.
//
// Crash safety: the keys file first gains the new slots beside the old,
// then the vault file is sealed under the new key (advancing a bound
// rollback counter), then the old slots go. OpenSealed after a crash uses
// the slots for whichever key the vault file is under and drops the rest.
// Other entries, such as recovery's backup MAC key, are carried over
// unchanged; rotating them is the caller's Put.
func (v *Vault) Reencrypt(factors ...Factor) (dropped int, err error) {
	for _, f := range factors {
		defer wipeFactor(f)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return 0, ErrClosed
	}
	if v.key == nil {
		return 0, errors.New("vault: not opened through its key slots")
	}
	kf, err := readKeys(v.keysPath)
	if err != nil {
		return 0, err
	}
	if _, err := kf.keyID(); err != nil {
		return 0, err
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return 0, err
	}
	defer wipe(key)
	id := newKeyID(key)
	var fresh []Slot
	for _, s := range kf.Slots {
		kek := proveSlot(s, v.key, factors)
		if kek == nil {
			if s.Kind != SlotTPM {
				return 0, ErrSlotNotProven
			}
			dropped++
			continue
		}
		n, err := rewrap(s, kek, key, id)
		wipe(kek)
		if err != nil {
			return 0, err
		}
		fresh = append(fresh, n)
	}
	aead, err := newAEAD(key)
	if err != nil {
		return 0, err
	}

	// 1. Both sets of slots: a crash here leaves the vault under the old
	// key with its old slots.
	both := &keyFile{Magic: kf.Magic, Version: kf.Version, Slots: append(append([]Slot(nil), kf.Slots...), fresh...)}
	if err := writeKeys(v.keysPath, both); err != nil {
		return 0, err
	}
	if err := crashPoint(1); err != nil {
		return 0, err
	}
	// 2. The vault under the new key.
	oldAEAD, oldID := v.aead, v.keyID
	v.aead, v.keyID = aead, id
	if err := v.save(); err != nil {
		v.aead, v.keyID = oldAEAD, oldID
		writeKeys(v.keysPath, kf)
		return 0, err
	}
	wipe(v.key)
	v.key = append([]byte(nil), key...)
	if err := crashPoint(2); err != nil {
		return 0, err
	}
	// 3. Only the new slots. A failure here is finished by the next
	// OpenSealed; the vault is already under the new key.
	writeKeys(v.keysPath, &keyFile{Magic: kf.Magic, Version: kf.Version, Slots: fresh})
	return dropped, nil
}

// proveSlot returns the slot's key-encryption key if one of factors gives
// it and it opens the slot to the current data key, else nil.
func proveSlot(s Slot, current []byte, factors []Factor) []byte {
	for _, f := range factors {
		if f.Kind() != s.Kind {
			continue
		}
		kek, err := f.KEK(s)
		if err != nil {
			continue
		}
		aead, err := newAEAD(kek)
		if err != nil || len(s.Nonce) != aead.NonceSize() {
			wipe(kek)
			continue
		}
		got, err := aead.Open(nil, s.Nonce, s.Wrapped, s.aad())
		ok := err == nil && bytes.Equal(got, current)
		wipe(got)
		if ok {
			return kek
		}
		wipe(kek)
	}
	return nil
}

// rewrap makes a copy of s that wraps key (ID id) under kek.
func rewrap(s Slot, kek, key, id []byte) (Slot, error) {
	aead, err := newAEAD(kek)
	if err != nil {
		return Slot{}, err
	}
	n := s
	n.KeyID = id
	n.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(n.Nonce); err != nil {
		return Slot{}, err
	}
	n.Wrapped = aead.Seal(nil, n.Nonce, key, n.aad())
	return n, nil
}
