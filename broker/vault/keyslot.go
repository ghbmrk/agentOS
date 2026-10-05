package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Key slots (CRED-8). The data key never reaches the drive in the clear:
// a keys file beside the vault holds it wrapped (AES-256-GCM) under each
// slot's key-encryption key. A slot's kind decides where that key comes
// from: the Owner Card's vault passphrase through Argon2id, a TPM seal
// (P2-4b, implemented by the vault process over package tpmseal), or the
// recovery key (REC-1). Every slot's kind and parameters
// are bound into its wrap as associated data, so an edited slot opens
// nothing.

// Slot kinds. The passphrase factor is here; the TPM factor lives in the
// vault process (cmd/agentos-egress), which alone talks to the TPM. Every
// known kind loads and is kept, whether or not this build can open it.
const (
	SlotPassphrase = "passphrase"
	SlotTPM        = "tpm"
	SlotRecovery   = "recovery"
)

// KindTOTPSeed is the owner's code-generator seed (CH-4). It lives only in
// the vault, so a copy of the drive cannot compute approval codes (CRED-8).
const KindTOTPSeed = "totp_seed"

// KindPCRPolicyKey is the box's PCR policy key (HW-5a): it approves the
// boot paths a trusted host may unlock on, so it too lives only in the
// vault.
const KindPCRPolicyKey = "pcr_policy_key"

// KindTPMLockoutAuth is a trusted PC's TPM lockout authorization (CRED-8
// boot PIN): whoever holds it can reset the TPM's PIN guess counter, so
// it lives only in the vault.
const KindTPMLockoutAuth = "tpm_lockout_auth"

// MinPassphraseLen is the shortest normalized passphrase enrolled. The
// Owner Card's generated passphrase carries at least 80 bits (§8.1); this
// floor only stops an obviously weak replacement.
const MinPassphraseLen = 20

const keysMagic = "agentos-vault-keys"
const keysVersion = 1

// KDF is a slot's Argon2id salt and cost.
type KDF struct {
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// specFloor is CRED-8's minimum: Argon2id with at least 256 MiB.
var specFloor = KDF{Time: 1, MemoryKiB: 256 << 10, Threads: 1}

// kdfFloor is checked before any derivation, so a keys file cannot make a
// guess cheap. Tests lower it; nothing else may.
var kdfFloor = specFloor

// kdfCeiling bounds what a keys file can make the box spend on one guess.
// The floor profile has 8 GB (HW-4).
var kdfCeiling = KDF{Time: 20, MemoryKiB: 2 << 20, Threads: 16}

// defaultKDF is the cost new passphrase slots get: 256 MiB, three passes,
// four lanes for the floor's four cores. It takes about 1 s on a 4-core
// cloud host; tuning to about 1 s on the N95 itself (HW-4) waits for the
// hardware.
var defaultKDF = KDF{Time: 3, MemoryKiB: 256 << 10, Threads: 4}

// Slot is one wrapped copy of the data key.
type Slot struct {
	Kind string `json:"kind"`
	// KDF is set for passphrase (and recovery) slots.
	KDF *KDF `json:"kdf,omitempty"`
	// Sealed is opaque factor data, such as a TPM-sealed blob (P2-4b).
	Sealed []byte `json:"sealed,omitempty"`
	// KeyID names the data key the slot wraps, once the vault has been
	// re-encrypted (reencrypt.go); empty before. It is bound into the wrap.
	KeyID   []byte `json:"key_id,omitempty"`
	Nonce   []byte `json:"nonce"`
	Wrapped []byte `json:"wrapped"`
}

// aad binds everything in the slot except the wrap itself.
func (s Slot) aad() []byte {
	b, _ := json.Marshal(struct {
		Magic   string `json:"magic"`
		Version int    `json:"version"`
		Kind    string `json:"kind"`
		KDF     *KDF   `json:"kdf,omitempty"`
		Sealed  []byte `json:"sealed,omitempty"`
		KeyID   []byte `json:"key_id,omitempty"`
	}{keysMagic, keysVersion, s.Kind, s.KDF, s.Sealed, s.KeyID})
	return b
}

// Factor derives a slot's key-encryption key. The TPM factor (P2-4b)
// implements it over Slot.Sealed and answers ErrSkipSlot for a slot sealed
// on another PC.
type Factor interface {
	Kind() string
	// Enroll makes a new slot of this kind and returns it, without its
	// wrap, together with its key-encryption key.
	Enroll() (Slot, []byte, error)
	// KEK derives the key-encryption key for an existing slot.
	KEK(Slot) ([]byte, error)
}

// ErrSkipSlot is what a factor's KEK returns for a slot that is not its
// own, such as a TPM slot sealed on another PC: unwrap tries the next one.
var ErrSkipSlot = errors.New("vault: key slot belongs to another factor instance")

// ErrNoSlotOpens is the one answer for a wrong factor, a slot of another
// kind, and an edited slot.
var ErrNoSlotOpens = errors.New("vault: no key slot opens with this factor")

// ErrChangeInterrupted is ErrNoSlotOpens for a passphrase while a
// passphrase change is staged beside the keys file (keysbind.go): the
// vault may already be under the new passphrase (P2-4g). It says only
// that an interrupted change exists.
var ErrChangeInterrupted = fmt.Errorf("%w; a passphrase change was interrupted", ErrNoSlotOpens)

// Passphrase is the Owner Card's vault passphrase as a factor. It is
// normalized first (see normalize), so a scan and a typed copy agree.
func Passphrase(p string) Factor { return passphrase(normalize(p)) }

type passphrase []byte

func (passphrase) Kind() string { return SlotPassphrase }

func (p passphrase) wipe() { wipe(p) }

// wipeFactor clears a factor's secret bytes once the call that took it is
// done, where the factor holds any (the normalized passphrase). Callers
// pass a fresh factor for each call.
func wipeFactor(f Factor) {
	if w, ok := f.(interface{ wipe() }); ok {
		w.wipe()
	}
}

func (p passphrase) Enroll() (Slot, []byte, error) {
	if len(p) < MinPassphraseLen {
		return Slot{}, nil, fmt.Errorf("vault: passphrase shorter than %d characters", MinPassphraseLen)
	}
	k := defaultKDF
	k.Salt = make([]byte, 16)
	if _, err := rand.Read(k.Salt); err != nil {
		return Slot{}, nil, err
	}
	s := Slot{Kind: SlotPassphrase, KDF: &k}
	kek, err := p.KEK(s)
	return s, kek, err
}

func (p passphrase) KEK(s Slot) ([]byte, error) {
	k := s.KDF
	if k == nil {
		return nil, errors.New("vault: passphrase slot without KDF parameters")
	}
	if k.Time < kdfFloor.Time || k.MemoryKiB < kdfFloor.MemoryKiB || k.Threads < kdfFloor.Threads || len(k.Salt) < 16 {
		return nil, errors.New("vault: passphrase slot below the Argon2id floor (CRED-8)")
	}
	if k.Time > kdfCeiling.Time || k.MemoryKiB > kdfCeiling.MemoryKiB || k.Threads > kdfCeiling.Threads || len(k.Salt) > 64 {
		return nil, errors.New("vault: passphrase slot above the Argon2id ceiling")
	}
	return argon2.IDKey(p, k.Salt, k.Time, k.MemoryKiB, k.Threads, KeySize), nil
}

// normalize lowercases the passphrase and joins its words with single
// spaces: card.NormalizePassphrase's canonical form (P2-2), so the card
// and the slot agree on what a scanned or typed passphrase is. Hyphens are
// kept; they belong to some word-list entries.
func normalize(p string) []byte {
	return []byte(strings.Join(strings.Fields(strings.ToLower(p)), " "))
}

type keyFile struct {
	Magic   string `json:"magic"`
	Version int    `json:"version"`
	Slots   []Slot `json:"slots"`
}

func readKeys(path string) (*keyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseKeys(raw)
}

func parseKeys(raw []byte) (*keyFile, error) {
	var kf keyFile
	if err := json.Unmarshal(raw, &kf); err != nil || kf.Magic != keysMagic || kf.Version != keysVersion {
		return nil, errors.New("vault: not a keys file this version can read")
	}
	for _, s := range kf.Slots {
		switch s.Kind {
		case SlotPassphrase, SlotTPM, SlotRecovery:
		default:
			return nil, fmt.Errorf("vault: unknown key slot kind %q", s.Kind)
		}
	}
	return &kf, nil
}

// unwrap returns the data key from the first slot of f's kind that opens,
// among the slots for key ID want.
func (kf *keyFile) unwrap(f Factor, want []byte) ([]byte, error) {
	key, _, err := kf.unwrapSlot(f, want)
	return key, err
}

// unwrapSlot is unwrap also returning the slot that opened.
func (kf *keyFile) unwrapSlot(f Factor, want []byte) ([]byte, Slot, error) {
	for _, s := range kf.Slots {
		if s.Kind != f.Kind() || !bytes.Equal(s.KeyID, want) {
			continue
		}
		kek, err := f.KEK(s)
		if errors.Is(err, ErrSkipSlot) {
			continue
		}
		if err != nil {
			return nil, Slot{}, err
		}
		aead, err := newAEAD(kek)
		wipe(kek)
		if err != nil {
			return nil, Slot{}, err
		}
		if len(s.Nonce) != aead.NonceSize() {
			continue
		}
		if key, err := aead.Open(nil, s.Nonce, s.Wrapped, s.aad()); err == nil && len(key) == KeySize {
			return key, s, nil
		}
	}
	return nil, Slot{}, ErrNoSlotOpens
}

// keyID returns the one key ID every slot in the file shares, or
// ErrReencryptPending if a re-encryption was interrupted and the file holds
// slots for two keys (OpenSealed finishes it).
func (kf *keyFile) keyID() ([]byte, error) {
	var id []byte
	for i, s := range kf.Slots {
		if i > 0 && !bytes.Equal(s.KeyID, id) {
			return nil, ErrReencryptPending
		}
		id = s.KeyID
	}
	return id, nil
}

// wrap makes a slot for f holding key, whose ID is keyID.
func wrap(f Factor, key, keyID []byte) (Slot, error) {
	s, kek, err := f.Enroll()
	if err != nil {
		return Slot{}, err
	}
	s.KeyID = keyID
	aead, err := newAEAD(kek)
	wipe(kek)
	if err != nil {
		return Slot{}, err
	}
	s.Nonce = make([]byte, aead.NonceSize())
	if _, err := rand.Read(s.Nonce); err != nil {
		return Slot{}, err
	}
	s.Wrapped = aead.Seal(nil, s.Nonce, key, s.aad())
	return s, nil
}

// ReadSlots lists the keys file's slots. Nothing in a slot is secret: the
// wrap is ciphertext, and Sealed is a factor's public or TPM-encrypted data.
func ReadSlots(keysPath string) ([]Slot, error) {
	kf, err := readKeys(keysPath)
	if err != nil {
		return nil, err
	}
	return kf.Slots, nil
}

// sealedBy records the keys file and a copy of the data key on a vault
// opened through its slots, so AddSlot can wrap the key for a new factor
// without the owner proving an old one again. Close wipes the copy. The
// cipher's AES key schedule already holds the key's equivalent in memory
// while the vault is open, so the copy adds no exposure.
func (v *Vault) sealedBy(keysPath string, key []byte) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.keysPath, v.key = keysPath, append([]byte(nil), key...)
}

// AddSlot wraps the open vault's data key for f and adds the slot,
// first removing any existing slot of f's kind for which replace returns
// true (the same PC enrolled again). CRED-9 makes adding a trusted host a
// tier-4 action: the caller checks the approval before calling.
func (v *Vault) AddSlot(f Factor, replace func(Slot) bool) error {
	defer wipeFactor(f)
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.slotsForChange()
	if err != nil {
		return err
	}
	s, err := wrap(f, v.key, v.keyID)
	if err != nil {
		return err
	}
	out := kf.Slots[:0:0]
	for _, old := range kf.Slots {
		if old.Kind == f.Kind() && replace != nil && replace(old) {
			continue
		}
		out = append(out, old)
	}
	kf.Slots = append(out, s)
	return v.replaceKeys(kf)
}

// RemoveSlots drops the trusted-host slots for which match returns true
// and reports how many. Only TPM slots are removed this way: the
// passphrase is replaced with Rekey, and the recovery slot belongs to
// REC-1. CRED-9: the caller checks the tier-4 approval first.
func (v *Vault) RemoveSlots(kind string, match func(Slot) bool) (int, error) {
	if kind != SlotTPM {
		return 0, errors.New("vault: only trusted-host slots can be removed")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.slotsForChange()
	if err != nil {
		return 0, err
	}
	out, n := kf.Slots[:0:0], 0
	for _, s := range kf.Slots {
		if s.Kind == kind && match(s) {
			n++
			continue
		}
		out = append(out, s)
	}
	if n == 0 {
		return 0, nil
	}
	kf.Slots = out
	return n, v.replaceKeys(kf)
}

// Rekey proves have against the keys file, then replaces every slot of
// next's kind with one new slot for next. Slots of other kinds stay. A
// copy of the keys file taken earlier no longer opens the vault written
// since (the keys file's hash is in the vault, keysbind.go), but a whole
// earlier copy of the drive still opens with what it held (CRED-8:
// replacement protects only against later copies; Reencrypt closes the
// data key too).
func (v *Vault) Rekey(have, next Factor) error {
	defer wipeFactor(have)
	defer wipeFactor(next)
	v.mu.Lock()
	defer v.mu.Unlock()
	kf, err := v.slotsForChange()
	if err != nil {
		return err
	}
	if proveSlotOfKind(kf, v.key, have) == false {
		return ErrNoSlotOpens
	}
	s, err := wrap(next, v.key, v.keyID)
	if err != nil {
		return err
	}
	out := kf.Slots[:0:0]
	for _, old := range kf.Slots {
		if old.Kind != next.Kind() {
			out = append(out, old)
		}
	}
	kf.Slots = append(out, s)
	return v.replaceKeys(kf)
}

// proveSlotOfKind reports whether f opens one of its kind's slots to key.
func proveSlotOfKind(kf *keyFile, key []byte, f Factor) bool {
	for _, s := range kf.Slots {
		if s.Kind != f.Kind() {
			continue
		}
		if kek := proveSlot(s, key, []Factor{f}); kek != nil {
			wipe(kek)
			return true
		}
	}
	return false
}

// CreateSealed makes a new, empty vault at vaultPath under a fresh random
// data key, and a keys file at keysPath with one slot for f. It refuses to
// replace either file. Its local copy of the data key is wiped before it
// returns; the open vault keeps one for AddSlot, wiped by Close.
func CreateSealed(vaultPath, keysPath string, f Factor) (*Vault, error) {
	defer wipeFactor(f)
	if _, err := os.Lstat(keysPath); err == nil {
		return nil, errors.New("vault: keys file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, KeySize)
	defer wipe(key)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	s, err := wrap(f, key, nil)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(&keyFile{Magic: keysMagic, Version: keysVersion, Slots: []Slot{s}})
	if err != nil {
		return nil, err
	}
	v, err := create(vaultPath, key, [][]byte{keysHash(raw)})
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(keysPath, raw); err != nil {
		v.Close()
		os.Remove(vaultPath)
		return nil, err
	}
	v.sealedBy(keysPath, key)
	return v, nil
}

// OpenSealed unwraps the data key with f and opens the vault. The keys
// file must be one the vault recorded (keysbind.go): an earlier keys file
// beside a later vault is refused with ErrRolledBack. The factor's secret
// bytes and the unwrapped key are wiped before it returns; the open vault
// keeps its cipher and one copy of the key for AddSlot, wiped by Close. If
// a slot change or re-encryption was interrupted, it finishes it.
func OpenSealed(vaultPath, keysPath string, f Factor) (*Vault, error) {
	defer wipeFactor(f)
	raw, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, err
	}
	kf, err := parseKeys(raw)
	if err != nil {
		return nil, err
	}
	want, err := fileKeyID(vaultPath)
	if err != nil {
		return nil, err
	}
	key, slot, err := kf.unwrapSlot(f, want)
	staged := false
	if err != nil {
		// A slot change interrupted after its seal: f's slot may be only
		// in the staged next file (keysbind.go). It counts only if the
		// vault it opens sealed that same file. Only a plain miss looks
		// there: a factor whose KEK failed otherwise (a TPM refusing a
		// PIN) is not asked again, so the staged file never doubles its
		// attempts before lockout.
		if !errors.Is(err, ErrNoSlotOpens) {
			return nil, err
		}
		nraw, rerr := os.ReadFile(keysPath + nextSuffix)
		if rerr != nil {
			return nil, err
		}
		nkf, perr := parseKeys(nraw)
		if perr != nil {
			return nil, err
		}
		nkey, nslot, nerr := nkf.unwrapSlot(f, want)
		if nerr != nil {
			if errors.Is(nerr, ErrNoSlotOpens) && f.Kind() == SlotPassphrase && passphraseChanged(kf, nkf) {
				return nil, ErrChangeInterrupted
			}
			return nil, err
		}
		raw, kf, key, slot, staged = nraw, nkf, nkey, nslot, true
	}
	defer wipe(key)
	v, err := Open(vaultPath, key)
	if err != nil {
		return nil, err
	}
	if staged && !v.stagedKeys(raw) {
		v.Close()
		return nil, ErrNoSlotOpens
	}
	v.sealedBy(keysPath, key)
	if err := v.checkKeys(raw, kf, want, slot); err != nil {
		v.Close()
		return nil, err
	}
	v.unfinished = v.dropStaleStaged()
	return v, nil
}

// ChangeUnfinished reports that OpenSealed found a passphrase change that
// was staged but never sealed, so it did not happen and the owner should
// change the passphrase again (P2-4g).
func (v *Vault) ChangeUnfinished() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.unfinished
}
