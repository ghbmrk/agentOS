package recovery

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"sync"

	"github.com/ghbmrk/agentos/broker/vault"
)

// Factor is the recovery key as a vault key-slot factor (CRED-8's third
// slot, REC-1). The key carries 160 bits and is never chosen by a person,
// so it is not stretched: its slot's key-encryption key is HKDF-SHA256 of
// the key under the slot's 32-byte salt, which the slot carries in its
// opaque Sealed field.
func Factor(rk RecoveryKey) vault.Factor { return factor{rk} }

type factor struct{ rk RecoveryKey }

func (factor) Kind() string { return vault.SlotRecovery }

func (f factor) Enroll() (vault.Slot, []byte, error) {
	if !f.rk.Valid() {
		return vault.Slot{}, nil, errors.New("recovery: no recovery key")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return vault.Slot{}, nil, err
	}
	s := vault.Slot{Kind: vault.SlotRecovery, Sealed: salt}
	kek, err := f.KEK(s)
	return s, kek, err
}

func (f factor) KEK(s vault.Slot) ([]byte, error) {
	if !f.rk.Valid() || s.KDF != nil || len(s.Sealed) != 32 {
		return nil, vault.ErrNoSlotOpens
	}
	return hkdf(f.rk.b[:], s.Sealed, "agentos-slot-recovery-v1", vault.KeySize), nil
}

// Box is the vault process's view of a drive: the sealed vault and its
// key-slot file, with the vault open (unlocked by any slot).
type Box struct {
	VaultPath, KeysPath string
	V                   *vault.Vault

	// Reencrypt moves the vault to a fresh data key, rewrapping the slots
	// owner proves (vault.Reencrypt; R10a). The vault process sets it to
	// its custody.reencrypt, which also gives the vault a new policy key
	// and reseals the trusted PCs it can (egress V7); nil calls
	// V.Reencrypt, which drops every TPM slot. It returns how many
	// trusted PCs must be trusted again.
	Reencrypt func(owner ...vault.Factor) (dropped int, err error)

	// mu serializes this package's read-modify-write operations on the
	// vault (re-confirmation, rotation, re-enrollment).
	mu sync.Mutex
}

// Vault entries this package keeps. Only the vault process reads them,
// and each is read only under its own kind: an entry of another kind (a
// credential written under a reserved name) fails closed.
const (
	// CardName holds the Owner Card's operating values (storedCard):
	// never the vault passphrase or the recovery key.
	CardName = "owner-card"
	KindCard = "owner_card"
	// KindCardPart marks each stored card secret's own entry
	// ("owner-card-wifi", "owner-card-setup"), there for the redactor.
	KindCardPart = "owner_card_part"
	// BackupKeyName holds the X25519 public key backups are sealed to,
	// bound to the recovery slot it belongs to.
	BackupKeyName = "recovery-backup-key"
	KindBackupKey = "backup_public_key"
	// MACKeyName holds the key of the MAC that ends every backup.
	MACKeyName = "recovery-backup-mac"
	KindMACKey = "backup_mac_key"
	// StateName holds the restore state (REC-2).
	StateName = "recovery-state"
	KindState = "recovery_state"
	// SeedName is the code-generator seed's entry, as in the vault
	// process (cmd/agentos-egress); TestSeedNameMatchesTheVaultProcess
	// keeps the two equal.
	SeedName = "owner-totp-seed"
)

// ErrWrongKind is a reserved entry stored under another kind.
var ErrWrongKind = errors.New("recovery: a reserved vault entry has the wrong kind")

// reserved reads a reserved entry, requiring its kind.
func reserved(v *vault.Vault, name, kind string) ([]byte, bool, error) {
	k, ok := entryKind(v, name)
	if !ok {
		return nil, false, nil
	}
	s, ok := v.Secret(name)
	if !ok {
		return nil, false, nil
	}
	if k != kind {
		return nil, true, ErrWrongKind
	}
	return []byte(s.Reveal()), true, nil
}

// opens reports whether rk opens the drive's recovery slot.
func (b *Box) opens(rk RecoveryKey) bool {
	return rk.Valid() && b.opensWith(Factor(rk))
}

// opensWith reports whether f opens the drive's key slots. It opens a
// second, short-lived view of the vault to prove it.
func (b *Box) opensWith(f vault.Factor) bool {
	if f == nil {
		return false
	}
	v, err := vault.OpenSealed(b.VaultPath, b.KeysPath, f)
	if err != nil {
		return false
	}
	v.Close()
	return true
}

// backupValue is the backup key entry: the public key and the recovery
// slot it was derived for, so a backup is never sealed to a key that no
// longer matches the drive's recovery slot.
type backupValue struct {
	Format string `json:"format"`
	Public []byte `json:"public"`
	Slot   []byte `json:"slot"`
}

const backupKeyFormat = "agentos-backup-key-v2"

func storeBackupKey(b *Box, rk RecoveryKey) error {
	pub, err := backupPublic(rk)
	if err != nil {
		return err
	}
	id, err := recoverySlotID(b.KeysPath)
	if err != nil {
		return err
	}
	if _, _, err := reserved(b.V, BackupKeyName, KindBackupKey); err != nil {
		return err
	}
	enc, err := json.Marshal(backupValue{backupKeyFormat, pub, id})
	if err != nil {
		return err
	}
	if err := b.V.Put(BackupKeyName, KindBackupKey, enc); err != nil {
		return err
	}
	// The forget log's key comes from the recovery key too (CAP-3).
	return ensureForgetLog(b.V, rk)
}

// backupKey returns the public key to seal backups to. It fails closed
// on a missing or wrong-kind entry, or one bound to another recovery slot.
func backupKey(b *Box) ([]byte, error) {
	raw, ok, err := reserved(b.V, BackupKeyName, KindBackupKey)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("recovery: no backup key in the vault; provision the recovery slot first")
	}
	var bv backupValue
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&bv); err != nil || bv.Format != backupKeyFormat || len(bv.Public) != 32 {
		return nil, errors.New("recovery: malformed backup key")
	}
	id, err := recoverySlotID(b.KeysPath)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(id, bv.Slot) {
		return nil, errors.New("recovery: the backup key does not match the drive's recovery slot; no backup made")
	}
	return bv.Public, nil
}

// ensureMACKey creates the backup MAC key if the vault has none.
func ensureMACKey(v *vault.Vault) error {
	_, ok, err := reserved(v, MACKeyName, KindMACKey)
	if err != nil || ok {
		return err
	}
	k, err := random(nil, 32)
	if err != nil {
		return err
	}
	defer wipe(k)
	return v.Put(MACKeyName, KindMACKey, k)
}

// rotateMACKey replaces the backup MAC key, which Reencrypt carries over
// and an earlier copy holds: with it, a backup the new recovery key opens
// could be altered outside its vault (R10a).
func rotateMACKey(v *vault.Vault) error {
	if _, _, err := reserved(v, MACKeyName, KindMACKey); err != nil {
		return err
	}
	k, err := random(nil, 32)
	if err != nil {
		return err
	}
	defer wipe(k)
	return v.Put(MACKeyName, KindMACKey, k)
}

// reencrypt runs the box's re-encryption.
func (b *Box) reencrypt(owner ...vault.Factor) (int, error) {
	if b.Reencrypt != nil {
		return b.Reencrypt(owner...)
	}
	return b.V.Reencrypt(owner...)
}

func macKey(v *vault.Vault) ([]byte, error) {
	k, ok, err := reserved(v, MACKeyName, KindMACKey)
	if err != nil {
		return nil, err
	}
	if !ok || len(k) != 32 {
		return nil, errors.New("recovery: no backup MAC key in the vault")
	}
	return k, nil
}

// LoadCard reads the Owner Card's stored values from the vault: every
// field but the vault passphrase and the recovery key, which the vault
// never holds.
func (b *Box) LoadCard() (Card, error) {
	raw, ok, err := reserved(b.V, CardName, KindCard)
	if err != nil {
		return Card{}, err
	}
	if !ok {
		return Card{}, errors.New("recovery: no Owner Card in the vault")
	}
	return DecodeCard(raw)
}
