package recovery

import (
	"crypto/rand"
	"errors"

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
}

// Vault entries this package keeps. Only the vault process reads them.
const (
	// CardName holds the full Owner Card (EncodeCard).
	CardName = "owner-card"
	KindCard = "owner_card"
	// KindCardPart marks each printed card secret's own entry
	// ("owner-card-passphrase" and so on), there for the redactor.
	KindCardPart = "owner_card_part"
	// BackupKeyName holds the X25519 public key backups are sealed to.
	BackupKeyName = "recovery-backup-key"
	KindBackupKey = "backup_public_key"
	// StateName holds the restore state (REC-2).
	StateName = "recovery-state"
	KindState = "recovery_state"
	// SeedName is the code-generator seed's entry, as in the vault
	// process (cmd/agentos-egress); TestSeedNameMatchesTheVaultProcess
	// keeps the two equal.
	SeedName = "owner-totp-seed"
)

// opens reports whether rk opens the drive's recovery slot. It opens a
// second, short-lived view of the vault to prove it.
func (b *Box) opens(rk RecoveryKey) bool {
	if !rk.Valid() {
		return false
	}
	v, err := vault.OpenSealed(b.VaultPath, b.KeysPath, Factor(rk))
	if err != nil {
		return false
	}
	v.Close()
	return true
}

// LoadCard reads the Owner Card from the vault.
func (b *Box) LoadCard() (Card, error) {
	s, ok := b.V.Secret(CardName)
	if !ok {
		return Card{}, errors.New("recovery: no Owner Card in the vault")
	}
	return DecodeCard([]byte(s.Reveal()))
}
