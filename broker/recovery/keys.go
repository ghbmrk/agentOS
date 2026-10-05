package recovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/ghbmrk/agentos/broker/vault"
)

// keysFile mirrors the vault's key-slot file (vault/keyslot.go) field for
// field, so this package can check it strictly (A8) and drop host slots
// on restore. TestKeysMirrorMatchesTheVault fails if the two drift.
type keysFile struct {
	Magic   string     `json:"magic"`
	Version int        `json:"version"`
	Slots   []keysSlot `json:"slots"`
}

type keysSlot struct {
	Kind    string   `json:"kind"`
	KDF     *keysKDF `json:"kdf,omitempty"`
	Sealed  []byte   `json:"sealed,omitempty"`
	Nonce   []byte   `json:"nonce"`
	Wrapped []byte   `json:"wrapped"`
}

type keysKDF struct {
	Salt      []byte `json:"salt"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// CheckKeys holds the plaintext key-slot file to A8: it carries the TPM,
// passphrase, and recovery slots and nothing else. An unknown field, an
// unknown kind, a second passphrase or recovery slot, a passphrase slot
// without Argon2id parameters, a recovery slot that is not a bare salt, or
// a wrapped key of the wrong size fails. Nothing in it verifies an
// approval code: there is no field for one.
func CheckKeys(raw []byte) error {
	_, err := parseKeys(raw)
	return err
}

func parseKeys(raw []byte) (*keysFile, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var kf keysFile
	if err := d.Decode(&kf); err != nil {
		return nil, fmt.Errorf("recovery: key slots: %v", err)
	}
	if d.More() {
		return nil, errors.New("recovery: key slots: trailing data")
	}
	if kf.Magic != "agentos-vault-keys" || kf.Version != 1 {
		return nil, errors.New("recovery: not a key-slot file this version can read")
	}
	n := map[string]int{}
	for _, s := range kf.Slots {
		n[s.Kind]++
		switch s.Kind {
		case vault.SlotPassphrase:
			if s.KDF == nil || len(s.KDF.Salt) < 16 || len(s.Sealed) != 0 {
				return nil, errors.New("recovery: malformed passphrase slot")
			}
		case vault.SlotRecovery:
			if s.KDF != nil || len(s.Sealed) != 32 {
				return nil, errors.New("recovery: malformed recovery slot")
			}
		case vault.SlotTPM:
			// P2-4b may add Argon2id parameters for the boot PIN.
			if len(s.Sealed) == 0 {
				return nil, errors.New("recovery: malformed TPM slot")
			}
		default:
			return nil, fmt.Errorf("recovery: slot kind %q is not allowed", s.Kind)
		}
		if len(s.Nonce) != 12 || len(s.Wrapped) != vault.KeySize+16 {
			return nil, fmt.Errorf("recovery: malformed %s slot", s.Kind)
		}
	}
	if n[vault.SlotPassphrase] > 1 || n[vault.SlotRecovery] > 1 {
		return nil, errors.New("recovery: at most one passphrase slot and one recovery slot")
	}
	return &kf, nil
}

// dropHostSlots removes every TPM slot (CRED-9: new hardware is trusted
// only when the owner adds it) and returns how many it removed.
func dropHostSlots(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	kf, err := parseKeys(raw)
	if err != nil {
		return 0, err
	}
	var keep []keysSlot
	for _, s := range kf.Slots {
		if s.Kind != vault.SlotTPM {
			keep = append(keep, s)
		}
	}
	dropped := len(kf.Slots) - len(keep)
	if dropped == 0 {
		return 0, nil
	}
	kf.Slots = keep
	out, err := json.Marshal(kf)
	if err != nil {
		return 0, err
	}
	return dropped, writeAtomic(path, out)
}

// AuditNeedles lists every secret A8's scan must not find in plaintext:
// the vault data key (unwrapped from the recovery slot by this package's
// own reading of the file format, so the scan does not trust the vault
// code it audits), and every value in the vault, the Owner Card's fields
// among them. It is for the A8 scan tool and tests only.
func AuditNeedles(b *Box, rk RecoveryKey) ([]Needle, error) {
	raw, err := os.ReadFile(b.KeysPath)
	if err != nil {
		return nil, err
	}
	key, err := unwrapRecovery(raw, rk)
	if err != nil {
		return nil, err
	}
	out := []Needle{{Name: "vault data key", Value: key}}
	for _, e := range b.V.List() {
		s, _ := b.V.Secret(e.Name)
		out = append(out, Needle{Name: "vault entry " + e.Name, Value: []byte(s.Reveal()), Text: true})
	}
	if c, err := b.LoadCard(); err == nil {
		for name, v := range map[string]string{"Wi-Fi password": c.WiFiPassword, "setup secret": c.SetupSecret,
			"vault passphrase": c.VaultPassphrase, "recovery key text": c.RecoveryKey} {
			if len(v) >= minPattern {
				out = append(out, Needle{Name: name, Value: []byte(v), Text: true})
			}
		}
		out = append(out, Needle{Name: "grid seed", Value: c.GridSeed})
	}
	out = append(out, Needle{Name: "recovery key", Value: append([]byte(nil), rk.b[:]...)})
	return out, nil
}

// unwrapRecovery opens the recovery slot from the file format alone.
func unwrapRecovery(raw []byte, rk RecoveryKey) ([]byte, error) {
	kf, err := parseKeys(raw)
	if err != nil {
		return nil, err
	}
	for _, s := range kf.Slots {
		if s.Kind != vault.SlotRecovery {
			continue
		}
		aad, err := json.Marshal(struct {
			Magic   string   `json:"magic"`
			Version int      `json:"version"`
			Kind    string   `json:"kind"`
			KDF     *keysKDF `json:"kdf,omitempty"`
			Sealed  []byte   `json:"sealed,omitempty"`
		}{kf.Magic, kf.Version, s.Kind, s.KDF, s.Sealed})
		if err != nil {
			return nil, err
		}
		kek := hkdf(rk.b[:], s.Sealed, "agentos-slot-recovery-v1", vault.KeySize)
		aead, err := newGCM(kek)
		wipe(kek)
		if err != nil {
			return nil, err
		}
		return aead.Open(nil, s.Nonce, s.Wrapped, aad)
	}
	return nil, errors.New("recovery: no recovery slot")
}
