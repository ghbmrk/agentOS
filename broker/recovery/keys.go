package recovery

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ghbmrk/agentos/broker/vault"
)

// keysFile mirrors the vault's key-slot file (vault/keyslot.go) field for
// field, so this package can check it strictly (A8) and unwrap the data
// key independently of the vault code it audits. TestKeysMirrorMatchesTheVault fails if the two drift.
type keysFile struct {
	Magic   string     `json:"magic"`
	Version int        `json:"version"`
	Slots   []keysSlot `json:"slots"`
}

type keysSlot struct {
	Kind    string   `json:"kind"`
	KDF     *keysKDF `json:"kdf,omitempty"`
	Sealed  []byte   `json:"sealed,omitempty"`
	KeyID   []byte   `json:"key_id,omitempty"`
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
	// One passphrase and one recovery slot per data key: an interrupted
	// re-encryption (vault.Reencrypt) leaves the old key's and the new
	// key's side by side until the vault next opens.
	n := map[string]int{}
	for _, s := range kf.Slots {
		n[s.Kind+"/"+hex.EncodeToString(s.KeyID)]++
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
	for k, c := range n {
		if c > 1 && !strings.HasPrefix(k, vault.SlotTPM+"/") {
			return nil, errors.New("recovery: at most one passphrase slot and one recovery slot")
		}
	}
	return &kf, nil
}

// recoverySlotID identifies the drive's recovery slot: a hash of its salt
// and wrapped key, which change whenever the slot is rewritten.
func recoverySlotID(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	kf, err := parseKeys(raw)
	if err != nil {
		return nil, err
	}
	for _, s := range kf.Slots {
		if s.Kind == vault.SlotRecovery {
			h := sha256.New()
			for _, f := range [][]byte{s.Sealed, s.Nonce, s.Wrapped} {
				h.Write(f)
			}
			return h.Sum(nil), nil
		}
	}
	return nil, errors.New("recovery: no recovery slot")
}

// AuditNeedles lists every secret A8's scan must not find in plaintext:
// the vault data key (unwrapped from the recovery slot by this package's
// own reading of the file format, so the scan does not trust the vault
// code it audits), every value in the vault (the card's stored values
// among them), and the factors the vault never holds, as typed from the
// card: the recovery key and, when given, the vault passphrase. It is for
// the A8 scan tool and tests only.
func AuditNeedles(b *Box, rk RecoveryKey, passphrase string) ([]Needle, error) {
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
		for name, v := range map[string]string{"Wi-Fi password": c.WiFiPassword, "setup secret": c.SetupSecret} {
			if len(v) >= minPattern {
				out = append(out, Needle{Name: name, Value: []byte(v), Text: true})
			}
		}
		out = append(out, Needle{Name: "grid seed", Value: c.GridSeed})
	}
	out = append(out, Needle{Name: "recovery key text", Value: []byte(rk.Text()), Text: true})
	if len(passphrase) >= minPattern {
		out = append(out, Needle{Name: "vault passphrase", Value: []byte(passphrase), Text: true})
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
	err = errors.New("recovery: no recovery slot")
	for _, s := range kf.Slots {
		if s.Kind != vault.SlotRecovery {
			continue
		}
		aad, merr := json.Marshal(struct {
			Magic   string   `json:"magic"`
			Version int      `json:"version"`
			Kind    string   `json:"kind"`
			KDF     *keysKDF `json:"kdf,omitempty"`
			Sealed  []byte   `json:"sealed,omitempty"`
			KeyID   []byte   `json:"key_id,omitempty"`
		}{kf.Magic, kf.Version, s.Kind, s.KDF, s.Sealed, s.KeyID})
		if merr != nil {
			return nil, merr
		}
		kek := hkdf(rk.b[:], s.Sealed, "agentos-slot-recovery-v1", vault.KeySize)
		aead, gerr := newGCM(kek)
		wipe(kek)
		if gerr != nil {
			return nil, gerr
		}
		var key []byte
		if key, err = aead.Open(nil, s.Nonce, s.Wrapped, aad); err == nil {
			return key, nil
		}
	}
	return nil, err
}
