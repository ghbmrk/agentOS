package homekit

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// KeyHolder holds the box's controller long-term key (iOSDeviceLTSK,
// Ed25519). Part b builds one over the sealed store (CLK-1, DEV-4); this
// package only asks it for its pairing ID, its public key and signatures,
// and never sees the private key.
type KeyHolder interface {
	PairingID() string
	PublicKey() ed25519.PublicKey
	Sign(msg []byte) ([]byte, error)
}

// MemoryKeyHolder keeps the key in memory, for tests; the clerk uses
// SealedKey. It prints and marshals no field, and the key is captured in a
// signing function, never a field, so even a struct holding the holder by
// value, printed with any verb, shows only a function address (#3325
// item 4).
type MemoryKeyHolder struct {
	id   string
	pub  ed25519.PublicKey
	sign func(msg []byte) []byte
}

// NewMemoryKeyHolder builds a holder from a 32-byte seed.
func NewMemoryKeyHolder(id string, seed []byte) (*MemoryKeyHolder, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("homekit: controller key seed must be 32 bytes")
	}
	if err := checkPairingID(id); err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &MemoryKeyHolder{id: id, pub: priv.Public().(ed25519.PublicKey),
		sign: func(msg []byte) []byte { return ed25519.Sign(priv, msg) }}, nil
}

func (k *MemoryKeyHolder) PairingID() string { return k.id }
func (k *MemoryKeyHolder) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), k.pub...)
}
func (k *MemoryKeyHolder) Sign(msg []byte) ([]byte, error) { return k.sign(msg), nil }

// Format prints no field, whatever the verb.
func (k MemoryKeyHolder) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "homekit.MemoryKeyHolder{key: redacted}")
}

// Pin is what pair-setup pins (DEV-3): the accessory's pairing ID and its
// Ed25519 long-term public key. Every session proves this key first.
type Pin struct {
	AccessoryID string
	LTPK        ed25519.PublicKey
}

// Valid reports whether the pin holds an ID and a full-length key.
func (p Pin) Valid() bool {
	return checkPairingID(p.AccessoryID) == nil && len(p.LTPK) == ed25519.PublicKeySize
}

// checkPairingID bounds a pairing identifier: 1 to 64 printable ASCII bytes
// (an accessory uses "XX:XX:XX:XX:XX:XX", a controller a UUID).
func checkPairingID(id string) error {
	if len(id) == 0 || len(id) > 64 {
		return fmt.Errorf("%w: pairing id length %d", ErrProtocol, len(id))
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x21 || id[i] > 0x7e {
			return fmt.Errorf("%w: pairing id not printable", ErrProtocol)
		}
	}
	return nil
}
