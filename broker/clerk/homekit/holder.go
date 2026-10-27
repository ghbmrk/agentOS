package homekit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
)

// NewControllerKey makes the box's controller long-term key (iOSDeviceLTSK)
// and hands its 32-byte seed to put, which seals it into a device slot
// (clerk.Secrets.Put under DeviceSlots, STO-2). The seed is wiped after put
// returns, so it is in memory only for that call (CLK-1).
func NewControllerKey(put func(seed []byte) error) error {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	return put(seed)
}

// SealedKeyHolder is the part b KeyHolder over the sealed store (CLK-1,
// DEV-4, #3325 item 4). It keeps no private key: Open lends the seed from
// the sealed store for one call (clerk.Secrets.DeviceKey), Sign derives the
// key, signs and wipes it, and the holder keeps only the public key and the
// pairing ID derived from it.
type SealedKeyHolder struct {
	open func(fn func(seed []byte) error) error
	pub  ed25519.PublicKey
	id   string
}

// NewSealedKeyHolder opens the seed once to learn the public key.
func NewSealedKeyHolder(open func(fn func(seed []byte) error) error) (*SealedKeyHolder, error) {
	if open == nil {
		return nil, errors.New("homekit: no sealed controller key")
	}
	var pub ed25519.PublicKey
	err := open(func(seed []byte) error {
		if len(seed) != ed25519.SeedSize {
			return errors.New("homekit: controller key seed must be 32 bytes")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		defer clear(priv)
		pub = bytes.Clone(priv[ed25519.SeedSize:])
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &SealedKeyHolder{open: open, pub: pub, id: controllerID(pub)}, nil
}

// controllerID is the controller's pairing ID: a UUID-shaped name taken from
// the public key's hash, so it needs no slot of its own and changes only
// with the key.
func controllerID(pub ed25519.PublicKey) string {
	h := sha512.Sum512(pub)
	return fmt.Sprintf("%X-%X-%X-%X-%X", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

func (k *SealedKeyHolder) PairingID() string { return k.id }

func (k *SealedKeyHolder) PublicKey() ed25519.PublicKey { return bytes.Clone(k.pub) }

// Sign lends the seed for one signature. A seed that no longer matches the
// public key (the slot was replaced) signs nothing.
func (k *SealedKeyHolder) Sign(msg []byte) ([]byte, error) {
	var sig []byte
	err := k.open(func(seed []byte) error {
		if len(seed) != ed25519.SeedSize {
			return errors.New("homekit: controller key seed must be 32 bytes")
		}
		priv := ed25519.NewKeyFromSeed(seed)
		defer clear(priv)
		if !bytes.Equal(priv[ed25519.SeedSize:], k.pub) {
			return errors.New("homekit: sealed controller key changed")
		}
		sig = ed25519.Sign(priv, msg)
		return nil
	})
	return sig, err
}

// Format prints no field, whatever the verb.
func (k *SealedKeyHolder) Format(f fmt.State, _ rune) {
	fmt.Fprint(f, "homekit.SealedKeyHolder{key: sealed}")
}
