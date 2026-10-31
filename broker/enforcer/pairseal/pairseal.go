// Package pairseal is the sealed hand-off of a safety-list device's secret
// from the core's pairing clerk to the enforcer (SPEC STO-3, STO-4;
// briefs/ENF.md decision 10, slice r). The enforcer holds a pairing key
// pair, X25519 with ML-KEM-768 as D-149 seals backups; the core seals a
// device's secret to its public half, bound to the device's ID, and keeps
// no plaintext. Only the enforcer's private half opens it, and only for
// the device it was sealed for.
//
// Both ends import it: the core's helper (broker/clerk/enfpair) and the
// enforcer's store (broker/enforcer/devsecret). It imports the standard
// library only (broker/daemon/arc2_test.go). Its assumptions are in
// ASSUMPTIONS.md.
package pairseal

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	magic = "AGOSPS1\x00"
	// HashLen is the length of an envelope's hash, which is also the
	// device secret's fingerprint the channel reads (wire.HashLen).
	HashLen = sha256.Size
	// MaxSecret bounds a device secret: above a HomeKit long-term key pair,
	// a Matter operational certificate chain or a keypad code.
	MaxSecret = 4096
	// RecipientLen is an encoded Recipient: the X25519 public key, then
	// the ML-KEM-768 encapsulation key.
	RecipientLen = 32 + mlkem.EncapsulationKeySize768
	// SeedLen is an encoded Key: the X25519 private key, then the
	// ML-KEM-768 seed.
	SeedLen = 32 + mlkem.SeedSize

	// ParamDevice and ParamHash are the add-device proposal link's query
	// parameters naming the device whose sealed secret it carries and the
	// envelope's hash (HashHex); the envelope itself is the link's
	// fragment, base64url without padding, which the page's script posts
	// back with the owner's assertion (decision 10).
	ParamDevice = "sd"
	ParamHash   = "sh"

	headerLen = len(magic) + 32 + mlkem.CiphertextSize768
	tagLen    = 16
)

var (
	ErrDevice    = errors.New("pairseal: not a device ID a secret can be sealed for")
	ErrSize      = errors.New("pairseal: a device secret is 1 to 4096 bytes")
	ErrRecipient = errors.New("pairseal: not an enforcer pairing key")
	ErrOpen      = errors.New("pairseal: the envelope does not open: sealed to another enforcer or another device, or changed")
)

// Recipient is the public half of the enforcer's pairing key: what the core
// seals to. It holds no private byte.
type Recipient struct {
	x  *ecdh.PublicKey
	ek *mlkem.EncapsulationKey768
}

// ParseRecipient reads an encoded Recipient (RecipientLen bytes).
func ParseRecipient(b []byte) (Recipient, error) {
	if len(b) != RecipientLen {
		return Recipient{}, ErrRecipient
	}
	x, err := ecdh.X25519().NewPublicKey(b[:32])
	if err != nil {
		return Recipient{}, ErrRecipient
	}
	ek, err := mlkem.NewEncapsulationKey768(b[32:])
	if err != nil {
		return Recipient{}, ErrRecipient
	}
	return Recipient{x: x, ek: ek}, nil
}

// Bytes is r's encoding.
func (r Recipient) Bytes() []byte { return append(r.x.Bytes(), r.ek.Bytes()...) }

func (r Recipient) valid() bool { return r.x != nil && r.ek != nil }

// Key is the enforcer's pairing key pair. Only the enforcer holds one; it
// keeps its Seed in its sealed state.
type Key struct {
	x  *ecdh.PrivateKey
	dk *mlkem.DecapsulationKey768
}

// NewKey makes a fresh pairing key pair.
func NewKey() (*Key, error) {
	seed := make([]byte, SeedLen)
	defer clear(seed)
	rand.Read(seed)
	return KeyFromSeed(seed)
}

// KeyFromSeed rebuilds a pairing key pair from its Seed.
func KeyFromSeed(seed []byte) (*Key, error) {
	if len(seed) != SeedLen {
		return nil, ErrRecipient
	}
	x, err := ecdh.X25519().NewPrivateKey(seed[:32])
	if err != nil {
		return nil, ErrRecipient
	}
	dk, err := mlkem.NewDecapsulationKey768(seed[32:])
	if err != nil {
		return nil, ErrRecipient
	}
	return &Key{x: x, dk: dk}, nil
}

// Seed is k's private encoding, for the enforcer's sealed state only.
func (k *Key) Seed() []byte { return append(k.x.Bytes(), k.dk.Bytes()...) }

// Recipient is k's public half.
func (k *Key) Recipient() Recipient {
	return Recipient{x: k.x.PublicKey(), ek: k.dk.EncapsulationKey()}
}

// Device reports whether id is a device ID a secret can be sealed for: a
// policy device ID in printable ASCII, so the page shows it as it is and
// the line the owner signs names it exactly (Statement).
func Device(id string) bool {
	if id == "" || len(id) > 253 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; c < 0x21 || c > 0x7e || c == '"' || c == '/' {
			return false
		}
	}
	return true
}

// Seal seals secret to the enforcer to, bound to device. The envelope is
// the ephemeral X25519 key, the ML-KEM ciphertext and the AES-GCM sealed
// secret; its key commits to both shared secrets, both ciphertexts, the
// recipient and the device, so it opens only with to's private half and
// only for device. It does not clear secret: the caller does
// (enfpair.Helper.Seal).
func Seal(to Recipient, device string, secret []byte) ([]byte, error) {
	if !Device(device) {
		return nil, ErrDevice
	}
	if len(secret) == 0 || len(secret) > MaxSecret {
		return nil, ErrSize
	}
	if !to.valid() {
		return nil, ErrRecipient
	}
	return seal(to, device, secret)
}

// seal is Seal without its checks.
func seal(to Recipient, device string, secret []byte) ([]byte, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ssX, err := eph.ECDH(to.x)
	if err != nil {
		return nil, ErrRecipient
	}
	defer clear(ssX)
	ssM, ctM := to.ek.Encapsulate()
	defer clear(ssM)
	head := append(append([]byte(magic), eph.PublicKey().Bytes()...), ctM...)
	aead, err := envelopeAEAD(ssM, ssX, head, to, device)
	if err != nil {
		return nil, err
	}
	return aead.Seal(head, make([]byte, aead.NonceSize()), secret, aad(device)), nil
}

// Open opens env for device with k: the secret, or ErrOpen if env was
// sealed to another enforcer, for another device, or changed.
func (k *Key) Open(device string, env []byte) ([]byte, error) {
	if !Device(device) || len(env) <= headerLen+tagLen || len(env) > headerLen+MaxSecret+tagLen ||
		string(env[:len(magic)]) != magic {
		return nil, ErrOpen
	}
	ephPub, err := ecdh.X25519().NewPublicKey(env[len(magic) : len(magic)+32])
	if err != nil {
		return nil, ErrOpen
	}
	ssX, err := k.x.ECDH(ephPub)
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(ssX)
	ssM, err := k.dk.Decapsulate(env[len(magic)+32 : headerLen])
	if err != nil {
		return nil, ErrOpen
	}
	defer clear(ssM)
	aead, err := envelopeAEAD(ssM, ssX, env[:headerLen], k.Recipient(), device)
	if err != nil {
		return nil, ErrOpen
	}
	out, err := aead.Open(nil, make([]byte, aead.NonceSize()), env[headerLen:], aad(device))
	if err != nil {
		return nil, ErrOpen
	}
	return out, nil
}

// envelopeAEAD is the envelope's AEAD: an X-Wing-style combiner, as backup's, with
// both shared secrets as HKDF input and the header (both ciphertexts), the
// recipient's keys and the device in its info, so a swapped half, another
// recipient or another device changes the key.
func envelopeAEAD(ssM, ssX, head []byte, to Recipient, device string) (cipher.AEAD, error) {
	rHash := sha256.Sum256(to.Bytes())
	info := append([]byte("agentos.enforcer.pairseal.v1\x00"), head...)
	info = append(info, rHash[:]...)
	info = append(info, device...)
	ikm := append(bytes.Clone(ssM), ssX...)
	defer clear(ikm)
	k, err := hkdf.Key(sha256.New, ikm, nil, string(info), 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	// Each envelope has its own key, so the all-zero nonce is used once.
	return cipher.NewGCM(b)
}

func aad(device string) []byte { return append([]byte(magic), device...) }

// Hash is env's SHA-256: what the owner's add-device diff names and what
// the channel's fingerprint read reports once the enforcer holds the
// secret. It reveals nothing of the secret, however short the secret is.
func Hash(env []byte) [HashLen]byte { return sha256.Sum256(env) }

// HashHex is Hash in lowercase hex.
func HashHex(env []byte) string { h := Hash(env); return hex.EncodeToString(h[:]) }

// Statement is the line of the add-device diff that hands device's sealed
// secret, whose envelope hashes to hash (HashHex), to the enforcer. The
// page renders it and the owner's assertion signs it; the enforcer's store
// opens the envelope only for a signed diff that holds this exact line.
func Statement(device, hash string) string {
	return fmt.Sprintf("Hand %s's secret to the enforcer, sealed as %s: only the radio process that drives %s can read it, and agentOS keeps no copy.", device, hash, device)
}

// ShortHash is how many hex characters of an envelope's hash the page
// shows in Statement's line; the line the owner signs keeps all of them.
const ShortHash = 12

// ParseStatement is the device and hash of line if line is Statement's
// line for a device ID and a lowercase hex hash, so the page can show the
// hash short without changing the signed text.
func ParseStatement(line string) (device, hash string, ok bool) {
	rest, ok := strings.CutPrefix(line, "Hand ")
	if !ok {
		return "", "", false
	}
	device, rest, ok = strings.Cut(rest, "'s secret to the enforcer, sealed as ")
	if !ok {
		return "", "", false
	}
	hash, _, _ = strings.Cut(rest, ":")
	b, err := hex.DecodeString(hash)
	if err != nil || len(b) != HashLen || hex.EncodeToString(b) != hash || !Device(device) ||
		Statement(device, hash) != line {
		return "", "", false
	}
	return device, hash, true
}
