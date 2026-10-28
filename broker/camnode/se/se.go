// Package se is the camera node's secure element (CAM-node part b,
// #3513; SPEC DEV-3, NET-2 Cameras, KRN-2, A16): the interface the node's
// server holds, and the driver for an Infineon OPTIGA Trust M class part
// on the board's I2C bus (brief question 6).
//
// The element holds the node's device key, generated inside it, and two
// monotonic counters: the settings counter that orders bundles and the
// image counter that orders images (camwire ASSUMPTIONS CAM-wire-4). It
// also holds the pin of the owner credential the first bundle named, so a
// node whose storage is rewritten offline still refuses another owner.
//
// There is no export: the interface has no method that returns private
// key material (TestDeviceKeyNeverExported), and the driver sends no
// command that reads a key slot.
package se

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
)

// PointLen is an uncompressed P-256 point: 0x04 ‖ X ‖ Y.
const PointLen = 65

// Kind names one of the element's two counters.
type Kind uint8

const (
	// Settings orders settings bundles.
	Settings Kind = 1
	// Image orders node images.
	Image Kind = 2
)

// Element is what the node's server holds. Every method is one or a few
// element commands; none returns private key material.
type Element interface {
	// Public is the device key's public point.
	Public() ([PointLen]byte, error)
	// Sign signs a SHA-256 digest with the device key and returns the
	// signature in ASN.1 DER.
	Sign(digest [32]byte) ([]byte, error)
	// Counter reads one monotonic counter.
	Counter(k Kind) (uint64, error)
	// Raise sets counter k to to, which must be above its value; the
	// element can only count up, so no call lowers it.
	Raise(k Kind, to uint64) error
	// OwnerPin is the pinned owner credential's digest (camnode
	// OwnerDigest), and whether one is pinned.
	OwnerPin() ([32]byte, bool, error)
	// SetOwnerPin pins an owner credential. The caller holds the first
	// bundle's button window (CAM-server); the element only stores.
	SetOwnerPin(pin [32]byte) error
	// ClearOwnerPin removes the pin (the button reset). The device key
	// and both counters survive it.
	ClearOwnerPin() error
}

// Errors common to every element.
var (
	// ErrCounter is a Raise that would not raise, or past what the
	// element's counter can hold.
	ErrCounter = errors.New("se: counter can only rise, within the element's range")
	// ErrDigest is a Sign asked for anything but a SHA-256 digest.
	ErrDigest = errors.New("se: element signs SHA-256 digests only")
	// ErrSignature is a signature from the element that does not verify
	// under the device key: a faulted or substituted element.
	ErrSignature = errors.New("se: element signature does not verify")
)

// Signer is the device key as a crypto.Signer, for TLS: it passes a
// SHA-256 digest to the element and refuses anything else.
type Signer struct {
	e   Element
	pub *ecdsa.PublicKey
}

// NewSigner reads the device key's public point once.
func NewSigner(e Element) (*Signer, error) {
	p, err := e.Public()
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), p[:])
	if err != nil {
		return nil, err
	}
	return &Signer{e, pub}, nil
}

// Public is the device key's public key.
func (s *Signer) Public() crypto.PublicKey { return s.pub }

// Sign signs digest, which must be a SHA-256 digest; the element makes
// the signature, and Sign verifies it under the device key before
// releasing it, so a faulted signature never leaves the node. rand is
// unused: the element draws its own nonce.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 || len(digest) != sha256.Size {
		return nil, ErrDigest
	}
	var d [32]byte
	copy(d[:], digest)
	sig, err := s.e.Sign(d)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(s.pub, digest, sig) {
		return nil, ErrSignature
	}
	return sig, nil
}

// Fingerprint is the device key's fingerprint as a bundle names it: the
// SHA-256 of its uncompressed point (camwire.Fingerprint).
func Fingerprint(e Element) ([32]byte, error) {
	p, err := e.Public()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(p[:]), nil
}

// Locked serialises e's calls: the driver speaks one exchange at a time,
// and TLS handshakes sign concurrently with bundle applies.
func Locked(e Element) Element { return &locked{e: e} }

type locked struct {
	mu sync.Mutex
	e  Element
}

func (l *locked) Public() ([PointLen]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.Public()
}

func (l *locked) Sign(d [32]byte) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.Sign(d)
}

func (l *locked) Counter(k Kind) (uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.Counter(k)
}

func (l *locked) Raise(k Kind, to uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.Raise(k, to)
}

func (l *locked) OwnerPin() ([32]byte, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.OwnerPin()
}

func (l *locked) SetOwnerPin(p [32]byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.SetOwnerPin(p)
}

func (l *locked) ClearOwnerPin() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.e.ClearOwnerPin()
}
