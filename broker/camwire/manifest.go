package camwire

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// manifestMagic opens every manifest, so neither the release signature nor
// the owner's challenge over one serves a bundle.
const manifestMagic = "AOSCAMM1"

// MaxImageSize bounds the image a manifest names.
const MaxImageSize = 1 << 31

// Manifest names one node image: its hash and size, the release number
// shown to the owner, and the counter that orders images.
type Manifest struct {
	Image   [32]byte // SHA-256 of the whole image
	Size    uint64   // bytes; 1 to MaxImageSize
	Version uint64   // the release number, for display
	Counter uint64   // above the node's image counter, or refused
}

// manifestLen is a manifest's encoded length.
const manifestLen = len(manifestMagic) + 32 + 8 + 8 + 8

// ErrRelease is a manifest without a valid release signature.
var ErrRelease = errors.New("camwire: release signature does not verify")

// Encode is m's one canonical encoding: fixed-width big-endian fields in
// declaration order.
func (m Manifest) Encode() ([]byte, error) {
	if m.Size == 0 || m.Size > MaxImageSize || m.Counter == 0 {
		return nil, ErrMalformed
	}
	out := append([]byte(manifestMagic), m.Image[:]...)
	out = binary.BigEndian.AppendUint64(out, m.Size)
	out = binary.BigEndian.AppendUint64(out, m.Version)
	return binary.BigEndian.AppendUint64(out, m.Counter), nil
}

// DecodeManifest decodes Encode's form, which must fill p.
func DecodeManifest(p []byte) (Manifest, error) {
	if len(p) != manifestLen || string(p[:len(manifestMagic)]) != manifestMagic {
		return Manifest{}, ErrMalformed
	}
	r := p[len(manifestMagic):]
	var m Manifest
	copy(m.Image[:], r)
	m.Size = binary.BigEndian.Uint64(r[32:])
	m.Version = binary.BigEndian.Uint64(r[40:])
	m.Counter = binary.BigEndian.Uint64(r[48:])
	if _, err := m.Encode(); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// SignedManifest is a manifest's encoding, the release signer's Ed25519
// signature over it, and the owner's assertion over it. Both are required:
// the release signer vouches for the code, the owner for installing it on
// a safety-list camera (NET-7).
type SignedManifest struct {
	Manifest  []byte
	Release   [ed25519.SignatureSize]byte
	Assertion Assertion
}

// Encode is s's wire form: manifest, release signature, assertion.
func (s SignedManifest) Encode() ([]byte, error) {
	if _, err := DecodeManifest(s.Manifest); err != nil {
		return nil, err
	}
	out := append(append([]byte{}, s.Manifest...), s.Release[:]...)
	out, err := appendAssertion(out, s.Assertion)
	if err != nil || len(out) > MaxSigned {
		return nil, ErrMalformed
	}
	return out, nil
}

// ParseSignedManifest splits Encode's form. It verifies nothing.
func ParseSignedManifest(p []byte) (SignedManifest, Manifest, error) {
	if len(p) > MaxSigned || len(p) < manifestLen+ed25519.SignatureSize {
		return SignedManifest{}, Manifest{}, ErrMalformed
	}
	m, err := DecodeManifest(p[:manifestLen])
	if err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	s := SignedManifest{Manifest: p[:manifestLen]}
	copy(s.Release[:], p[manifestLen:])
	if s.Assertion, err = parseAssertion(p[manifestLen+ed25519.SignatureSize:]); err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	return s, m, nil
}

// VerifyManifest reports the manifest p carries if the node may stage its
// image: the encoding is canonical, release (the key the node's image
// pins) signed it, the pinned owner's assertion over it verifies, and its
// counter is above counter by at most MaxCounterStep, the image counter in the node's secure element.
// The image's bytes are checked against Image after they arrive.
func VerifyManifest(p []byte, release ed25519.PublicKey, owner Owner, counter uint64) (Manifest, error) {
	s, m, err := ParseSignedManifest(p)
	if err != nil {
		return Manifest{}, err
	}
	if !rises(m.Counter, counter) {
		return Manifest{}, ErrCounter
	}
	if len(release) != ed25519.PublicKeySize || !ed25519.Verify(release, s.Manifest, s.Release[:]) {
		return Manifest{}, ErrRelease
	}
	if !owner.verify(s.Manifest, s.Assertion) {
		return Manifest{}, ErrAssertion
	}
	return m, nil
}
