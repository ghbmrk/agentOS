package camwire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// manifestMagic opens every manifest, so neither the release signature nor
// the owner's challenge over one serves a bundle.
// AOSCAMM2 added the node list (#3565); an AOSCAMM1 manifest is refused.
const manifestMagic = "AOSCAMM2"

// MaxImageSize bounds the image a manifest names.
const MaxImageSize = 1 << 31

// MaxNodes bounds the cameras one manifest names, so a signed manifest
// fits MaxSigned with the largest assertion.
const MaxNodes = 32

// Manifest names one node image: its hash and size, the release number
// shown to the owner, the counter that orders images, and the cameras the
// owner approved it for (#3565, NET-4: the owner's one tap covers only the
// cameras the owner picked).
type Manifest struct {
	Image   [32]byte   // SHA-256 of the whole image
	Size    uint64     // bytes; 1 to MaxImageSize
	Version uint64     // the release number, for display
	Counter uint64     // above the node's image counter, or refused
	Nodes   [][32]byte // device-key Fingerprints, strictly ascending; 1 to MaxNodes
}

// manifestFixed is a manifest's encoded length without its node list.
const manifestFixed = len(manifestMagic) + 32 + 8 + 8 + 8 + 1

// ErrRelease is a manifest without a valid release signature.
var ErrRelease = errors.New("camwire: release signature does not verify")

// Encode is m's one canonical encoding: fixed-width big-endian fields in
// declaration order, the node list after a 1-byte count. The list must be
// strictly ascending, so a set of cameras has one spelling.
func (m Manifest) Encode() ([]byte, error) {
	if m.Size == 0 || m.Size > MaxImageSize || m.Counter == 0 {
		return nil, ErrMalformed
	}
	if len(m.Nodes) == 0 || len(m.Nodes) > MaxNodes {
		return nil, ErrMalformed
	}
	for i := 1; i < len(m.Nodes); i++ {
		if bytes.Compare(m.Nodes[i-1][:], m.Nodes[i][:]) >= 0 {
			return nil, ErrMalformed
		}
	}
	out := append([]byte(manifestMagic), m.Image[:]...)
	out = binary.BigEndian.AppendUint64(out, m.Size)
	out = binary.BigEndian.AppendUint64(out, m.Version)
	out = binary.BigEndian.AppendUint64(out, m.Counter)
	out = append(out, byte(len(m.Nodes)))
	for _, n := range m.Nodes {
		out = append(out, n[:]...)
	}
	return out, nil
}

// Names reports whether m names the node whose fingerprint is node.
func (m Manifest) Names(node [32]byte) bool {
	for _, n := range m.Nodes {
		if n == node {
			return true
		}
	}
	return false
}

// DecodeManifest decodes Encode's form, which must fill p.
func DecodeManifest(p []byte) (Manifest, error) {
	m, n, err := decodeManifestPrefix(p)
	if err != nil {
		return Manifest{}, err
	}
	if n != len(p) {
		return Manifest{}, ErrMalformed
	}
	return m, nil
}

// decodeManifestPrefix decodes the manifest that opens p and returns its
// length.
func decodeManifestPrefix(p []byte) (Manifest, int, error) {
	if len(p) < manifestFixed || string(p[:len(manifestMagic)]) != manifestMagic {
		return Manifest{}, 0, ErrMalformed
	}
	r := p[len(manifestMagic):]
	var m Manifest
	copy(m.Image[:], r)
	m.Size = binary.BigEndian.Uint64(r[32:])
	m.Version = binary.BigEndian.Uint64(r[40:])
	m.Counter = binary.BigEndian.Uint64(r[48:])
	count := int(r[56])
	r = r[57:]
	if count > MaxNodes || len(r) < 32*count {
		return Manifest{}, 0, ErrMalformed
	}
	m.Nodes = make([][32]byte, count)
	for i := range m.Nodes {
		copy(m.Nodes[i][:], r[32*i:])
	}
	if _, err := m.Encode(); err != nil {
		return Manifest{}, 0, err
	}
	return m, manifestFixed + 32*count, nil
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
	if len(p) > MaxSigned {
		return SignedManifest{}, Manifest{}, ErrMalformed
	}
	m, n, err := decodeManifestPrefix(p)
	if err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	if len(p) < n+ed25519.SignatureSize {
		return SignedManifest{}, Manifest{}, ErrMalformed
	}
	s := SignedManifest{Manifest: p[:n]}
	copy(s.Release[:], p[n:])
	if s.Assertion, err = parseAssertion(p[n+ed25519.SignatureSize:]); err != nil {
		return SignedManifest{}, Manifest{}, err
	}
	return s, m, nil
}

// VerifyManifest reports the manifest p carries if the node whose
// fingerprint is node may stage its image: the encoding is canonical, it
// names node, release (the key the node's image pins) signed it, the pinned
// owner's assertion over it verifies, and its counter is above counter by
// at most MaxCounterStep, the image counter in the node's secure element.
// The image's bytes are checked against Image after they arrive.
func VerifyManifest(p []byte, node [32]byte, release ed25519.PublicKey, owner Owner, counter uint64) (Manifest, error) {
	s, m, err := ParseSignedManifest(p)
	if err != nil {
		return Manifest{}, err
	}
	if !m.Names(node) {
		return Manifest{}, ErrOtherNode
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
