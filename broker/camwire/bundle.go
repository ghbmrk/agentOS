package camwire

import (
	"encoding/binary"
	"errors"
)

// bundleMagic opens every bundle, so a bundle's challenge never equals a
// manifest's.
const bundleMagic = "AOSCAMB1"

// IR modes.
const (
	IROff  = 0
	IROn   = 1
	IRAuto = 2
)

// Settings is the sensor part of a bundle. Each value is checked against
// the node's declared ranges by the node before it reaches a source
// (CAM-server); the encoding only fixes that each field has one spelling.
type Settings struct {
	Width, Height uint16
	FPS           uint8
	BitrateKbps   uint32
	IR            uint8 // IROff, IROn or IRAuto
	Thermal       bool  // the thermal core streams
	Stream        bool  // the stream is on
}

// Bundle is one node's settings as the owner signs them: which node, the
// counter that orders bundles, the owner's credential, the client keys the
// node admits for each role, and the sensor settings.
type Bundle struct {
	Node     [32]byte // Fingerprint of the node's device key
	Counter  uint64   // above the node's settings counter, or refused
	Owner    Owner
	Core     [PointLen]byte // the core's client key: the stream only
	Enforcer [PointLen]byte // the enforcer's client key: the settings channel only
	Settings Settings
}

// Bundle verification errors besides ErrMalformed and ErrAssertion.
var (
	ErrOtherNode = errors.New("camwire: bundle is for another node")
	ErrCounter   = errors.New("camwire: counter does not rise")
	ErrOwner     = errors.New("camwire: bundle names another owner credential")
)

// Encode is b's one canonical encoding: fixed-width big-endian fields in
// declaration order, the RP ID with a 1-byte length. It refuses a bundle
// Decode would refuse.
func (b Bundle) Encode() ([]byte, error) {
	if err := b.check(); err != nil {
		return nil, err
	}
	out := append([]byte(bundleMagic), b.Node[:]...)
	out = binary.BigEndian.AppendUint64(out, b.Counter)
	out = append(out, byte(len(b.Owner.RPID)))
	out = append(out, b.Owner.RPID...)
	out = append(out, b.Owner.Point[:]...)
	out = append(out, b.Core[:]...)
	out = append(out, b.Enforcer[:]...)
	s := b.Settings
	out = binary.BigEndian.AppendUint16(out, s.Width)
	out = binary.BigEndian.AppendUint16(out, s.Height)
	out = append(out, s.FPS)
	out = binary.BigEndian.AppendUint32(out, s.BitrateKbps)
	return append(out, s.IR, boolByte(s.Thermal), boolByte(s.Stream)), nil
}

// bundleFixed is a bundle's length without its RP ID.
const bundleFixed = len(bundleMagic) + 32 + 8 + 1 + 3*PointLen + 2 + 2 + 1 + 4 + 3

// DecodeBundle decodes Encode's form, which must fill p. Any other
// spelling of a bundle is ErrMalformed.
func DecodeBundle(p []byte) (Bundle, error) {
	b, n, err := decodeBundlePrefix(p)
	if err != nil {
		return Bundle{}, err
	}
	if n != len(p) {
		return Bundle{}, ErrMalformed
	}
	return b, nil
}

// decodeBundlePrefix decodes the bundle that opens p and returns its
// length.
func decodeBundlePrefix(p []byte) (Bundle, int, error) {
	if len(p) < bundleFixed || string(p[:len(bundleMagic)]) != bundleMagic {
		return Bundle{}, 0, ErrMalformed
	}
	var b Bundle
	r := p[len(bundleMagic):]
	copy(b.Node[:], r)
	r = r[32:]
	b.Counter = binary.BigEndian.Uint64(r)
	r = r[8:]
	rl := int(r[0])
	r = r[1:]
	if len(p) < bundleFixed+rl {
		return Bundle{}, 0, ErrMalformed
	}
	b.Owner.RPID = string(r[:rl])
	r = r[rl:]
	copy(b.Owner.Point[:], r)
	r = r[PointLen:]
	copy(b.Core[:], r)
	r = r[PointLen:]
	copy(b.Enforcer[:], r)
	r = r[PointLen:]
	b.Settings.Width = binary.BigEndian.Uint16(r)
	b.Settings.Height = binary.BigEndian.Uint16(r[2:])
	b.Settings.FPS = r[4]
	b.Settings.BitrateKbps = binary.BigEndian.Uint32(r[5:])
	b.Settings.IR = r[9]
	var ok1, ok2 bool
	b.Settings.Thermal, ok1 = byteBool(r[10])
	b.Settings.Stream, ok2 = byteBool(r[11])
	if !ok1 || !ok2 {
		return Bundle{}, 0, ErrMalformed
	}
	if err := b.check(); err != nil {
		return Bundle{}, 0, err
	}
	return b, bundleFixed + rl, nil
}

// check holds the rules every encoded bundle meets.
func (b Bundle) check() error {
	s := b.Settings
	switch {
	case b.Counter == 0, !validRPID(b.Owner.RPID):
		return ErrMalformed
	case !validPoint(b.Owner.Point), !validPoint(b.Core), !validPoint(b.Enforcer):
		return ErrMalformed
	case b.Core == b.Enforcer: // one key in two roles would make the roles one
		return ErrMalformed
	case s.Width == 0, s.Height == 0, s.FPS == 0, s.BitrateKbps == 0, s.IR > IRAuto:
		return ErrMalformed
	}
	return nil
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

func byteBool(c byte) (bool, bool) { return c == 1, c <= 1 }

// SignedBundle is a bundle's encoding followed by the owner's assertion
// over it.
type SignedBundle struct {
	Bundle    []byte
	Assertion Assertion
}

// Encode is s's wire form: the bundle, then the assertion. A bundle is
// self-delimiting, so the two need no outer length.
func (s SignedBundle) Encode() ([]byte, error) {
	if _, err := DecodeBundle(s.Bundle); err != nil {
		return nil, err
	}
	out, err := appendAssertion(append([]byte{}, s.Bundle...), s.Assertion)
	if err != nil || len(out) > MaxSigned {
		return nil, ErrMalformed
	}
	return out, nil
}

// ParseSignedBundle splits Encode's form. It decodes the bundle but
// verifies nothing.
func ParseSignedBundle(p []byte) (SignedBundle, Bundle, error) {
	if len(p) > MaxSigned {
		return SignedBundle{}, Bundle{}, ErrMalformed
	}
	b, n, err := decodeBundlePrefix(p)
	if err != nil {
		return SignedBundle{}, Bundle{}, err
	}
	a, err := parseAssertion(p[n:])
	if err != nil {
		return SignedBundle{}, Bundle{}, err
	}
	return SignedBundle{Bundle: p[:n], Assertion: a}, b, nil
}

// Pin is what the node holds when a bundle arrives: its own fingerprint,
// the owner credential it pinned at provisioning, and the settings counter
// in its secure element.
type Pin struct {
	Node    [32]byte
	Owner   Owner
	Counter uint64
}

// VerifyBundle reports the bundle p carries if the node pinned by pin may
// apply it: the encoding is canonical, it names this node and the pinned
// owner credential, its counter is above pin.Counter, and the pinned
// owner's assertion over it verifies. The caller then raises the
// element's counter to the bundle's before applying it.
func VerifyBundle(p []byte, pin Pin) (Bundle, error) {
	s, b, err := ParseSignedBundle(p)
	if err != nil {
		return Bundle{}, err
	}
	if b.Node != pin.Node {
		return Bundle{}, ErrOtherNode
	}
	if b.Owner != pin.Owner {
		return Bundle{}, ErrOwner
	}
	if b.Counter <= pin.Counter {
		return Bundle{}, ErrCounter
	}
	if !pin.Owner.verify(s.Bundle, s.Assertion) {
		return Bundle{}, ErrAssertion
	}
	return b, nil
}

// VerifyFirstBundle is VerifyBundle for a node with no owner yet, taken
// only while the board's button is held (CAM-server): the owner credential
// is the one the bundle itself names, and its assertion proves the owner
// holds it. counter is the element's settings counter, which a reset does
// not lower.
func VerifyFirstBundle(p []byte, node [32]byte, counter uint64) (Bundle, error) {
	_, b, err := ParseSignedBundle(p)
	if err != nil {
		return Bundle{}, err
	}
	return VerifyBundle(p, Pin{Node: node, Owner: b.Owner, Counter: counter})
}
