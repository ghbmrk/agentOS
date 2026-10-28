package camwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"reflect"
	"slices"
	"testing"
)

// REQ: NET-7, NET-4

func signedManifest(t *testing.T, m Manifest, rel ed25519.PrivateKey, o passkey) []byte {
	t.Helper()
	enc, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	s := SignedManifest{Manifest: enc, Assertion: o.assert(t, enc)}
	copy(s.Release[:], ed25519.Sign(rel, enc))
	out, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestManifestVerifies: an image needs both the release signature and the
// owner's assertion over its manifest; either missing or wrong fails, as
// does an old counter. Revert mutant: VerifyManifest skipping either check
// passes its row.
func TestManifestVerifies(t *testing.T) {
	rel := newRelease(t)
	relPub := rel.Public().(ed25519.PublicKey)
	o := newPasskey(t)
	node := Fingerprint(newPoint(t))
	m := Manifest{Image: sha256.Sum256([]byte("image")), Size: 64 << 20, Version: 12, Counter: 5, Nodes: [][32]byte{node}}
	good := signedManifest(t, m, rel, o)
	got, err := VerifyManifest(good, node, relPub, o.owner(), 4)
	if err != nil || !reflect.DeepEqual(got, m) {
		t.Fatalf("honest manifest: %v", err)
	}

	enc, _ := m.Encode()
	noRelease := bytes.Clone(good)
	clear(noRelease[len(enc) : len(enc)+ed25519.SignatureSize])
	otherRel := signedManifest(t, m, newRelease(t), o)
	otherOwner := signedManifest(t, m, rel, newPasskey(t))
	flipped := bytes.Clone(good)
	flipped[len(manifestMagic)] ^= 1

	for name, c := range map[string]struct {
		p    []byte
		want error
	}{
		"no assertion":           {good[:len(enc)+ed25519.SignatureSize], ErrMalformed},
		"no release signature":   {noRelease, ErrRelease},
		"release by another key": {otherRel, ErrRelease},
		"owner is another key":   {otherOwner, ErrAssertion},
		"manifest alone":         {enc, ErrMalformed},
		"flipped image hash":     {flipped, ErrRelease},
	} {
		if _, err := VerifyManifest(c.p, node, relPub, o.owner(), 4); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	for _, c := range []uint64{5, 6} {
		if _, err := VerifyManifest(good, node, relPub, o.owner(), c); !errors.Is(err, ErrCounter) {
			t.Errorf("image counter %d: %v", c, err)
		}
	}
	far := signedManifest(t, Manifest{Image: m.Image, Size: m.Size, Counter: 4 + MaxCounterStep + 1, Nodes: m.Nodes}, rel, o)
	if _, err := VerifyManifest(far, node, relPub, o.owner(), 4); !errors.Is(err, ErrCounter) {
		t.Errorf("image counter jump past MaxCounterStep: %v", err)
	}
	// A bundle's assertion never serves a manifest: the magics differ.
	if bytes.HasPrefix(enc, []byte(bundleMagic)) {
		t.Fatal("manifest opens with the bundle magic")
	}
	if _, err := VerifyManifest(good, node, nil, o.owner(), 4); !errors.Is(err, ErrRelease) {
		t.Errorf("no release key pinned: %v", err)
	}
}

// TestManifestForAnotherNodeRefused: the owner's approval covers only the
// cameras the manifest names (#3565, NET-4). A manifest whose list omits
// the node is refused before any signature is checked, and one that names
// it among others verifies. Revert mutant: VerifyManifest skipping
// Names lets the second camera stage the image.
func TestManifestForAnotherNodeRefused(t *testing.T) {
	rel := newRelease(t)
	relPub := rel.Public().(ed25519.PublicKey)
	o := newPasskey(t)
	a, b, c := ascending(t, 3)
	m := Manifest{Image: sha256.Sum256([]byte("image")), Size: 1 << 20, Counter: 9, Nodes: [][32]byte{a, c}}
	p := signedManifest(t, m, rel, o)
	for _, n := range [][32]byte{a, c} {
		if _, err := VerifyManifest(p, n, relPub, o.owner(), 8); err != nil {
			t.Errorf("a named camera: %v", err)
		}
	}
	if _, err := VerifyManifest(p, b, relPub, o.owner(), 8); !errors.Is(err, ErrOtherNode) {
		t.Errorf("a camera the list omits: got %v, want ErrOtherNode", err)
	}
	// The list is inside what both signatures cover: widening it breaks them.
	wide := Manifest{Image: m.Image, Size: m.Size, Counter: m.Counter, Nodes: [][32]byte{a, b, c}}
	enc, _ := wide.Encode()
	s, _, err := ParseSignedManifest(p)
	if err != nil {
		t.Fatal(err)
	}
	s.Manifest = enc
	forged, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(forged, b, relPub, o.owner(), 8); !errors.Is(err, ErrRelease) {
		t.Errorf("a widened list under the old signatures: %v", err)
	}
}

// ascending returns n distinct fingerprints in ascending order.
func ascending(t *testing.T, n int) (x, y, z [32]byte) {
	t.Helper()
	fs := make([][32]byte, n)
	for i := range fs {
		fs[i] = Fingerprint(newPoint(t))
	}
	slices.SortFunc(fs, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return fs[0], fs[1], fs[2]
}

func TestManifestCanonical(t *testing.T) {
	one := [][32]byte{{1}}
	m := Manifest{Size: 1, Counter: 1, Nodes: one}
	enc, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if d, err := DecodeManifest(enc); err != nil || !reflect.DeepEqual(d, m) {
		t.Fatalf("round trip: %v", err)
	}
	many := make([][32]byte, MaxNodes+1)
	for i := range many {
		many[i][0] = byte(i + 1)
	}
	for name, mm := range map[string]Manifest{
		"size 0":          {Counter: 1, Nodes: one},
		"size too big":    {Size: MaxImageSize + 1, Counter: 1, Nodes: one},
		"counter 0":       {Size: 1, Nodes: one},
		"no node":         {Size: 1, Counter: 1},
		"too many nodes":  {Size: 1, Counter: 1, Nodes: many},
		"duplicate node":  {Size: 1, Counter: 1, Nodes: [][32]byte{{1}, {1}}},
		"nodes unordered": {Size: 1, Counter: 1, Nodes: [][32]byte{{2}, {1}}},
	} {
		if _, err := mm.Encode(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeManifest(append(enc, 0)); !errors.Is(err, ErrMalformed) {
		t.Error("trailing byte taken")
	}
	// A count that overstates the list, and a first-version manifest.
	short := bytes.Clone(enc)
	short[manifestFixed-1] = 2
	old := bytes.Clone(enc)
	copy(old, "AOSCAMM1")
	for name, p := range map[string][]byte{"count past the list": short, "AOSCAMM1": old} {
		if _, err := DecodeManifest(p); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
