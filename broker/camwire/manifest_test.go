package camwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
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
	m := Manifest{Image: sha256.Sum256([]byte("image")), Size: 64 << 20, Version: 12, Counter: 5}
	good := signedManifest(t, m, rel, o)
	got, err := VerifyManifest(good, relPub, o.owner(), 4)
	if err != nil || got != m {
		t.Fatalf("honest manifest: %v", err)
	}

	enc, _ := m.Encode()
	noRelease := bytes.Clone(good)
	clear(noRelease[manifestLen : manifestLen+ed25519.SignatureSize])
	otherRel := signedManifest(t, m, newRelease(t), o)
	otherOwner := signedManifest(t, m, rel, newPasskey(t))
	flipped := bytes.Clone(good)
	flipped[len(manifestMagic)] ^= 1

	for name, c := range map[string]struct {
		p    []byte
		want error
	}{
		"no assertion":           {good[:manifestLen+ed25519.SignatureSize], ErrMalformed},
		"no release signature":   {noRelease, ErrRelease},
		"release by another key": {otherRel, ErrRelease},
		"owner is another key":   {otherOwner, ErrAssertion},
		"manifest alone":         {enc, ErrMalformed},
		"flipped image hash":     {flipped, ErrRelease},
	} {
		if _, err := VerifyManifest(c.p, relPub, o.owner(), 4); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	for _, c := range []uint64{5, 6} {
		if _, err := VerifyManifest(good, relPub, o.owner(), c); !errors.Is(err, ErrCounter) {
			t.Errorf("image counter %d: %v", c, err)
		}
	}
	far := signedManifest(t, Manifest{Image: m.Image, Size: m.Size, Counter: 4 + MaxCounterStep + 1}, rel, o)
	if _, err := VerifyManifest(far, relPub, o.owner(), 4); !errors.Is(err, ErrCounter) {
		t.Errorf("image counter jump past MaxCounterStep: %v", err)
	}
	// A bundle's assertion never serves a manifest: the magics differ.
	if bytes.HasPrefix(enc, []byte(bundleMagic)) {
		t.Fatal("manifest opens with the bundle magic")
	}
	if _, err := VerifyManifest(good, nil, o.owner(), 4); !errors.Is(err, ErrRelease) {
		t.Errorf("no release key pinned: %v", err)
	}
}

func TestManifestCanonical(t *testing.T) {
	m := Manifest{Size: 1, Counter: 1}
	enc, err := m.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if d, err := DecodeManifest(enc); err != nil || d != m {
		t.Fatalf("round trip: %v", err)
	}
	for name, mm := range map[string]Manifest{
		"size 0":       {Counter: 1},
		"size too big": {Size: MaxImageSize + 1, Counter: 1},
		"counter 0":    {Size: 1},
	} {
		if _, err := mm.Encode(); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := DecodeManifest(append(enc, 0)); !errors.Is(err, ErrMalformed) {
		t.Error("trailing byte taken")
	}
}
