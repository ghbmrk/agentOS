package camwire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

// REQ: NET-2, NET-4, KRN-2

// FuzzFrame: on any input and direction the codec never panics, holds no
// payload over its type's cap, and a frame it returns re-encodes to exactly
// the bytes it consumed. Revert mutant: checkHeader skipping the cap
// returns an over-cap payload.
func FuzzFrame(f *testing.F) {
	f.Add(append(header(TypeVideo, 5), au(5)...))
	f.Add(append(header(TypeStatus, StatusLen), make([]byte, StatusLen)...))
	f.Add(append(header(TypeBundle, 2), 1, 2))
	f.Add(header(TypeVideo, 0xffffffff))
	f.Add([]byte{2, 0, 0, 0x96, 0x08})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, d := range []Direction{ToCore, FromEnforcer, ToEnforcer} {
			r := bytes.NewReader(data)
			fr, err := ReadFrame(r, d, lepton)
			if err != nil {
				continue
			}
			if uint32(len(fr.Payload)) > types[fr.Type].cap {
				t.Fatalf("payload of %d bytes over its cap", len(fr.Payload))
			}
			used := data[:len(data)-r.Len()]
			enc, err := AppendFrame(nil, d, lepton, fr)
			if err != nil || !bytes.Equal(enc, used) {
				t.Fatalf("direction %d: re-encoding differs from the bytes consumed: %v", d, err)
			}
		}
	})
}

// FuzzBundle: a signed bundle that parses re-encodes to its input, and
// verification of any input never panics.
func FuzzBundle(f *testing.F) {
	fx := newFixture(f)
	good := fx.signed(f, fx.bundle, nil)
	f.Add(good)
	f.Add(good[:bundleFixed])
	f.Add([]byte(bundleMagic))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = VerifyBundle(data, fx.pin(0))
		s, _, err := ParseSignedBundle(data)
		if err != nil {
			return
		}
		enc, err := s.Encode()
		if err != nil || !bytes.Equal(enc, data) {
			t.Fatalf("a parsed bundle does not re-encode to its input: %v", err)
		}
	})
}

// FuzzManifest: as FuzzBundle, for the image manifest.
func FuzzManifest(f *testing.F) {
	rel := newRelease(f)
	o := newPasskey(f)
	node := Fingerprint(newPoint(f))
	enc, _ := Manifest{Image: sha256.Sum256(nil), Size: 1, Counter: 1, Nodes: [][32]byte{node}}.Encode()
	s := SignedManifest{Manifest: enc, Assertion: o.assert(f, enc)}
	copy(s.Release[:], ed25519.Sign(rel, enc))
	good, err := s.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add(enc)
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = VerifyManifest(data, node, rel.Public().(ed25519.PublicKey), o.owner(), 0)
		s, _, err := ParseSignedManifest(data)
		if err != nil {
			return
		}
		enc, err := s.Encode()
		if err != nil || !bytes.Equal(enc, data) {
			t.Fatalf("a parsed manifest does not re-encode to its input: %v", err)
		}
	})
}
