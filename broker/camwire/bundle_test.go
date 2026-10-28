package camwire

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// REQ: NET-4, DEV-3

// TestBundleVerifies: an honest bundle verifies against the pinned owner,
// and each bent part of the ceremony or the bytes is refused. Revert
// mutant: dropping any one check in Owner.verify passes its row.
func TestBundleVerifies(t *testing.T) {
	f := newFixture(t)
	good := f.signed(t, f.bundle, nil)
	b, err := VerifyBundle(good, f.pin(3))
	if err != nil {
		t.Fatalf("honest bundle: %v", err)
	}
	if b != f.bundle {
		t.Fatalf("verified bundle differs from the one signed")
	}

	other := f.bundle
	other.Counter++
	otherEnc, _ := other.Encode()
	wrongKey := newPasskey(t)

	cases := map[string]func() []byte{
		"flipped bundle byte": func() []byte {
			p := bytes.Clone(good)
			p[len(bundleMagic)+32+8+1+len(testRP)+PointLen+3] ^= 1 // inside the core key
			return p
		},
		"flipped settings byte": func() []byte {
			p := bytes.Clone(good)
			p[bundleFixed+len(testRP)-6] ^= 1 // the bitrate
			return p
		},
		"wrong relying-party hash": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.rpHash = sha256.Sum256([]byte("evil.example")) })
		},
		"user verification unset": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.flags = flagUP })
		},
		"user presence unset": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.flags = flagUV })
		},
		"attested data flag on a get": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.flags |= flagAT })
		},
		"extension flag without extension bytes": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.flags |= flagED })
		},
		"wrong origin": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.origin = "https://sub." + testRP })
		},
		"cross-origin frame": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.cross = true })
		},
		"create, not get": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.typ = "webauthn.create" })
		},
		"challenge for another bundle": func() []byte {
			return f.signed(t, f.bundle, func(c *ceremony) { c.challenge = otherEnc })
		},
		"wrong key": func() []byte {
			enc, _ := f.bundle.Encode()
			out, err := SignedBundle{enc, wrongKey.assert(t, enc)}.Encode()
			if err != nil {
				t.Fatal(err)
			}
			return out
		},
		"BER long-form length": func() []byte { return withSig(t, good, berLong) },
		"padded integer":       func() []byte { return withSig(t, good, padR) },
		"trailing byte":        func() []byte { return append(bytes.Clone(good), 0) },
	}
	for name, mk := range cases {
		if _, err := VerifyBundle(mk(), f.pin(3)); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}

// withSig rewrites the signature of signed bundle p with bend.
func withSig(t *testing.T, p []byte, bend func([]byte) []byte) []byte {
	t.Helper()
	s, _, err := ParseSignedBundle(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := bend(bytes.Clone(s.Assertion.Signature))
	// Built by hand: the encoder refuses a non-DER signature.
	out := bytes.Clone(s.Bundle)
	out = append(out, byte(len(s.Assertion.AuthenticatorData)>>8), byte(len(s.Assertion.AuthenticatorData)))
	out = append(out, s.Assertion.AuthenticatorData...)
	out = append(out, byte(len(s.Assertion.ClientDataJSON)>>8), byte(len(s.Assertion.ClientDataJSON)))
	out = append(out, s.Assertion.ClientDataJSON...)
	out = append(out, byte(len(sig)))
	return append(out, sig...)
}

func berLong(sig []byte) []byte { return append([]byte{0x30, 0x81, sig[1]}, sig[2:]...) }

func padR(sig []byte) []byte {
	rl := int(sig[3])
	out := []byte{0x30, sig[1] + 1, 0x02, byte(rl + 1), 0}
	return append(out, sig[4:]...)
}

func TestStrictDER(t *testing.T) {
	p := newPasskey(t)
	sig := p.assert(t, []byte("m")).Signature
	if !strictDER(sig) {
		t.Fatal("a signature from SignASN1 is not strict DER")
	}
	for name, s := range map[string][]byte{
		"long form":  berLong(sig),
		"padded r":   padR(sig),
		"raw r‖s":    make([]byte, 64),
		"zero r":     {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
		"negative r": {0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01},
		"trailing":   append(bytes.Clone(sig), 0),
		"empty":      nil,
	} {
		if strictDER(s) {
			t.Errorf("%s: taken as strict DER", name)
		}
	}
}

// TestBundleForAnotherNodeRefused: a bundle honestly signed for one node
// is refused by every other.
func TestBundleForAnotherNodeRefused(t *testing.T) {
	f := newFixture(t)
	p := f.signed(t, f.bundle, nil)
	pin := f.pin(0)
	pin.Node = Fingerprint(newPoint(t))
	if _, err := VerifyBundle(p, pin); !errors.Is(err, ErrOtherNode) {
		t.Fatalf("bundle for another node: %v", err)
	}
	if _, err := VerifyFirstBundle(p, pin.Node, 0); !errors.Is(err, ErrOtherNode) {
		t.Fatalf("first bundle for another node: %v", err)
	}
}

// TestCounterMustRise: a bundle whose counter equals or is below the
// element's is refused, so a captured bundle cannot be replayed or roll
// settings back.
func TestCounterMustRise(t *testing.T) {
	f := newFixture(t)
	p := f.signed(t, f.bundle, nil)
	for _, c := range []uint64{f.bundle.Counter, f.bundle.Counter + 1, 1 << 63} {
		if _, err := VerifyBundle(p, f.pin(c)); !errors.Is(err, ErrCounter) {
			t.Errorf("element counter %d, bundle %d: %v", c, f.bundle.Counter, err)
		}
	}
	if _, err := VerifyBundle(p, f.pin(f.bundle.Counter-1)); err != nil {
		t.Errorf("counter one above: %v", err)
	}
	if _, err := VerifyFirstBundle(p, f.node, f.bundle.Counter); !errors.Is(err, ErrCounter) {
		t.Errorf("first bundle at the element's counter: %v", err)
	}
}

// TestOwnerPinnedAfterFirst: the first bundle pins the credential it names
// and proves; a later bundle naming another credential is refused even when
// that credential signed it.
func TestOwnerPinnedAfterFirst(t *testing.T) {
	f := newFixture(t)
	first, err := VerifyFirstBundle(f.signed(t, f.bundle, nil), f.node, 0)
	if err != nil {
		t.Fatalf("first bundle: %v", err)
	}
	pin := Pin{Node: f.node, Owner: first.Owner, Counter: first.Counter}

	thief := newPasskey(t)
	g := fixture{owner: thief, node: f.node, bundle: f.bundle}
	g.bundle.Owner = thief.owner()
	g.bundle.Counter = 99
	if _, err := VerifyBundle(g.signed(t, g.bundle, nil), pin); !errors.Is(err, ErrOwner) {
		t.Fatalf("bundle naming another owner: %v", err)
	}
	// A first bundle whose assertion is not by the credential it names.
	h := f
	h.bundle.Owner = thief.owner()
	if _, err := VerifyFirstBundle(h.signed(t, h.bundle, nil), f.node, 0); !errors.Is(err, ErrAssertion) {
		t.Fatalf("first bundle signed by a key it does not name: %v", err)
	}
}

// TestCanonicalEncoding: equal bundles encode equally, a changed field
// changes the bytes, decoding then encoding returns the input, and every
// other spelling is refused.
func TestCanonicalEncoding(t *testing.T) {
	f := newFixture(t)
	a, err := f.bundle.Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := f.bundle.Encode()
	if !bytes.Equal(a, b) {
		t.Fatal("one bundle, two encodings")
	}
	d, err := DecodeBundle(a)
	if err != nil || d != f.bundle {
		t.Fatalf("decode: %v", err)
	}
	if re, _ := d.Encode(); !bytes.Equal(re, a) {
		t.Fatal("decode then encode differs")
	}
	changed := f.bundle
	changed.Settings.FPS++
	if c, _ := changed.Encode(); bytes.Equal(c, a) {
		t.Fatal("a changed field kept the encoding")
	}

	at := func(off int, v byte) []byte {
		p := bytes.Clone(a)
		p[off] = v
		return p
	}
	rp := len(testRP)
	tail := bundleFixed + rp // end of the bundle
	compressed := bytes.Clone(a)
	compressed[len(bundleMagic)+32+8+1+rp] = 0x02
	for name, p := range map[string][]byte{
		"thermal flag 2":     at(tail-2, 2),
		"stream flag 0xff":   at(tail-1, 0xff),
		"IR mode 3":          at(tail-3, 3),
		"zero frame rate":    at(tail-8, 0),
		"upper-case RP ID":   at(len(bundleMagic)+32+8+1, 'E'),
		"compressed point":   compressed,
		"trailing byte":      append(bytes.Clone(a), 0),
		"truncated":          a[:len(a)-1],
		"wrong magic":        at(0, 'X'),
		"RP length too long": at(len(bundleMagic)+32+8, byte(rp+1)),
	} {
		if _, err := DecodeBundle(p); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}

	same := f.bundle
	same.Enforcer = same.Core
	if _, err := same.Encode(); !errors.Is(err, ErrMalformed) {
		t.Errorf("one key for both roles: %v", err)
	}
	zero := f.bundle
	zero.Counter = 0
	if _, err := zero.Encode(); !errors.Is(err, ErrMalformed) {
		t.Errorf("counter 0: %v", err)
	}
}

// TestExtensionDataTaken: bytes after the sign count are taken only as
// extension data the ED flag announces.
func TestExtensionDataTaken(t *testing.T) {
	o := newPasskey(t)
	msg := []byte(bundleMagic + "x")
	if !o.owner().verify(msg, o.assert(t, msg)) {
		t.Fatal("honest assertion")
	}
	if o.owner().verify(append(msg, 0), o.assert(t, msg)) {
		t.Fatal("assertion over another message")
	}
	a := o.assert(t, msg)
	a.Signature = berLong(a.Signature)
	if o.owner().verify(msg, a) {
		t.Fatal("a BER signature verifies when called directly")
	}
	ext := []byte{0xa1, 0x63, 'f', 'o', 'o', 0xf5} // CBOR {"foo": true}
	c := o.ceremony(msg)
	c.flags |= flagED
	c.ext = ext
	if !o.owner().verify(msg, o.sign(t, c)) {
		t.Fatal("extension data announced by ED refused")
	}
	c.flags &^= flagED
	if o.owner().verify(msg, o.sign(t, c)) {
		t.Fatal("trailing bytes without ED taken")
	}
}
