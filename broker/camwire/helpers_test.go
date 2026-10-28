package camwire

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The test passkey, node and client keys are generated per run: synthetic,
// never a real credential.

const testRP = "enforcer.home.arpa"

// passkey is a fake authenticator: a P-256 key on testRP that answers a
// get() the way a platform passkey does.
type passkey struct {
	priv *ecdsa.PrivateKey
	rp   string
}

func newPasskey(t testing.TB) passkey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return passkey{k, testRP}
}

func (p passkey) owner() Owner { return Owner{RPID: p.rp, Point: point(p.priv)} }

// ceremony is one get()'s inputs, which the tests bend one at a time.
type ceremony struct {
	rpHash    [32]byte
	flags     byte
	typ       string
	origin    string
	cross     bool
	challenge []byte // the message the page hashes into the challenge
	ext       []byte // extension data after the sign count
}

func (p passkey) ceremony(msg []byte) ceremony {
	return ceremony{
		rpHash:    sha256.Sum256([]byte(p.rp)),
		flags:     flagUP | flagUV,
		typ:       "webauthn.get",
		origin:    "https://" + p.rp,
		challenge: msg,
	}
}

func (p passkey) sign(t testing.TB, c ceremony) Assertion {
	t.Helper()
	ad := append(append([]byte{}, c.rpHash[:]...), c.flags, 0, 0, 0, 0)
	ad = append(ad, c.ext...)
	ch := Challenge(c.challenge)
	cd, err := json.Marshal(map[string]any{
		"type":        c.typ,
		"challenge":   base64.RawURLEncoding.EncodeToString(ch[:]),
		"origin":      c.origin,
		"crossOrigin": c.cross,
	})
	if err != nil {
		t.Fatal(err)
	}
	cdh := sha256.Sum256(cd)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

func (p passkey) assert(t testing.TB, msg []byte) Assertion {
	return p.sign(t, p.ceremony(msg))
}

func point(k *ecdsa.PrivateKey) [PointLen]byte {
	b, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	var out [PointLen]byte
	copy(out[:], b)
	return out
}

func newPoint(t testing.TB) [PointLen]byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return point(k)
}

// fixture is one provisioned node: its fingerprint, its owner and a bundle
// for it.
type fixture struct {
	owner  passkey
	node   [32]byte
	bundle Bundle
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	o := newPasskey(t)
	node := Fingerprint(newPoint(t))
	return fixture{o, node, Bundle{
		Node:     node,
		Counter:  7,
		Owner:    o.owner(),
		Core:     newPoint(t),
		Enforcer: newPoint(t),
		Settings: Settings{Width: 1920, Height: 1080, FPS: 25, BitrateKbps: 4000, IR: IRAuto, Thermal: true, Stream: true},
	}}
}

func (f fixture) pin(counter uint64) Pin {
	return Pin{Node: f.node, Owner: f.owner.owner(), Counter: counter}
}

// signed encodes b with the owner's assertion from ceremony c (nil: an
// honest one over b).
func (f fixture) signed(t testing.TB, b Bundle, bend func(*ceremony)) []byte {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c := f.owner.ceremony(enc)
	if bend != nil {
		bend(&c)
	}
	out, err := SignedBundle{enc, f.owner.sign(t, c)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// release is a synthetic release signer.
func newRelease(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
