// Package camwiretest is a synthetic owner passkey for tests of the
// packages that link camwire (CAM-server, CAM-clerk): a P-256 key generated
// per run that answers a WebAuthn get() the way a platform passkey does.
// It holds no real credential and is imported by tests only.
package camwiretest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// RP is the synthetic enforcer page's relying-party ID.
const RP = "enforcer.home.arpa"

// Passkey is a fake authenticator on RP.
type Passkey struct{ priv *ecdsa.PrivateKey }

// NewPasskey generates a fresh synthetic passkey.
func NewPasskey(t testing.TB) Passkey {
	t.Helper()
	return Passkey{NewKey(t)}
}

// Owner is the passkey as a node pins it.
func (p Passkey) Owner() camwire.Owner { return camwire.Owner{RPID: RP, Point: Point(&p.priv.PublicKey)} }

// Assert is the passkey's honest assertion over msg: user present and
// verified, challenge camwire.Challenge(msg), origin https://RP.
func (p Passkey) Assert(t testing.TB, msg []byte) camwire.Assertion {
	t.Helper()
	rp := sha256.Sum256([]byte(RP))
	ad := append(rp[:], 0x01|0x04, 0, 0, 0, 0)
	ch := camwire.Challenge(msg)
	cd, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(ch[:]),
		"origin":      "https://" + RP,
		"crossOrigin": false,
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
	return camwire.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

// SignBundle encodes b with the passkey's assertion over it.
func (p Passkey) SignBundle(t testing.TB, b camwire.Bundle) []byte {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := camwire.SignedBundle{Bundle: enc, Assertion: p.Assert(t, enc)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// NewKey generates a synthetic P-256 key.
func NewKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Point is k's uncompressed encoding.
func Point(k *ecdsa.PublicKey) [camwire.PointLen]byte {
	b, err := k.Bytes()
	if err != nil {
		panic(err)
	}
	var out [camwire.PointLen]byte
	copy(out[:], b)
	return out
}
