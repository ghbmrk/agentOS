package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
)

// Passkey algorithms. ES256 is a WebAuthn credential bound to its RP ID
// (KEY-4); Ed25519 signs the message itself, for the simulator's fake
// authenticator (EVL-1) and tests.
const (
	AlgEd25519 = "ed25519"
	AlgES256   = "es256"
)

// PublicKey is a passkey's public key, naming its algorithm. It is
// comparable, so == is equality. The zero value is no key and verifies
// nothing.
type PublicKey struct {
	alg  string
	rpID string // ES256: the relying party the credential is bound to
	raw  string // Ed25519: 32 bytes; ES256: the 65-byte uncompressed P-256 point
}

// Ed25519 is the passkey whose signature is a plain Ed25519 one.
func Ed25519(pk ed25519.PublicKey) PublicKey {
	if len(pk) != ed25519.PublicKeySize {
		return PublicKey{}
	}
	return PublicKey{alg: AlgEd25519, raw: string(pk)}
}

// ES256 is the WebAuthn credential with P-256 point (0x04 ‖ X ‖ Y, stored
// at enrolment) on relying party rpID. It refuses a point off the curve.
func ES256(rpID string, point []byte) (PublicKey, error) {
	if rpID == "" || len(rpID) > 253 || strings.ContainsAny(rpID, ": \x00") {
		return PublicKey{}, ErrMalformed
	}
	if _, err := ecdsa.ParseUncompressedPublicKey(ecdsaP256, point); err != nil {
		return PublicKey{}, ErrMalformed
	}
	return PublicKey{alg: AlgES256, rpID: rpID, raw: string(point)}, nil
}

// Valid reports whether pk is a key, not the zero value.
func (pk PublicKey) Valid() bool { return pk.alg != "" }

// Alg is pk's algorithm, AlgEd25519 or AlgES256; "" for no key.
func (pk PublicKey) Alg() string { return pk.alg }

// Bytes is the key's raw form: the Ed25519 key or the P-256 point.
func (pk PublicKey) Bytes() []byte { return []byte(pk.raw) }

// Verify reports whether sig is pk's signature over msg: for Ed25519 the
// signature itself, for ES256 an Assertion's JSON (VerifyAssertion).
func (pk PublicKey) Verify(msg, sig []byte) bool {
	switch pk.alg {
	case AlgEd25519:
		return ed25519.Verify(ed25519.PublicKey(pk.raw), msg, sig)
	case AlgES256:
		// A key's ID hashes its signatures, so a signature has exactly one
		// accepted encoding: AssertionSig's (KEY-7). Any other spelling of
		// the same assertion, or its high-S twin, would be a new ID with
		// no tap, such as a revoked grant come back.
		var a Assertion
		d := json.NewDecoder(bytes.NewReader(sig))
		d.DisallowUnknownFields()
		if d.Decode(&a) != nil {
			return false
		}
		canon, err := AssertionSig(a)
		return err == nil && bytes.Equal(sig, canon) && pk.VerifyAssertion(msg, a)
	}
	return false
}

// String is the key's text form, for display: "ed25519:<hex>" or
// "es256:<rp id>:<hex>".
func (pk PublicKey) String() string {
	switch pk.alg {
	case AlgEd25519:
		return AlgEd25519 + ":" + hex.EncodeToString(pk.Bytes())
	case AlgES256:
		return AlgES256 + ":" + pk.rpID + ":" + hex.EncodeToString(pk.Bytes())
	}
	return ""
}

// Encode is the key as a signed message names it: an Ed25519 key's 32
// bytes, as before ES256 existed, or "es256", its RP ID and its point, each
// ended by a NUL. The lengths differ, so neither reads as the other.
func (pk PublicKey) Encode() []byte {
	if pk.alg == AlgES256 {
		return []byte(AlgES256 + "\x00" + pk.rpID + "\x00" + pk.raw + "\x00")
	}
	return []byte(pk.raw)
}

// es256JSON is an ES256 key's JSON form.
type es256JSON struct {
	Alg   string `json:"alg"`
	RPID  string `json:"rp_id"`
	Point []byte `json:"point"`
}

// MarshalJSON writes an Ed25519 key as its bytes, as an ed25519.PublicKey
// was written, so a root's signed body and the log's entries keep their
// form; an ES256 key as an object naming its RP ID; no key as null.
func (pk PublicKey) MarshalJSON() ([]byte, error) {
	switch pk.alg {
	case AlgEd25519:
		return json.Marshal(pk.Bytes())
	case AlgES256:
		return json.Marshal(es256JSON{AlgES256, pk.rpID, pk.Bytes()})
	}
	return []byte("null"), nil
}

func (pk *PublicKey) UnmarshalJSON(b []byte) error {
	*pk = PublicKey{}
	b = bytes.TrimSpace(b)
	switch {
	case bytes.Equal(b, []byte("null")):
		return nil
	case len(b) > 0 && b[0] == '"':
		var raw []byte
		if err := json.Unmarshal(b, &raw); err != nil || len(raw) != ed25519.PublicKeySize {
			return ErrMalformed
		}
		*pk = Ed25519(raw)
		return nil
	}
	var e es256JSON
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil || e.Alg != AlgES256 {
		return ErrMalformed
	}
	k, err := ES256(e.RPID, e.Point)
	*pk = k
	return err
}

// Assertion is what a WebAuthn get() returns for one tap.
type Assertion struct {
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"` // ASN.1 DER ECDSA
}

// AssertionSig is a's one accepted encoding as a signature: its JSON with
// the ECDSA signature in DER at low S. An authenticator may return either
// S; both verify, so the high one is replaced by n−S here, before the
// signature is attached and can reach an ID.
func AssertionSig(a Assertion) ([]byte, error) {
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(a.Signature, &rs); err != nil || len(rest) != 0 || rs.R.Sign() <= 0 || rs.S.Sign() <= 0 {
		return nil, ErrMalformed
	}
	n := ecdsaP256.Params().N
	if rs.S.Cmp(new(big.Int).Rsh(n, 1)) > 0 {
		rs.S.Sub(n, rs.S)
	}
	der, err := asn1.Marshal(rs)
	if err != nil {
		return nil, ErrMalformed
	}
	a.Signature = der
	return json.Marshal(a)
}

// Authenticator-data flags (WebAuthn §6.1).
const (
	flagUP = 0x01 // user present: a tap
	flagUV = 0x04 // user verified: biometric or PIN
)

// Challenge is the WebAuthn challenge for msg, a domain-separated message
// a passkey signs: its SHA-256 (KEY-4).
func Challenge(msg []byte) [32]byte { return sha256.Sum256(msg) }

// VerifyAssertion reports whether a is pk's assertion over msg: a get()
// ceremony whose challenge is Challenge(msg), on pk's RP ID, with the user
// both present and verified, signed by pk's credential over
// authenticatorData ‖ SHA-256(clientDataJSON), from the page at
// https://<RP ID> itself, not framed by another origin. A browser lets any
// subdomain of the RP ID ask for the tap; the origin check keeps those out.
// The sign count is not checked (synced passkeys report 0) (ASSUMPTIONS
// MIG-2-a). It accepts either S: Verify takes only AssertionSig's form.
func (pk PublicKey) VerifyAssertion(msg []byte, a Assertion) bool {
	if pk.alg != AlgES256 || len(a.AuthenticatorData) < 37 {
		return false
	}
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if json.Unmarshal(a.ClientDataJSON, &cd) != nil || cd.Type != "webauthn.get" ||
		cd.Origin != "https://"+pk.rpID || cd.CrossOrigin {
		return false
	}
	c := Challenge(msg)
	if cd.Challenge != base64.RawURLEncoding.EncodeToString(c[:]) {
		return false
	}
	rp := sha256.Sum256([]byte(pk.rpID))
	ad := a.AuthenticatorData
	if !bytes.Equal(ad[:32], rp[:]) || ad[32]&(flagUP|flagUV) != flagUP|flagUV {
		return false
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(ecdsaP256, pk.Bytes())
	if err != nil {
		return false
	}
	cdh := sha256.Sum256(a.ClientDataJSON)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	return ecdsa.VerifyASN1(pub, h[:], a.Signature)
}

// Signer is a passkey that can sign here. A real passkey signs on the
// owner's device instead: export the message (RootMsg, LinkMsg, EnrollMsg,
// CosignMsg, UseMsg), hand Challenge(msg) to the page, and attach
// AssertionSig of what comes back (AttachRoot, AttachLink, or the
// Enrollment and Cosign fields).
type Signer interface {
	Public() PublicKey
	Sign(msg []byte) []byte
}

// Ed25519Signer is the fake authenticator: an Ed25519 key signing as a
// passkey (EVL-1).
type Ed25519Signer ed25519.PrivateKey

func (s Ed25519Signer) Public() PublicKey {
	return Ed25519(ed25519.PrivateKey(s).Public().(ed25519.PublicKey))
}

func (s Ed25519Signer) Sign(msg []byte) []byte { return ed25519.Sign(ed25519.PrivateKey(s), msg) }

var ecdsaP256 = elliptic.P256()
