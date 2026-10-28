package camwire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
)

// PointLen is an uncompressed P-256 point: 0x04 ‖ X ‖ Y.
const PointLen = 65

// Bounds on an assertion's parts as the wire carries them.
const (
	minAuthData = 37 // RP ID hash (32), flags (1), sign count (4)
	maxAuthData = 1024
	maxClient   = 1024
	maxDER      = 72 // SEQUENCE of two INTEGERs of at most 33 bytes each
)

// Authenticator-data flags (WebAuthn §6.1).
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified: biometric or PIN
	flagAT = 0x40 // attested credential data: a create(), never a get()
	flagED = 0x80 // extension data follows
)

// ErrAssertion is any failed check of an owner assertion. It is one error
// on purpose: which check failed is the forger's information, not the
// node's.
var ErrAssertion = errors.New("camwire: owner assertion does not verify")

// ErrMalformed is an encoding that is not the one canonical form.
var ErrMalformed = errors.New("camwire: encoding malformed or not canonical")

// Owner is the owner's passkey as the node pins it: the relying party it
// is bound to (the enforcer's page) and its P-256 public key.
type Owner struct {
	RPID  string
	Point [PointLen]byte
}

// Assertion is what one WebAuthn get() returns for one tap.
type Assertion struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte // ECDSA in strict DER
}

// Challenge is the WebAuthn challenge the owner's page asks the passkey to
// sign for msg: its SHA-256 (NET-4, "each challenge commits to the
// change"). msg is a whole bundle or manifest, which opens with its own
// magic, so one challenge never serves another kind of message.
func Challenge(msg []byte) [32]byte { return sha256.Sum256(msg) }

// verify reports whether a is o's assertion over msg: a get() ceremony on
// o's relying party, from the page at https://<RP ID> and not framed by
// another origin, with the user both present and verified, whose challenge
// is Challenge(msg), signed in strict DER by o's credential over
// authenticatorData ‖ SHA-256(clientDataJSON). The sign count is not
// checked: synced passkeys report 0 (ASSUMPTIONS CAM-wire-3).
func (o Owner) verify(msg []byte, a Assertion) bool {
	if !validRPID(o.RPID) {
		return false
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), o.Point[:])
	if err != nil {
		return false
	}
	ad := a.AuthenticatorData
	if len(ad) < minAuthData || len(ad) > maxAuthData {
		return false
	}
	rp := sha256.Sum256([]byte(o.RPID))
	flags := ad[32]
	if !bytes.Equal(ad[:32], rp[:]) || flags&(flagUP|flagUV) != flagUP|flagUV || flags&flagAT != 0 {
		return false
	}
	// Bytes past the fixed part are extension data only, and only when the
	// authenticator says so.
	if (flags&flagED == 0) != (len(ad) == minAuthData) {
		return false
	}
	var cd struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if len(a.ClientDataJSON) > maxClient || json.Unmarshal(a.ClientDataJSON, &cd) != nil {
		return false
	}
	c := Challenge(msg)
	if cd.Type != "webauthn.get" || cd.Origin != "https://"+o.RPID || cd.CrossOrigin ||
		cd.Challenge != base64.RawURLEncoding.EncodeToString(c[:]) {
		return false
	}
	if !strictDER(a.Signature) {
		return false
	}
	cdh := sha256.Sum256(a.ClientDataJSON)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	return ecdsa.VerifyASN1(pub, h[:], a.Signature)
}

// strictDER reports whether sig is an ECDSA signature in DER with no
// alternative spelling: SEQUENCE { INTEGER r, INTEGER s }, short-form
// lengths, each integer positive and minimally encoded, nothing after.
// Range against the group order is VerifyASN1's.
func strictDER(sig []byte) bool {
	if len(sig) < 8 || len(sig) > maxDER || sig[0] != 0x30 || int(sig[1]) != len(sig)-2 {
		return false
	}
	rest := sig[2:]
	for i := 0; i < 2; i++ {
		if len(rest) < 3 || rest[0] != 0x02 {
			return false
		}
		n := int(rest[1])
		if n == 0 || n > 33 || len(rest) < 2+n {
			return false
		}
		v := rest[2 : 2+n]
		if v[0]&0x80 != 0 || (n > 1 && v[0] == 0 && v[1]&0x80 == 0) || (n == 1 && v[0] == 0) {
			return false
		}
		rest = rest[2+n:]
	}
	return len(rest) == 0
}

// appendAssertion appends a's wire form: authenticator data and client
// data each with a 2-byte length, the signature with a 1-byte one.
func appendAssertion(dst []byte, a Assertion) ([]byte, error) {
	if len(a.AuthenticatorData) < minAuthData || len(a.AuthenticatorData) > maxAuthData ||
		len(a.ClientDataJSON) == 0 || len(a.ClientDataJSON) > maxClient ||
		!strictDER(a.Signature) {
		return dst, ErrMalformed
	}
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(a.AuthenticatorData)))
	dst = append(dst, a.AuthenticatorData...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(a.ClientDataJSON)))
	dst = append(dst, a.ClientDataJSON...)
	dst = append(dst, byte(len(a.Signature)))
	return append(dst, a.Signature...), nil
}

// parseAssertion decodes appendAssertion's form, which must fill b.
func parseAssertion(b []byte) (Assertion, error) {
	var a Assertion
	var ok bool
	if a.AuthenticatorData, b, ok = take16(b); !ok {
		return Assertion{}, ErrMalformed
	}
	if a.ClientDataJSON, b, ok = take16(b); !ok {
		return Assertion{}, ErrMalformed
	}
	if len(b) < 1 || len(b) != 1+int(b[0]) {
		return Assertion{}, ErrMalformed
	}
	a.Signature = b[1:]
	// The same bounds the encoder holds, so a parsed assertion re-encodes.
	if _, err := appendAssertion(nil, a); err != nil {
		return Assertion{}, err
	}
	return a, nil
}

// take16 splits a 2-byte length and that many bytes off b.
func take16(b []byte) (v, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b) < 2+n {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

// validRPID reports whether s is a relying-party ID the node takes: a
// lower-case host name of letters, digits, dots and hyphens, at most 253
// bytes, so the origin built from it has one spelling.
func validRPID(s string) bool {
	if s == "" || len(s) > 253 || s[0] == '.' || s[len(s)-1] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// validPoint reports whether p is an uncompressed point on P-256.
func validPoint(p [PointLen]byte) bool {
	_, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), p[:])
	return err == nil
}

// Fingerprint is a node's key fingerprint: the SHA-256 of its device key's
// uncompressed P-256 point. It is what the case prints and the bundle
// names.
func Fingerprint(point [PointLen]byte) [32]byte { return sha256.Sum256(point[:]) }
