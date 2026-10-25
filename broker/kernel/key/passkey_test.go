package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"testing"
)

// REQ: KEY-4

// authenticator is a software WebAuthn authenticator and browser: it answers
// a get() for its RP ID with an assertion in the wire layout (WebAuthn §6.1,
// §5.8.1), so the verifier is tested on the bytes a real passkey returns.
type authenticator struct {
	t     *testing.T
	priv  *ecdsa.PrivateKey
	rpID  string
	flags byte
	// edit changes the client data or authenticator data before signing.
	edit func(cd map[string]any, ad []byte) []byte
}

func newAuthenticator(t *testing.T, rpID string) *authenticator {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &authenticator{t: t, priv: p, rpID: rpID, flags: flagUP | flagUV}
}

func (a *authenticator) Public() PublicKey {
	point, err := a.priv.PublicKey.Bytes()
	if err != nil {
		a.t.Fatal(err)
	}
	pk, err := ES256(a.rpID, point)
	if err != nil {
		a.t.Fatal(err)
	}
	return pk
}

func (a *authenticator) Sign(msg []byte) []byte {
	c := Challenge(msg)
	cd := map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://" + a.rpID, "crossOrigin": false}
	rp := sha256.Sum256([]byte(a.rpID))
	ad := append(rp[:], a.flags, 0, 0, 0, 0) // sign count 0, as a synced passkey reports
	if a.edit != nil {
		ad = a.edit(cd, ad)
	}
	cdj, _ := json.Marshal(cd)
	cdh := sha256.Sum256(cdj)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, h[:])
	if err != nil {
		a.t.Fatal(err)
	}
	b, err := AssertionSig(Assertion{AuthenticatorData: ad, ClientDataJSON: cdj, Signature: sig})
	if err != nil {
		a.t.Fatal(err)
	}
	return b
}

// An ES256 assertion verifies only with the challenge, RP ID, UP and UV and
// signature all right (KEY-4, #2858 item 3).
func TestAWebAuthnAssertionVerifiesOnlyWhenEveryPartIsRight(t *testing.T) {
	msg := append([]byte(DomainCosign), make([]byte, 32)...)
	a := newAuthenticator(t, "owner.example")
	pk := a.Public()
	if !pk.Verify(msg, a.Sign(msg)) {
		t.Fatal("a well-formed assertion must verify")
	}
	cases := map[string]func(cd map[string]any, ad []byte) []byte{
		"wrong challenge": func(cd map[string]any, ad []byte) []byte {
			c := Challenge([]byte("another change"))
			cd["challenge"] = base64.RawURLEncoding.EncodeToString(c[:])
			return ad
		},
		"wrong RP ID hash": func(_ map[string]any, ad []byte) []byte {
			rp := sha256.Sum256([]byte("evil.example"))
			return append(rp[:], ad[32:]...)
		},
		"UV clear":     func(_ map[string]any, ad []byte) []byte { ad[32] &^= flagUV; return ad },
		"UP clear":     func(_ map[string]any, ad []byte) []byte { ad[32] &^= flagUP; return ad },
		"wrong type":   func(cd map[string]any, ad []byte) []byte { cd["type"] = "webauthn.create"; return ad },
		"subdomain":    func(cd map[string]any, ad []byte) []byte { cd["origin"] = "https://evil.owner.example"; return ad },
		"plain http":   func(cd map[string]any, ad []byte) []byte { cd["origin"] = "http://owner.example"; return ad },
		"cross origin": func(cd map[string]any, ad []byte) []byte { cd["crossOrigin"] = true; return ad },
		"short data":   func(_ map[string]any, ad []byte) []byte { return ad[:36] },
		"padded chall": func(cd map[string]any, ad []byte) []byte { cd["challenge"] = cd["challenge"].(string) + "="; return ad },
	}
	for name, edit := range cases {
		a.edit = edit
		if pk.Verify(msg, a.Sign(msg)) {
			t.Errorf("%s: verified", name)
		}
	}
	a.edit = nil
	var as Assertion
	if err := json.Unmarshal(a.Sign(msg), &as); err != nil {
		t.Fatal(err)
	}
	as.Signature[len(as.Signature)/2] ^= 1
	if pk.VerifyAssertion(msg, as) {
		t.Error("a flipped signature byte: verified")
	}
	if other := newAuthenticator(t, "owner.example"); other.Public().Verify(msg, a.Sign(msg)) {
		t.Error("another credential's assertion: verified")
	}
	if !pk.Verify(msg, a.Sign(msg)) || pk.Verify(append(msg, 0), a.Sign(msg)) {
		t.Error("an assertion binds its message")
	}
}

// A passkey's text form round-trips and names its algorithm and RP ID; a
// point off the curve, an Ed25519 signature for an ES256 key and the zero
// key are refused.
func TestAPublicKeyNamesItsAlgorithm(t *testing.T) {
	a := newAuthenticator(t, "owner.example")
	o := gen(1)
	for _, pk := range []PublicKey{a.Public(), o.pk} {
		b, err := json.Marshal(pk)
		if err != nil {
			t.Fatal(err)
		}
		var back PublicKey
		if err := json.Unmarshal(b, &back); err != nil || back != pk {
			t.Fatalf("%s: round trip %v %v", b, back, err)
		}
	}
	if a.Public().Alg() != AlgES256 || o.pk.Alg() != AlgEd25519 {
		t.Fatal("algorithms")
	}
	bad := a.Public().Bytes()
	bad[64] ^= 1
	if _, err := ES256("owner.example", bad); err == nil {
		t.Fatal("a point off the curve must be refused")
	}
	if _, err := ES256("owner.example:443", a.Public().Bytes()); err == nil {
		t.Fatal("an RP ID with a colon must be refused")
	}
	point, _ := json.Marshal(a.Public().Bytes())
	for _, s := range []string{`"AAAA"`, `5`, `{"alg":"rsa"}`, `{"alg":"es256","rp_id":"x","point":"AAAA"}`,
		`{"alg":"es256","rp_id":"x","point":` + string(point) + `,"more":1}`, `{"alg":"es256","rp_id":"","point":` + string(point) + `}`} {
		var pk PublicKey
		if err := json.Unmarshal([]byte(s), &pk); err == nil {
			t.Errorf("%s: parsed as %v", s, pk)
		}
	}
	msg := []byte("m")
	if a.Public().Verify(msg, o.pass.Sign(msg)) || (PublicKey{}).Verify(msg, nil) || In([]PublicKey{{}}, PublicKey{}) {
		t.Fatal("an Ed25519 signature for an ES256 key, or the zero key, must verify nothing")
	}
	if p, _ := ES256("other.example", a.Public().Bytes()); p == a.Public() {
		t.Fatal("one point on two RP IDs is two keys")
	}
}

// A root, a first link, an enrolment and a cosign each go out as a message
// and come back as a passkey's assertion attached, and verify (KEY-4).
func TestAPasskeySignsByPrepareAndAttach(t *testing.T) {
	hw, phone := newAuthenticator(t, "owner.example"), newAuthenticator(t, "owner.example")
	clerk := gen(2)

	// Enrolment: the hardware key enrolls the phone.
	e := Enrollment{Passkey: phone.Public(), By: hw.Public()}
	e.Sig = hw.Sign(EnrollMsg(e.Passkey))
	owners := Passkeys([]PublicKey{hw.Public()}, []Enrollment{e}, nil)
	if !In(owners, phone.Public()) {
		t.Fatal("an attached enrolment must enroll the phone")
	}
	moved, _ := ES256("other.example", phone.Public().Bytes())
	if In(Passkeys([]PublicKey{hw.Public()}, []Enrollment{{Passkey: moved, By: hw.Public(), Sig: e.Sig}}, nil), moved) {
		t.Fatal("an enrolment binds the RP ID it was signed for")
	}

	// Root: the phone issues it.
	r := PrepareRoot(phone.Public(), Root{Clerk: "mail", Verbs: []Verb{Trash, Organize}, Serial: "pk"})
	root := AttachRoot(r, phone.Sign(RootMsg(r)))
	if _, err := Chain(root, owners); err != nil {
		t.Fatalf("an attached root: %v", err)
	}
	if !SignedBy(root, phone.Public()) || SignedBy(root, hw.Public()) {
		t.Fatal("SignedBy a root")
	}

	// First link: the hardware key grants the clerk.
	l := Link{Caveats: []Caveat{LimitExpires(ClerkLife), LimitSpendDay(100)}, Holder: clerk.pub}
	k, err := AttachLink(root, l, hw.Sign(LinkMsg(root, l)))
	if err != nil {
		t.Fatal(err)
	}
	use := []byte("plan")
	if _, err := Verify(k, owners, use, Sign(k, clerk.priv, use)); err != nil {
		t.Fatalf("an attached first link: %v", err)
	}
	if !SignedBy(k, hw.Public()) || SignedBy(k, phone.Public()) {
		t.Fatal("SignedBy a first link")
	}
	if _, err := AttachLink(root, Link{Holder: clerk.pub}, nil); err == nil {
		t.Fatal("attach must refuse a first link with no expiry or day cap")
	}

	// A narrowing the phone approves for the clerk.
	n, err := Narrow(k, phone, LimitVerbs(Trash))
	if err != nil {
		t.Fatal(err)
	}
	if v, err := Verify(n, owners, use, Sign(n, clerk.priv, use)); err != nil || !v.ByOwner || v.Narrowers[0] != phone.Public() {
		t.Fatalf("a passkey narrowing: %v %+v", err, v)
	}

	// A bare root's use, signed by a passkey.
	if _, err := Verify(root, owners, use, phone.Sign(UseMsg(root, use))); err != nil {
		t.Fatalf("a passkey's use of a bare root: %v", err)
	}
	if UseSigner(root, owners, use, hw.Sign(UseMsg(root, use))) != hw.Public() {
		t.Fatal("UseSigner")
	}

	// Cosign: two passkeys, one an anchor, approve a change.
	what := sha256.Sum256([]byte("a big grant"))
	cos := []Cosign{{By: hw.Public(), Sig: hw.Sign(CosignMsg(what))}, {By: phone.Public(), Sig: phone.Sign(CosignMsg(what))}}
	if !Approved(owners, []PublicKey{hw.Public()}, what, nil, cos) {
		t.Fatal("two attached cosigns must approve")
	}
	if Approved(owners, []PublicKey{hw.Public()}, sha256.Sum256([]byte("another")), nil, cos) {
		t.Fatal("a cosign binds its change")
	}
	hw.flags = flagUP // a tap with no user verification
	if (Cosign{By: hw.Public(), Sig: hw.Sign(CosignMsg(what))}).Over(what) {
		t.Fatal("a cosign without UV must not count")
	}
}

// A signature has one accepted encoding, so one tap is one key ID: the same
// assertion spelt another way, or with its high-S twin, verifies nothing,
// and AssertionSig turns an authenticator's high S into the accepted form
// (KEY-7, #3137 review).
func TestAnES256SignatureHasOneEncoding(t *testing.T) {
	msg := append([]byte(DomainRoot), "r"...)
	a := newAuthenticator(t, "owner.example")
	pk := a.Public()
	sig := a.Sign(msg)
	var as Assertion
	if err := json.Unmarshal(sig, &as); err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(as.Signature, &rs); err != nil {
		t.Fatal(err)
	}
	high := as
	high.Signature, _ = asn1.Marshal(struct{ R, S *big.Int }{rs.R, new(big.Int).Sub(ecdsaP256.Params().N, rs.S)})
	if !pk.VerifyAssertion(msg, high) {
		t.Fatal("the high-S twin is a valid ECDSA signature")
	}
	highJSON, _ := json.Marshal(high)
	reordered := fmt.Sprintf(`{"signature":%q,"client_data_json":%q,"authenticator_data":%q}`,
		base64.StdEncoding.EncodeToString(as.Signature), base64.StdEncoding.EncodeToString(as.ClientDataJSON),
		base64.StdEncoding.EncodeToString(as.AuthenticatorData))
	extra := append(append([]byte{}, sig[:len(sig)-1]...), `,"x":1}`...)
	for name, v := range map[string][]byte{
		"leading space": append([]byte(" "), sig...), "trailing newline": append(append([]byte{}, sig...), '\n'),
		"high S": highJSON, "fields reordered": []byte(reordered), "unknown field": extra,
		"key case": bytes.Replace(sig, []byte(`"signature"`), []byte(`"Signature"`), 1),
	} {
		if bytes.Equal(v, sig) {
			t.Fatalf("%s: not a variant", name)
		}
		if pk.Verify(msg, v) {
			t.Errorf("%s: verified", name)
		}
	}
	canon, err := AssertionSig(high)
	if err != nil || !bytes.Equal(canon, sig) || !pk.Verify(msg, canon) {
		t.Fatalf("AssertionSig must turn the high S into the one accepted form: %v", err)
	}
	if _, err := AssertionSig(Assertion{Signature: []byte{0x30, 0}}); err == nil {
		t.Fatal("a signature that is no DER pair must be refused")
	}
	// The key IDs a tap makes: one root, one ID.
	k := AttachRoot(PrepareRoot(pk, Root{Clerk: "mail", Verbs: []Verb{Trash}, Serial: "s"}), nil)
	k = AttachRoot(k.Root, a.Sign(RootMsg(k.Root)))
	if _, err := Chain(k, []PublicKey{pk}); err != nil {
		t.Fatal(err)
	}
	k2 := k
	k2.Root.Sig = append([]byte(" "), k.Root.Sig...)
	if _, err := Chain(k2, []PublicKey{pk}); !errors.Is(err, ErrBadSig) {
		t.Fatalf("a root re-encoded under a new ID: %v", err)
	}
}

// KEY-4, #3138: DecodePublicKey is Encode's exact inverse, so the unlock
// step's hand-off carries a hardware key as it was enrolled. A P-256 point
// can hold NULs, so a decoder that split on NUL would misread one.
func TestDecodeInvertsEncode(t *testing.T) {
	var es PublicKey
	for i := 0; i < 1000 && !es.Valid(); i++ {
		if pk := newAuthenticator(t, "box.example").Public(); bytes.IndexByte(pk.Bytes()[1:], 0) >= 0 {
			es = pk
		}
	}
	if !es.Valid() {
		t.Fatal("no point with a NUL in it")
	}
	ed := Ed25519(bytes.Repeat([]byte{7}, 32))
	for _, pk := range []PublicKey{ed, es} {
		if got, err := DecodePublicKey(pk.Encode()); err != nil || got != pk {
			t.Errorf("%v: decoded %v %v", pk, got, err)
		}
	}
	enc := es.Encode()
	sep := len(enc) - 65 - 2
	edit := func(f func([]byte) []byte) []byte { return f(bytes.Clone(enc)) }
	off := bytes.Clone(enc)
	off[sep+2] ^= 1 // X changed: the point is off the curve
	colon := []byte("es256\x00box:example\x00" + string(es.Bytes()) + "\x00")
	for name, b := range map[string][]byte{
		"empty": nil, "31 bytes": make([]byte, 31), "33 bytes": make([]byte, 33),
		"no final NUL":      enc[:len(enc)-1],
		"final not NUL":     edit(func(b []byte) []byte { b[len(b)-1] = 'x'; return b }),
		"separator not NUL": edit(func(b []byte) []byte { b[sep] = 'X'; return b }),
		"bad prefix":        edit(func(b []byte) []byte { b[0] = 'E'; return b }),
		"no rp id":          []byte("es256\x00\x00" + string(es.Bytes()) + "\x00"),
		"off the curve":     off,
		"rp id with colon":  colon,
	} {
		if _, err := DecodePublicKey(b); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v, want ErrMalformed", name, err)
		}
	}
}
