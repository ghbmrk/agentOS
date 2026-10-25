package kernel_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: KEY-4, KEY-7

// webauthn is a software WebAuthn passkey on owner.example: it answers a
// get() for Challenge(msg) as a browser and authenticator would.
type webauthn struct{ p *ecdsa.PrivateKey }

func newWebAuthn(t *testing.T) webauthn {
	p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	return webauthn{p}
}

func (w webauthn) Public() key.PublicKey {
	b, _ := w.p.PublicKey.Bytes()
	pk, _ := key.ES256("owner.example", b)
	return pk
}

func (w webauthn) Sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://owner.example"})
	rp := sha256.Sum256([]byte("owner.example"))
	ad := append(rp[:], 0x05, 0, 0, 0, 0) // UP and UV
	cdh := sha256.Sum256(cd)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	s, _ := ecdsa.SignASN1(rand.Reader, w.p, h[:])
	b, _ := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: s})
	return b
}

// highS is sig's assertion with its ECDSA S replaced by n−S: still a valid
// signature, spelt as the authenticator might.
func highS(t *testing.T, sig []byte) []byte {
	var a key.Assertion
	must(t, json.Unmarshal(sig, &a))
	var rs struct{ R, S *big.Int }
	_, err := asn1.Unmarshal(a.Signature, &rs)
	must(t, err)
	rs.S.Sub(elliptic.P256().Params().N, rs.S)
	a.Signature, _ = asn1.Marshal(rs)
	b, _ := json.Marshal(a)
	return b
}

// A revoked ES256 passkey's grant, re-sent with its signature spelt another
// way, is no new grant: the kernel refuses it and a plan under it, so a
// revocation needs no second tap to hold (KEY-7, #3137 review).
func TestARevokedES256GrantReencodedStaysRefused(t *testing.T) {
	r := newRig(t)
	phone := newWebAuthn(t)
	must(t, r.k.Enroll(0, key.Enroll(r.owner.pass, phone.Public())))
	root := key.Issue(phone, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "phone"})
	must(t, r.issue(0, root))
	must(t, r.k.Revoke(1, root.Tip()))
	steps := []kernel.PlanStep{st(key.Trash, "m1")}
	at := 2 + kernel.GrantHold
	for name, sig := range map[string][]byte{
		"leading space": append([]byte(" "), root.Root.Sig...),
		"high S":        highS(t, root.Root.Sig),
	} {
		replay := root
		replay.Root.Sig = sig
		if replay.Tip() == root.Tip() {
			t.Fatalf("%s: not a new ID", name)
		}
		if err := r.issue(2, replay); err == nil {
			t.Errorf("%s: a re-encoded revoked grant was taken", name)
		}
		p := kernel.Plan{ID: "p-" + name, Key: replay, Steps: steps}
		p.Sig = phone.Sign(kernel.PlanMsg(p))
		if code := admits(r, p, at); code == "" {
			t.Errorf("%s: a plan under the re-encoded grant was admitted", name)
		}
	}
	// The control: the same passkey's live grant, and a plan it signs, admit.
	live := key.Issue(phone, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "phone-2"})
	must(t, r.issue(2, live))
	p := kernel.Plan{ID: "p-live", Key: live, Steps: steps}
	p.Sig = phone.Sign(kernel.PlanMsg(p))
	if code := admits(r, p, at); code != "" {
		t.Fatalf("a live ES256 grant's plan: %q", code)
	}
	if _, ok := r.k.State().Granted(root.Tip()); !ok {
		t.Fatal("the original grant must stay on record, revoked")
	}
}
