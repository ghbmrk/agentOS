package enfpair

// REQ: STO-3

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/pairseal"
)

var canary = []byte("SYNTHETIC-PAIRING-SECRET-CANARY-42")

// TestCoreKeepsNoCopy: after Seal the caller's buffer is erased, nothing
// the helper holds is or contains the secret, and the sealed copy opens
// only with the enforcer's key; once the enforcer reports that fingerprint
// held, the sealed copy is gone too. A wrong fingerprint keeps it.
func TestCoreKeepsNoCopy(t *testing.T) {
	enf, err := pairseal.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	h := New(enf.Recipient())
	secret := bytes.Clone(canary)
	s, err := h.Seal("front-lock", secret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, make([]byte, len(canary))) {
		t.Fatalf("the caller's plaintext was not erased: %q", secret)
	}

	// Everything the helper holds, field by field.
	dump := fmt.Sprintf("%#v %#v", h.to, h.held)
	for _, env := range h.held {
		dump += string(env)
	}
	if strings.Contains(dump, string(canary)) {
		t.Fatal("the helper holds the secret")
	}
	w, ok := h.Waiting("front-lock")
	if !ok || !bytes.Equal(w.Envelope, s.Envelope) {
		t.Fatal("no sealed copy waiting")
	}
	other, _ := pairseal.NewKey()
	if _, err := other.Open("front-lock", w.Envelope); !errors.Is(err, pairseal.ErrOpen) {
		t.Error("the sealed copy opens without the enforcer's key")
	}
	if got, err := enf.Open("front-lock", w.Envelope); err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("the enforcer cannot open it: %v", err)
	}

	if err := h.Held("front-lock", [pairseal.HashLen]byte{1}); !errors.Is(err, ErrNotHeld) {
		t.Errorf("a wrong fingerprint dropped the copy: %v", err)
	}
	if _, ok := h.Waiting("front-lock"); !ok {
		t.Fatal("a wrong fingerprint dropped the copy")
	}
	if err := h.Held("front-lock", pairseal.Hash(s.Envelope)); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.Waiting("front-lock"); ok || len(h.held) != 0 {
		t.Error("the sealed copy outlived the fingerprint read")
	}

	bad := bytes.Clone(canary)
	if _, err := h.Seal("bad id", bad); err == nil || !bytes.Equal(bad, make([]byte, len(canary))) {
		t.Errorf("a refused seal left the plaintext: %v %q", err, bad)
	}
}

// TestLinkCarriesHashAndFragment: the link names the device and the hash
// in its query and carries the envelope only in its fragment.
func TestLinkCarriesHashAndFragment(t *testing.T) {
	enf, _ := pairseal.NewKey()
	s, err := New(enf.Recipient()).Seal("front-lock", bytes.Clone(canary))
	if err != nil {
		t.Fatal(err)
	}
	link, err := s.Link("https://enforcer.home.arpa/p?d=abc")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(link)
	q := u.Query()
	if q.Get("d") != "abc" || q.Get(pairseal.ParamDevice) != "front-lock" || q.Get(pairseal.ParamHash) != s.Hash() {
		t.Errorf("query %v", q)
	}
	env, err := base64.RawURLEncoding.DecodeString(u.Fragment)
	if err != nil || !bytes.Equal(env, s.Envelope) || strings.Contains(u.RawQuery, u.Fragment) {
		t.Errorf("fragment %q", u.Fragment)
	}
	if _, err := s.Link("https://enforcer.home.arpa/p?d=abc#x"); err == nil {
		t.Error("a link with a fragment already was accepted")
	}
}
