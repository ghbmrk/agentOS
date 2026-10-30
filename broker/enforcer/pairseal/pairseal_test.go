package pairseal

// REQ: STO-3, STO-4

import (
	"bytes"
	"errors"
	"testing"
)

var canary = []byte("SYNTHETIC-DEVICE-SECRET-CANARY-7f3a")

// TestSealOpensOnlyForItsEnforcerAndDevice: an envelope opens with the
// enforcer's key for its device only; another enforcer, another device, or
// any changed byte is refused, and the envelope never carries the secret
// in the clear.
func TestSealOpensOnlyForItsEnforcerAndDevice(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := Seal(k.Recipient(), "front-lock", canary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(env, canary) {
		t.Fatal("the envelope carries the secret in the clear")
	}
	got, err := k.Open("front-lock", env)
	if err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("open: %q %v", got, err)
	}
	if _, err := k.Open("back-lock", env); !errors.Is(err, ErrOpen) {
		t.Errorf("opened for another device: %v", err)
	}
	other, _ := NewKey()
	if _, err := other.Open("front-lock", env); !errors.Is(err, ErrOpen) {
		t.Errorf("another enforcer opened it: %v", err)
	}
	for i := range env {
		bad := bytes.Clone(env)
		bad[i] ^= 1
		if _, err := k.Open("front-lock", bad); !errors.Is(err, ErrOpen) {
			t.Fatalf("byte %d flipped still opens", i)
		}
	}
	for _, n := range []int{0, 1, headerLen, len(env) - 1} {
		if _, err := k.Open("front-lock", env[:n]); !errors.Is(err, ErrOpen) {
			t.Errorf("truncated to %d opens", n)
		}
	}
	if _, err := k.Open("front-lock", append(bytes.Clone(env), 0)); !errors.Is(err, ErrOpen) {
		t.Error("extended envelope opens")
	}
	again, _ := Seal(k.Recipient(), "front-lock", canary)
	if bytes.Equal(again, env) {
		t.Error("two seals of one secret are equal")
	}
}

func TestSealRefusals(t *testing.T) {
	k, _ := NewKey()
	for _, d := range []string{"", "a b", "a/b", "a\"b", "lock‮", string(make([]byte, 254))} {
		if _, err := Seal(k.Recipient(), d, canary); !errors.Is(err, ErrDevice) {
			t.Errorf("device %q: %v", d, err)
		}
	}
	for _, s := range [][]byte{nil, make([]byte, MaxSecret+1)} {
		if _, err := Seal(k.Recipient(), "lock", s); !errors.Is(err, ErrSize) {
			t.Errorf("secret of %d bytes: %v", len(s), err)
		}
	}
	if _, err := Seal(Recipient{}, "lock", canary); !errors.Is(err, ErrRecipient) {
		t.Errorf("zero recipient: %v", err)
	}
}

func TestKeyAndRecipientRoundTrip(t *testing.T) {
	k, _ := NewKey()
	k2, err := KeyFromSeed(k.Seed())
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecipient(k.Recipient().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	env, _ := Seal(r, "lock", canary)
	if got, err := k2.Open("lock", env); err != nil || !bytes.Equal(got, canary) {
		t.Fatalf("rebuilt key: %q %v", got, err)
	}
	if !bytes.Equal(k.Recipient().Bytes(), k2.Recipient().Bytes()) {
		t.Error("recipient changed through the seed")
	}
	if _, err := ParseRecipient(make([]byte, RecipientLen-1)); !errors.Is(err, ErrRecipient) {
		t.Error("short recipient parsed")
	}
	if _, err := KeyFromSeed(make([]byte, SeedLen+1)); !errors.Is(err, ErrRecipient) {
		t.Error("long seed accepted")
	}
}
