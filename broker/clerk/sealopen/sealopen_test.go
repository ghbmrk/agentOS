package sealopen_test

// REQ: CLK-1, STO-2

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/inbox/gmailtest"
	"github.com/ghbmrk/agentos/broker/clerk/sealopen"
)

var aad = []byte("agentos/clerk/sealopen-test")

// sealed is a fresh sealer and a synthetic canary sealed under it.
func sealed(t *testing.T) (clerk.Sealer, []byte) {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	s, err := clerk.NewAESSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.Seal([]byte("canary-not-a-secret"), aad)
	if err != nil {
		t.Fatal(err)
	}
	return s, blob
}

func wantWiped(t *testing.T, k *gmailtest.Kept) {
	t.Helper()
	if n, wiped := k.Wiped(); n != 1 || !wiped {
		t.Fatalf("plaintexts kept %d, wiped %v; want 1, wiped", n, wiped)
	}
}

// fn gets the plaintext, and it is wiped once With returns.
func TestWithHandsFnThePlaintextAndWipesItAfter(t *testing.T) {
	s, blob := sealed(t)
	k := &gmailtest.Kept{Sealer: s}
	var got []byte
	if err := sealopen.With(k, blob, aad, func(plain []byte) error {
		got = append([]byte(nil), plain...)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("canary-not-a-secret")) {
		t.Fatalf("fn got %q", got)
	}
	wantWiped(t, k)
}

// fn's error comes back, and the plaintext is wiped all the same.
func TestWithReturnsFnsErrorAndWipes(t *testing.T) {
	s, blob := sealed(t)
	k := &gmailtest.Kept{Sealer: s}
	want := errors.New("fn refused")
	if err := sealopen.With(k, blob, aad, func([]byte) error { return want }); err != want {
		t.Fatalf("With = %v; want fn's error", err)
	}
	wantWiped(t, k)
}

// A sealer that fails after it decrypted hands back the plaintext with its
// error: fn is not called, Open's error comes back unchanged, and the
// plaintext is wiped.
func TestWithWipesThePlaintextAFailedOpenHandsBack(t *testing.T) {
	s, blob := sealed(t)
	k := &gmailtest.Kept{Sealer: s, OpenErr: os.ErrClosed} // any error
	called := false
	if err := sealopen.With(k, blob, aad, func([]byte) error { called = true; return nil }); err != os.ErrClosed || called {
		t.Fatalf("With with a failing open = %v, fn called %v; want Open's error, not called", err, called)
	}
	wantWiped(t, k)
}
