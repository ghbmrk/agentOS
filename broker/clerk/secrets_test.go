package clerk_test

// REQ: CLK-1, STO-2, STO-3

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
)

func sealer(t *testing.T) clerk.Sealer {
	t.Helper()
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	s, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSecretsSealedAtRestAndRoundTrip(t *testing.T) {
	s := clerk.NewSecrets(sealer(t))
	canary := []byte("canary-secret-0001")
	if err := s.Put("mail", canary); err != nil {
		t.Fatal(err)
	}
	blob, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, canary) {
		t.Fatal("secret is in the stored bytes in the clear")
	}
	s2 := clerk.NewSecrets(s.Sealer())
	if err := s2.UnmarshalBinary(blob); err != nil {
		t.Fatal(err)
	}
	if !s2.Has("mail") || s2.Has("bank") {
		t.Fatal("slot set changed across a round trip")
	}
}

func TestSecretsRefuseSwappedSlotsAndWrongKey(t *testing.T) {
	sl := sealer(t)
	s := clerk.NewSecrets(sl)
	_ = s.Put("a", []byte("canary-a"))
	_ = s.Put("b", []byte("canary-b"))
	blob, _ := s.MarshalBinary()
	swapped := bytes.Replace(blob, []byte(`"a"`), []byte(`"x"`), 1)
	swapped = bytes.Replace(swapped, []byte(`"b"`), []byte(`"a"`), 1)
	swapped = bytes.Replace(swapped, []byte(`"x"`), []byte(`"b"`), 1)
	if err := clerk.NewSecrets(sl).UnmarshalBinary(swapped); err == nil {
		t.Fatal("slots with swapped names must not open")
	}
	if err := clerk.NewSecrets(sealer(t)).UnmarshalBinary(blob); err == nil {
		t.Fatal("a different sealing key must not open the store")
	}
}

func TestSecretsRejectEmptyAndBadKey(t *testing.T) {
	if _, err := clerk.NewAESSealer(make([]byte, 5)); err == nil {
		t.Fatal("short sealing key accepted")
	}
	if err := clerk.NewSecrets(sealer(t)).Put("", []byte("x")); err == nil {
		t.Fatal("empty slot name accepted")
	}
}
