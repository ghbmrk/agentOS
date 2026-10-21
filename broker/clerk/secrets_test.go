package clerk_test

// REQ: CLK-1, STO-2, STO-3

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

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
	sl := sealer(t)
	s := clerk.NewSecrets(sl, nil)
	canary := []byte("canary-secret-0001")
	if err := s.Put("mail", clerk.KindStatic, canary); err != nil {
		t.Fatal(err)
	}
	blob, err := s.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, canary) {
		t.Fatal("secret is in the stored bytes in the clear")
	}
	s2 := clerk.NewSecrets(sl, nil)
	if err := s2.UnmarshalBinary(blob); err != nil {
		t.Fatal(err)
	}
	if !s2.Has("mail") || s2.Has("bank") {
		t.Fatal("slot set changed across a round trip")
	}
}

func TestSecretsRefuseSwappedSlotsAndWrongKey(t *testing.T) {
	sl := sealer(t)
	s := clerk.NewSecrets(sl, nil)
	_ = s.Put("a", clerk.KindStatic, []byte("canary-a"))
	_ = s.Put("b", clerk.KindStatic, []byte("canary-b"))
	blob, _ := s.MarshalBinary()
	swapped := bytes.Replace(blob, []byte(`"a"`), []byte(`"x"`), 1)
	swapped = bytes.Replace(swapped, []byte(`"b"`), []byte(`"a"`), 1)
	swapped = bytes.Replace(swapped, []byte(`"x"`), []byte(`"b"`), 1)
	if err := clerk.NewSecrets(sl, nil).UnmarshalBinary(swapped); err == nil {
		t.Fatal("slots with swapped names must not open")
	}
	if err := clerk.NewSecrets(sealer(t), nil).UnmarshalBinary(blob); err == nil {
		t.Fatal("a different sealing key must not open the store")
	}
}

func TestSecretsRejectEmptyAndBadKey(t *testing.T) {
	if _, err := clerk.NewAESSealer(make([]byte, 5)); err == nil {
		t.Fatal("short sealing key accepted")
	}
	if err := clerk.NewSecrets(sealer(t), nil).Put("", clerk.KindStatic, []byte("x")); err == nil {
		t.Fatal("empty slot name accepted")
	}
}

func TestSecretsRefuseARelabelledKind(t *testing.T) {
	sl := sealer(t)
	s := clerk.NewSecrets(sl, nil)
	if err := s.Put("a", clerk.KindGrant, []byte("canary-a")); err != nil {
		t.Fatal(err)
	}
	blob, _ := s.MarshalBinary()
	for _, k := range []string{`"static"`, `"other"`} {
		if err := clerk.NewSecrets(sl, nil).UnmarshalBinary(bytes.Replace(blob, []byte(`"grant"`), []byte(k), 1)); err == nil {
			t.Fatalf("a slot relabelled %s opened", k)
		}
	}
	if err := clerk.NewSecrets(sl, nil).Put("a", "other", []byte("x")); err == nil {
		t.Fatal("a kind off the closed list was accepted")
	}
}

func TestSecretsWriteBeforePutReturns(t *testing.T) {
	sl := sealer(t)
	var disk []byte
	fail := false
	s := clerk.NewSecrets(sl, func(b []byte) error {
		if fail {
			return errors.New("disk full")
		}
		disk = bytes.Clone(b)
		return nil
	})
	if err := s.Put("a", clerk.KindStatic, []byte("canary-1")); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := s.Put("a", clerk.KindStatic, []byte("canary-2")); err == nil {
		t.Fatal("a Put whose write failed reported success")
	}
	mem, _ := s.MarshalBinary()
	if !bytes.Equal(mem, disk) {
		t.Fatal("a failed write left the store ahead of its at-rest form")
	}
	if err := clerk.NewSecrets(sl, nil).UnmarshalBinary(disk); err != nil {
		t.Fatal(err)
	}
}

// Put holds the store's lock across its write, so the at-rest form written
// last is the store's state: concurrent Puts lose nothing.
func TestSecretsConcurrentPutsLoseNothing(t *testing.T) {
	sl := sealer(t)
	var mu sync.Mutex
	var disk []byte
	s := clerk.NewSecrets(sl, func(b []byte) error {
		time.Sleep(time.Millisecond)
		mu.Lock()
		disk = bytes.Clone(b)
		mu.Unlock()
		return nil
	})
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Put(fmt.Sprintf("s%d", i), clerk.KindStatic, []byte("canary")); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	mem, _ := s.MarshalBinary()
	if s.Len() != 16 || !bytes.Equal(mem, disk) {
		t.Fatalf("concurrent Puts left %d slots, at rest equal to memory: %v", s.Len(), bytes.Equal(mem, disk))
	}
}
