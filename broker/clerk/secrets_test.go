package clerk_test

// REQ: CLK-1, STO-2, STO-3

import (
	"bytes"
	"context"
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

// Remove persists through the store's write like Put, leaves the store as it
// was when the write fails, and writes nothing for a missing slot.
func TestSecretsRemovePersists(t *testing.T) {
	sl := sealer(t)
	var disk []byte
	writes, fail := 0, false
	s := clerk.NewSecrets(sl, func(b []byte) error {
		if fail {
			return errors.New("disk full")
		}
		writes++
		disk = bytes.Clone(b)
		return nil
	})
	_ = s.Put("a", clerk.KindStatic, []byte("canary-a"))
	_ = s.Put("b", clerk.KindStatic, []byte("canary-b"))
	fail = true
	if err := s.Remove("a"); err == nil || !s.Has("a") {
		t.Fatal("a Remove whose write failed changed the store")
	}
	fail = false
	if err := s.Remove("a"); err != nil {
		t.Fatal(err)
	}
	re := clerk.NewSecrets(sl, nil)
	if err := re.UnmarshalBinary(disk); err != nil || re.Has("a") || !re.Has("b") {
		t.Fatalf("at-rest form after Remove: err %v, a %v, b %v", err, re.Has("a"), re.Has("b"))
	}
	n := writes
	if err := s.Remove("a"); err != nil || writes != n {
		t.Fatal("removing a missing slot wrote or failed")
	}
}

// Login opens its static slot at each call: it gives the password, and after a
// Remove, once the name holds a grant, or for a slot outside MailSlots, it
// gives nothing.
func TestSecretsLoginOpensPerConnection(t *testing.T) {
	s := clerk.NewSecrets(sealer(t), nil)
	cred := s.Login("mail/a", "you@example.com")
	if _, err := cred(context.Background()); err == nil {
		t.Fatal("Login gave a credential for a missing slot")
	}
	_ = s.Put("mail/a", clerk.KindStatic, []byte("canary-pass-0001"))
	l, err := cred(context.Background())
	if err != nil || l.User != "you@example.com" || l.Secret != "canary-pass-0001" {
		t.Fatalf("Login = %+v, %v", l, err)
	}
	_ = s.Remove("mail/a")
	if _, err := cred(context.Background()); err == nil {
		t.Fatal("Login still gave the password after Remove")
	}
	_ = s.Put("mail/a", clerk.KindGrant, []byte("canary-grant-0001"))
	if l, err := cred(context.Background()); err == nil || l.Secret != "" {
		t.Fatal("Login opened a grant slot")
	}
	// Another clerk's static slot is not a mail password: Login is no getter.
	_ = s.Put("exit-key", clerk.KindStatic, []byte("canary-api-key-0001"))
	if l, err := s.Login("exit-key", "x")(context.Background()); err == nil || l.Secret != "" {
		t.Fatal("Login opened a slot outside MailSlots")
	}
}

// DeviceKey opens only a static slot under DeviceSlots, at each call, and
// wipes the key it lent once fn returns.
func TestSecretsDeviceKeyOpensOnlyADeviceSlot(t *testing.T) {
	s := clerk.NewSecrets(sealer(t), nil)
	open := s.DeviceKey("device/scale")
	if err := open(func([]byte) error { return nil }); err == nil {
		t.Fatal("DeviceKey opened a missing slot")
	}
	_ = s.Put("device/scale", clerk.KindStatic, []byte("canary-kl-0001"))
	var lent []byte
	if err := open(func(k []byte) error {
		if string(k) != "canary-kl-0001" {
			t.Fatalf("key %q", k)
		}
		lent = k
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(lent, make([]byte, len(lent))) {
		t.Fatal("the lent key was not wiped after fn returned")
	}
	_ = s.Put("device/scale", clerk.KindGrant, []byte("canary-grant-0002"))
	if err := open(func([]byte) error { t.Fatal("opened a grant"); return nil }); err == nil {
		t.Fatal("DeviceKey opened a grant slot")
	}
	_ = s.Put("mail/a", clerk.KindStatic, []byte("canary-pass-0002"))
	if err := s.DeviceKey("mail/a")(func([]byte) error { t.Fatal("opened a mail slot"); return nil }); err == nil {
		t.Fatal("DeviceKey opened a slot outside DeviceSlots")
	}
}

// RemovePrefix drops every slot under the prefix but the one kept, in one
// write, leaves the store as it was when the write fails, and writes nothing
// when nothing matches.
func TestSecretsRemovePrefix(t *testing.T) {
	sl := sealer(t)
	writes, fail := 0, false
	var disk []byte
	s := clerk.NewSecrets(sl, func(b []byte) error {
		if fail {
			return errors.New("disk full")
		}
		writes++
		disk = bytes.Clone(b)
		return nil
	})
	for _, slot := range []string{"mail/a", "mail/b", "mail/c", "exit-key"} {
		_ = s.Put(slot, clerk.KindStatic, []byte("canary-"+slot))
	}
	fail = true
	if err := s.RemovePrefix("mail/", "mail/b"); err == nil || s.Len() != 4 {
		t.Fatal("a RemovePrefix whose write failed changed the store")
	}
	fail = false
	n := writes
	if err := s.RemovePrefix("mail/", "mail/b"); err != nil || writes != n+1 {
		t.Fatalf("RemovePrefix: %v, %d writes", err, writes-n)
	}
	re := clerk.NewSecrets(sl, nil)
	if err := re.UnmarshalBinary(disk); err != nil || re.Len() != 2 || !re.Has("mail/b") || !re.Has("exit-key") {
		t.Fatalf("at rest after RemovePrefix: %v, %d slots", err, re.Len())
	}
	if err := s.RemovePrefix("mail/", "mail/b"); err != nil || writes != n+1 {
		t.Fatal("a RemovePrefix matching nothing wrote")
	}
	if err := s.RemovePrefix("", "mail/b"); err == nil || s.Len() != 2 {
		t.Fatal("an empty prefix was taken as every slot")
	}
}

// REQ: DEV-7
//
// VisionTemplate opens a vision-template/ slot alone, and no other lend
// opens one; Names lists names under its prefix only, and none for an empty
// prefix (VIS-faces, D-214).
func TestVisionTemplateOpensOnlyItsSlots(t *testing.T) {
	s := clerk.NewSecrets(sealer(t), nil)
	for slot, v := range map[string]string{"vision-template/alice": "tpl", "device/scale": "kl", "mail/me": "pw"} {
		if err := s.Put(slot, clerk.KindStatic, []byte(v)); err != nil {
			t.Fatal(err)
		}
	}
	var got []byte
	if err := s.VisionTemplate("vision-template/alice")(func(b []byte) error { got = bytes.Clone(b); return nil }); err != nil || string(got) != "tpl" {
		t.Fatalf("own slot: %q %v", got, err)
	}
	for _, slot := range []string{"device/scale", "mail/me", "vision-template", "xvision-template/alice"} {
		if err := s.VisionTemplate(slot)(func([]byte) error { return nil }); err == nil {
			t.Errorf("VisionTemplate opened %s", slot)
		}
	}
	if err := s.DeviceKey("vision-template/alice")(func([]byte) error { return nil }); err == nil {
		t.Error("DeviceKey opened a template slot")
	}
	if n := s.Names(clerk.VisionTemplateSlots); len(n) != 1 || n[0] != "vision-template/alice" {
		t.Errorf("names: %v", n)
	}
	if n := s.Names(""); n != nil {
		t.Errorf("an empty prefix listed %v", n)
	}
}
