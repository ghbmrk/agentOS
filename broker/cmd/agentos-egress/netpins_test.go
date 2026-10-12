package main

// REQ: DEV-2, BAK-1, REV-5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/vault"
)

func pinVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.Create(filepath.Join(t.TempDir(), "v"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func pinJSON(kind, name, addr string, key [32]byte) []byte {
	return []byte(`{"kind":"` + kind + `","name":"` + name + `","addr":"` + addr + `","key":"` + hex.EncodeToString(key[:]) + `"}`)
}

var pinKey = sha256.Sum256([]byte("synthetic pinned public key"))

// No owner setting, no pin: the release default is an empty list.
func TestNoOwnerPinsByDefault(t *testing.T) {
	pins, _ := loadPins(pinVault(t))
	if len(pins) != 0 {
		t.Fatalf("pins without a setting: %+v", pins)
	}
}

// An owner pin is read for its kind, name, address and key, and a record
// that is malformed, of an unknown kind, or without a key is skipped and
// named in the problems without its value.
func TestOwnerPinsAreReadAndBadOnesSkipped(t *testing.T) {
	v := pinVault(t)
	put := func(name string, val []byte) {
		t.Helper()
		if err := v.Put(name, pinEntryKind, val); err != nil {
			t.Fatal(err)
		}
	}
	put("netpin:backup", pinJSON("backup", "backup.example.test", "192.168.1.40:8443", pinKey))
	put("netpin:bad-kind", pinJSON("router", "x.example.test", "", pinKey))
	put("netpin:no-key", pinJSON("hosted", "h.example.test", "", [32]byte{}))
	put("netpin:junk", []byte("not json at all, long enough"))
	if err := v.Put("netpin:other-kind", "api-key", pinJSON("backup", "z.example.test", "", pinKey)); err != nil {
		t.Fatal(err)
	}
	pins, problems := loadPins(v)
	if len(pins) != 1 || pins[0].Kind != netguard.PinBackup || pins[0].Name != "backup.example.test" ||
		pins[0].Addr != netip.MustParseAddrPort("192.168.1.40:8443") || pins[0].Key != pinKey {
		t.Fatalf("pins: %+v", pins)
	}
	if len(problems) != 3 {
		t.Fatalf("problems: %v", problems)
	}
	for _, p := range problems {
		if strings.Contains(p, "example.test") || strings.Contains(p, "not json") {
			t.Fatalf("a problem carries a value: %q", p)
		}
	}
}

// A pin reaches only its endpoint: the pinned address and port, with the
// pinned key. Another private address, or another port on the pinned
// address, stays refused. The pin ends with the unlock.
func TestOwnerPinReachesOnlyItsEndpointAndEndsWithTheUnlock(t *testing.T) {
	v := pinVault(t)
	if err := v.Put("netpin:backup", pinEntryKind, pinJSON("backup", "", "192.168.1.40:8443", pinKey)); err != nil {
		t.Fatal(err)
	}
	g := netguard.New(netguard.Config{})
	c := &custody{guard: g, build: func(*vault.Vault) (*egress.Proxy, error) { return nil, nil }}
	c.mu.Lock()
	if err := c.serve(v); err != nil {
		t.Fatal(err)
	}
	c.mu.Unlock()
	backup := netguard.WithPurpose(context.Background(), netguard.PurposeBackup)
	if err := g.Check(backup, netip.MustParseAddr("192.168.1.40"), 8443, "tcp"); err != nil {
		t.Fatalf("the pinned endpoint: %v", err)
	}
	for _, tc := range []struct {
		a string
		p uint16
	}{{"192.168.1.40", 22}, {"192.168.1.41", 8443}} {
		if err := g.Check(backup, netip.MustParseAddr(tc.a), tc.p, "tcp"); !errors.Is(err, netguard.ErrDenied) {
			t.Fatalf("%s:%d: %v", tc.a, tc.p, err)
		}
	}
	if err := g.Check(context.Background(), netip.MustParseAddr("192.168.1.40"), 8443, "tcp"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("the pin served another purpose: %v", err)
	}
	c.mu.Lock()
	c.discard()
	c.mu.Unlock()
	if err := g.Check(backup, netip.MustParseAddr("192.168.1.40"), 8443, "tcp"); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("the pin outlived the unlock: %v", err)
	}
}
