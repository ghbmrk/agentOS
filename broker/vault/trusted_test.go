package vault

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// REQ: CRED-8, CRED-9

// hostFactor stands in for the TPM factor (P2-4b): one per PC, and a slot
// sealed on another PC is skipped rather than failing the unlock.
type hostFactor struct {
	host string
	kek  []byte
}

func newHost(host string) hostFactor {
	return hostFactor{host, bytes.Repeat([]byte(host[:1]), KeySize)}
}

func (hostFactor) Kind() string { return SlotTPM }

func (h hostFactor) Enroll() (Slot, []byte, error) {
	return Slot{Kind: SlotTPM, Sealed: []byte(h.host)}, append([]byte(nil), h.kek...), nil
}

func (h hostFactor) KEK(s Slot) ([]byte, error) {
	if string(s.Sealed) != h.host {
		return nil, ErrSkipSlot
	}
	return append([]byte(nil), h.kek...), nil
}

func sameHost(h hostFactor) func(Slot) bool {
	return func(s Slot) bool { return string(s.Sealed) == h.host }
}

func openWithPassphrase(t *testing.T) (*Vault, string, string) {
	t.Helper()
	fastKDF(t)
	vp, kp := sealedPaths(t)
	v, err := CreateSealed(vp, kp, Passphrase(testPass))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Put("openai", KindAPIKey, []byte("sk-canary-0123456789")); err != nil {
		t.Fatal(err)
	}
	return v, vp, kp
}

// An open vault adds a trusted-host slot without asking for the
// passphrase again; the new slot opens the vault by itself, and the
// passphrase slot still does.
func TestAddSlotWhileOpen(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	a := newHost("alpha")
	if err := v.AddSlot(a, sameHost(a)); err != nil {
		t.Fatal(err)
	}
	v.Close()

	w, err := OpenSealed(vp, kp, a)
	if err != nil {
		t.Fatalf("trusted host slot: %v", err)
	}
	if s, ok := w.Secret("openai"); !ok || s.Reveal() != "sk-canary-0123456789" {
		t.Fatal("trusted host slot opened a different vault")
	}
	w.Close()
	if w, err := OpenSealed(vp, kp, Passphrase(testPass)); err != nil {
		t.Fatalf("passphrase after adding a host: %v", err)
	} else {
		w.Close()
	}
}

// Each trusted PC has its own slot. A slot sealed on another PC is skipped,
// and a PC with no slot opens nothing.
func TestSlotsForOtherHostsAreSkipped(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	a, b := newHost("alpha"), newHost("bravo")
	for _, h := range []hostFactor{a, b} {
		if err := v.AddSlot(h, sameHost(h)); err != nil {
			t.Fatal(err)
		}
	}
	v.Close()
	w, err := OpenSealed(vp, kp, b)
	if err != nil {
		t.Fatalf("second host behind the first's slot: %v", err)
	}
	w.Close()
	if _, err := OpenSealed(vp, kp, newHost("charlie")); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("unknown host: got %v, want ErrNoSlotOpens", err)
	}
}

// Re-enrolling the same PC (say, to add a boot PIN) replaces its slot.
func TestAddSlotReplacesTheSameHost(t *testing.T) {
	v, _, kp := openWithPassphrase(t)
	defer v.Close()
	a := newHost("alpha")
	for i := 0; i < 2; i++ {
		if err := v.AddSlot(a, sameHost(a)); err != nil {
			t.Fatal(err)
		}
	}
	slots, err := ReadSlots(kp)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range slots {
		if s.Kind == SlotTPM {
			n++
		}
	}
	if n != 1 || len(slots) != 2 {
		t.Fatalf("slots after re-enrolling one host: %d tpm of %d", n, len(slots))
	}
}

// Removing a trusted host (CRED-9) drops its slot; the passphrase slot
// cannot be removed this way.
func TestRemoveTrustedHost(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	a, b := newHost("alpha"), newHost("bravo")
	v.AddSlot(a, sameHost(a))
	v.AddSlot(b, sameHost(b))
	n, err := v.RemoveSlots(SlotTPM, sameHost(a))
	if err != nil || n != 1 {
		t.Fatalf("remove: %d, %v", n, err)
	}
	if _, err := v.RemoveSlots(SlotPassphrase, func(Slot) bool { return true }); err == nil {
		t.Fatal("passphrase slot removed")
	}
	v.Close()
	if _, err := OpenSealed(vp, kp, a); !errors.Is(err, ErrNoSlotOpens) {
		t.Fatalf("removed host: got %v, want ErrNoSlotOpens", err)
	}
	if w, err := OpenSealed(vp, kp, b); err != nil {
		t.Fatalf("other host after removal: %v", err)
	} else {
		w.Close()
	}
}

// The open vault keeps the data key only to add slots, and Close wipes
// it; a vault opened from a raw key (tests, the slot code) cannot add one.
func TestDataKeyIsWipedOnClose(t *testing.T) {
	v, _, _ := openWithPassphrase(t)
	key := v.key
	v.Close()
	if !bytes.Equal(key, make([]byte, KeySize)) {
		t.Fatal("data key not wiped on Close")
	}
	if err := v.AddSlot(newHost("alpha"), nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("AddSlot after Close: got %v, want ErrClosed", err)
	}
	raw, err := Create(filepath.Join(t.TempDir(), "raw"), bytes.Repeat([]byte{1}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.AddSlot(newHost("alpha"), nil); err == nil {
		t.Fatal("raw-key vault added a slot")
	}
}

// A factor error other than "not this host" ends the unlock with that
// error, so the caller can tell the owner why (say, a changed boot path).
func TestFactorErrorIsReported(t *testing.T) {
	v, vp, kp := openWithPassphrase(t)
	a := newHost("alpha")
	v.AddSlot(a, sameHost(a))
	v.Close()
	boom := errors.New("boot path changed")
	if _, err := OpenSealed(vp, kp, failingFactor{boom}); !errors.Is(err, boom) {
		t.Fatalf("got %v, want the factor's error", err)
	}
}

type failingFactor struct{ err error }

func (failingFactor) Kind() string                  { return SlotTPM }
func (failingFactor) Enroll() (Slot, []byte, error) { return Slot{}, nil, errors.New("no") }
func (f failingFactor) KEK(Slot) ([]byte, error)    { return nil, f.err }
