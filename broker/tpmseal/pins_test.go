package tpmseal_test

// REQ: STO-2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

func testPins(t *testing.T) tpmseal.Pins {
	t.Helper()
	k, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	a := make([]byte, tpmseal.PinsAnchorLen)
	if _, err := rand.Read(a); err != nil {
		t.Fatal(err)
	}
	return tpmseal.Pins{PolicyKey: &k.PublicKey, Anchor: a}
}

func samePins(a, b tpmseal.Pins) bool {
	return a.PolicyKey.Equal(b.PolicyKey) && bytes.Equal(a.Anchor, b.Anchor)
}

func mustReadPins(t *testing.T, s *swtpm.TPM, srk, id []byte) tpmseal.Pins {
	t.Helper()
	p, err := tpmseal.ReadPins(s.TPM(), srk, id)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// ownerAuth is the empty owner hierarchy auth the tests' attacker uses.
var ownerAuth = tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)}

// The pins read back as written, and still do after a power cycle; each
// store has its own index.
func TestPinsRoundTripAndPowerCycle(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, other := srkName(t, s), vaultID(t), vaultID(t)
	if _, err := tpmseal.ReadPins(s.TPM(), srk, id); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("read before any write: %v", err)
	}
	p, q := testPins(t), testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.WritePins(s.TPM(), srk, other, q); err != nil {
		t.Fatal(err)
	}
	s.Reboot()
	if got := mustReadPins(t, s, srk, id); !samePins(got, p) {
		t.Fatal("pins changed across a power cycle")
	}
	if got := mustReadPins(t, s, srk, other); !samePins(got, q) {
		t.Fatal("the second store read the first store's pins")
	}
}

// Once written the index is locked: a rewrite with other values is
// refused and changes nothing, the same values are accepted, and a raw
// write through the owner hierarchy fails, after a power cycle too.
func TestPinsAreWriteOnce(t *testing.T) {
	s := swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	p := testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatalf("rewriting the same pins: %v", err)
	}
	evil := testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srk, id, evil); !errors.Is(err, tpmseal.ErrPinsDiffer) {
		t.Fatalf("rewrite with other pins: %v", err)
	}
	evil.Anchor = p.Anchor
	if err := tpmseal.WritePins(s.TPM(), srk, id, evil); !errors.Is(err, tpmseal.ErrPinsDiffer) {
		t.Fatalf("rewrite with another policy key: %v", err)
	}
	s.Reboot()
	tried := 0
	for _, h := range tpmseal.PinsHandles(id) {
		rsp, err := tpm2.NVReadPublic{NVIndex: h}.Execute(s.TPM())
		if err != nil {
			continue
		}
		tried++
		_, err = tpm2.NVWrite{
			AuthHandle: ownerAuth,
			NVIndex:    tpm2.NamedHandle{Handle: h, Name: rsp.NVName},
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: []byte{1}},
		}.Execute(s.TPM())
		if !errors.Is(err, tpm2.TPMRCNVLocked) {
			t.Fatalf("raw write to the locked index: %v", err)
		}
	}
	if tried != 1 {
		t.Fatalf("found %d pins indexes, want 1", tried)
	}
	if got := mustReadPins(t, s, srk, id); !samePins(got, p) {
		t.Fatal("a refused rewrite changed the pins")
	}
}

// An index of the pins' shape that was defined, or written, but never
// locked is not read as pins; WritePins finishes it.
func TestUnlockedPinsFailClosed(t *testing.T) {
	s := swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	h := tpmseal.PinsHandles(id)[0]
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: ownerAuth,
		PublicInfo: tpm2.New2B(tpmseal.PinsPublic(h, id, false, false)),
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srk, id); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("read of a defined, unwritten index: %v", err)
	}
	data := make([]byte, 98)
	data[0] = 1
	if _, err := (tpm2.NVWrite{
		AuthHandle: ownerAuth,
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: mustNVName(t, s, h)},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srk, id); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("read of a written, unlocked index: %v", err)
	}
	p := testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatal(err)
	}
	if got := mustReadPins(t, s, srk, id); !samePins(got, p) {
		t.Fatal("finished index reads other pins")
	}
	if rsp, err := (tpm2.NVReadPublic{NVIndex: h}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	} else if pub, err := rsp.NVPublic.Contents(); err != nil || !pub.Attributes.WriteLocked {
		t.Fatalf("WritePins did not finish the interrupted index: %v", err)
	}
}

// An index at a derived handle with the same tag but other attributes
// (here writable by its own auth value, so anyone holding that could
// rewrite it) is not the pins, even written and locked, and WritePins
// uses the next free handle.
func TestPinsOfAnotherShapeAreNotRead(t *testing.T) {
	s := swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	h := tpmseal.PinsHandles(id)[0]
	pub := tpmseal.PinsPublic(h, id, false, false)
	pub.Attributes.OwnerWrite, pub.Attributes.AuthWrite = false, true
	if _, err := (tpm2.NVDefineSpace{AuthHandle: ownerAuth, PublicInfo: tpm2.New2B(pub)}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	evil := testPins(t)
	k, err := evil.PolicyKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte{1}, k...), evil.Anchor...)
	name := mustNVName(t, s, h)
	if _, err := (tpm2.NVWrite{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: name},
		Data:       tpm2.TPM2BMaxNVBuffer{Buffer: data},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	name = mustNVName(t, s, h)
	if _, err := (tpm2.NVWriteLock{
		AuthHandle: tpm2.AuthHandle{Handle: h, Name: name, Auth: tpm2.PasswordAuth(nil)},
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: name},
	}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srk, id); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("read an index of another shape: %v", err)
	}
	p := testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatal(err)
	}
	if got := mustReadPins(t, s, srk, id); !samePins(got, p) {
		t.Fatal("read the other index's values")
	}
}

// The pins are read and written only through this TPM's own storage root
// key.
func TestPinsPinTheSRK(t *testing.T) {
	s, other := swtpm.Start(t), swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	p := testPins(t)
	if err := tpmseal.WritePins(s.TPM(), srkName(t, other), id, p); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("write with another SRK name: %v", err)
	}
	if err := tpmseal.WritePins(s.TPM(), srk, id, p); err != nil {
		t.Fatal(err)
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srkName(t, other), id); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("read with another SRK name: %v", err)
	}
}

// WritePins refuses pins it could not read back as a policy key and an
// anchor, before touching the TPM.
func TestPinsRefuseBadValues(t *testing.T) {
	s := swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	p := testPins(t)
	for name, bad := range map[string]tpmseal.Pins{
		"no key":       {Anchor: p.Anchor},
		"short anchor": {PolicyKey: p.PolicyKey, Anchor: p.Anchor[:31]},
		"no anchor":    {PolicyKey: p.PolicyKey},
		"other curve":  {PolicyKey: &ecdsa.PublicKey{}, Anchor: p.Anchor},
	} {
		if err := tpmseal.WritePins(s.TPM(), srk, id, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srk, id); !errors.Is(err, tpmseal.ErrNoPins) {
		t.Fatalf("a refused write left an index: %v", err)
	}
}
