package tpmseal_test

// REQ: STO-2, STO-1

import (
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// absent says that no handle derived for id holds an index.
func absent(t *testing.T, tpm transport.TPM, hs []tpm2.TPMHandle) bool {
	t.Helper()
	for _, h := range hs {
		if _, err := (tpm2.NVReadPublic{NVIndex: h}).Execute(tpm); !errors.Is(err, tpm2.TPMRCHandle) {
			return false
		}
	}
	return true
}

// Freeing a store's pins and counter leaves NV_ReadPublic reporting both
// absent, and touches no other store's indexes. Freeing twice is a no-op.
func TestFreePinsAndCounter(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, other := srkName(t, s), vaultID(t), vaultID(t)
	for _, v := range [][]byte{id, other} {
		if err := tpmseal.WritePins(s.TPM(), srk, v, testPins(t)); err != nil {
			t.Fatal(err)
		}
		if _, err := tpmseal.DefineCounter(s.TPM(), srk, v, counterAuth(t)); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		if err := tpmseal.FreePins(s.TPM(), srk, id); err != nil {
			t.Fatal(err)
		}
		if err := tpmseal.FreeCounter(s.TPM(), srk, id); err != nil {
			t.Fatal(err)
		}
	}
	if !absent(t, s.TPM(), tpmseal.PinsHandles(id)) || !absent(t, s.TPM(), tpmseal.CounterHandles(id)) {
		t.Fatal("a freed index is still defined")
	}
	if _, err := tpmseal.ReadPins(s.TPM(), srk, other); err != nil {
		t.Fatalf("the other store's pins: %v", err)
	}
	if ok, err := tpmseal.FindCounter(s.TPM(), other); err != nil || !ok {
		t.Fatalf("the other store's counter: %v %v", ok, err)
	}
	// Once freed, the store's pins can be written with a new key: this is
	// how a rotation replaces them.
	if err := tpmseal.WritePins(s.TPM(), srk, id, testPins(t)); err != nil {
		t.Fatal(err)
	}
}

// An unlocked pins index (an interrupted WritePins) and a never-incremented
// counter (an interrupted DefineCounter) are freed too.
func TestFreeHalfMadeIndexes(t *testing.T) {
	s := swtpm.Start(t)
	srk, id := srkName(t, s), vaultID(t)
	ph := tpmseal.PinsHandles(id)[0]
	if _, err := (tpm2.NVDefineSpace{AuthHandle: ownerAuth, PublicInfo: tpm2.New2B(tpmseal.PinsPublic(ph, id, false, false))}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	ch := tpmseal.CounterHandles(id)[0]
	pub := tpm2.TPMSNVPublic{
		NVIndex: ch, NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{NT: tpm2.TPMNTCounter, AuthWrite: true, AuthRead: true, NoDA: true},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: tpmseal.CounterTag(id)}, DataSize: 8,
	}
	if _, err := (tpm2.NVDefineSpace{AuthHandle: ownerAuth, Auth: tpm2.TPM2BAuth{Buffer: counterAuth(t)}, PublicInfo: tpm2.New2B(pub)}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	if ok, err := tpmseal.FindCounter(s.TPM(), id); err != nil || !ok {
		t.Fatalf("the half-made counter is not found: %v %v", ok, err)
	}
	if err := tpmseal.FreePins(s.TPM(), srk, id); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.FreeCounter(s.TPM(), srk, id); err != nil {
		t.Fatal(err)
	}
	if !absent(t, s.TPM(), []tpm2.TPMHandle{ph, ch}) {
		t.Fatal("a half-made index is still defined")
	}
}

// OtherPins finds a locked pins index of any other store, and not the
// store's own, an unlocked one, or a counter.
func TestOtherPins(t *testing.T) {
	s := swtpm.Start(t)
	srk, id, other := srkName(t, s), vaultID(t), vaultID(t)
	check := func(v []byte, want bool) {
		t.Helper()
		if got, err := tpmseal.OtherPins(s.TPM(), v); err != nil || got != want {
			t.Fatalf("OtherPins(%x) = %v, %v; want %v", v, got, err, want)
		}
	}
	check(nil, false)
	if _, err := tpmseal.DefineCounter(s.TPM(), srk, other, counterAuth(t)); err != nil {
		t.Fatal(err)
	}
	h := tpmseal.PinsHandles(other)[0]
	if _, err := (tpm2.NVDefineSpace{AuthHandle: ownerAuth, PublicInfo: tpm2.New2B(tpmseal.PinsPublic(h, other, false, false))}).Execute(s.TPM()); err != nil {
		t.Fatal(err)
	}
	check(nil, false)
	if err := tpmseal.WritePins(s.TPM(), srk, id, testPins(t)); err != nil {
		t.Fatal(err)
	}
	check(id, false)
	check(nil, true)
	check(other, true)
	if err := tpmseal.FreePins(s.TPM(), srk, id); err != nil {
		t.Fatal(err)
	}
	check(nil, false)
}
