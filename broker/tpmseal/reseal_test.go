package tpmseal_test

// REQ: CRED-8, CRED-9

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// B5: a PC trusted earlier gets a secret sealed under a new policy key
// while it is away, from the SRK public area its slot recorded. It
// unseals on its approved boot path once the path is re-signed under the
// new key; the old key's policies and another PC do not open it.
func TestSealToAnotherPC(t *testing.T) {
	a, b := swtpm.Start(t), swtpm.Start(t)
	boot(a, releaseA)
	boot(b, releaseA)
	oldKey := newKey(t)
	_, sealed, oldPols := enroll(t, a, oldKey, "")
	if len(sealed.SRKPublic) == 0 {
		t.Fatal("Seal recorded no SRK public area")
	}

	newKeyB := newKey(t)
	sec := secret(t)
	moved, err := tpmseal.SealTo(sealed.SRKPublic, sec, &newKeyB.PublicKey, "Test PC")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(moved.SRKName, sealed.SRKName) {
		t.Fatal("offline seal names another TPM")
	}
	if _, err := tpmseal.Unseal(a.TPM(), moved, oldPols, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("old key's policies: %v, want ErrPolicy", err)
	}
	re, err := tpmseal.Resign(newKeyB, oldPols[0])
	if err != nil {
		t.Fatal(err)
	}
	both := append(append([]tpmseal.Policy(nil), oldPols...), re)
	boot(a, releaseA)
	got, err := tpmseal.Unseal(a.TPM(), moved, both, "")
	if err != nil {
		t.Fatalf("unseal on the PC: %v", err)
	}
	if !bytes.Equal(got, sec) {
		t.Fatal("unsealed a different secret")
	}
	// The old slot still opens under the old key's policy in the same
	// file: the two keys' policies do not mix up.
	if _, err := tpmseal.Unseal(a.TPM(), sealed, both, ""); err != nil {
		t.Fatalf("old slot with both keys' policies: %v", err)
	}
	if _, err := tpmseal.Unseal(b.TPM(), moved, both, ""); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("other PC: %v, want ErrOtherTPM", err)
	}
	boot(a, releaseB)
	if _, err := tpmseal.Unseal(a.TPM(), moved, both, ""); !errors.Is(err, tpmseal.ErrNoPolicy) {
		t.Fatalf("unapproved boot path: %v", err)
	}
}

// A recorded SRK public area that is not this kind of key is refused.
func TestSealToRefusesABadSRK(t *testing.T) {
	if _, err := tpmseal.SealTo([]byte{0, 4, 1, 2, 3, 4}, []byte("kek"), &newKey(t).PublicKey, ""); !errors.Is(err, tpmseal.ErrSRK) {
		t.Fatalf("bad SRK: %v", err)
	}
}
