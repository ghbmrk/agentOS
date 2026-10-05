package tpmseal_test

// REQ: CRED-8, HW-5a, A8

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// The boot path a trusted host measures: the initrd into PCR 9 and the
// kernel command line (which carries the /usr root hash) into PCR 12, as
// the Type #1 boot of S7 does.
var pcrs = []uint{9, 12}

type bootPath struct{ initrd, cmdline string }

var (
	releaseA = bootPath{"initrd-A", "usrhash=aaaa quiet"}
	releaseB = bootPath{"initrd-B", "usrhash=bbbb quiet"}
)

func boot(s *swtpm.TPM, b bootPath) {
	s.Reboot()
	s.Measure(9, b.initrd)
	s.Measure(12, b.cmdline)
}

// predict is what an updater computes for a release before rebooting.
func predict(b bootPath) [][]byte {
	return [][]byte{swtpm.Predict(b.initrd), swtpm.Predict(b.cmdline)}
}

func secret(t *testing.T) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := tpmseal.NewPolicyKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// enroll seals a secret on the running boot path and approves that path.
func enroll(t *testing.T, s *swtpm.TPM, key *ecdsa.PrivateKey, pin string) ([]byte, *tpmseal.Sealed, []tpmseal.Policy) {
	t.Helper()
	sec := secret(t)
	sealed, err := tpmseal.Seal(s.TPM(), sec, &key.PublicKey, pin, "Test PC")
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpmseal.SignCurrent(s.TPM(), key, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	return sec, sealed, []tpmseal.Policy{p}
}

// A trusted host restarts unattended: after a power cycle on the same boot
// path, the TPM releases the secret with no owner input.
func TestTrustedHostRestartsUnattended(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	sec, sealed, pols := enroll(t, s, key, "")

	boot(s, releaseA)
	got, err := tpmseal.Unseal(s.TPM(), sealed, pols, "")
	if err != nil {
		t.Fatalf("unseal after restart: %v", err)
	}
	if !bytes.Equal(got, sec) {
		t.Fatal("unsealed a different secret")
	}
}

// A modified initrd or kernel command line does not unlock (HW-5a, A8).
func TestModifiedBootPathDoesNotUnlock(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	_, sealed, pols := enroll(t, s, key, "")

	for name, b := range map[string]bootPath{
		"initrd":  {"initrd-A-with-a-keylogger", releaseA.cmdline},
		"cmdline": {releaseA.initrd, releaseA.cmdline + " init=/bin/sh"},
	} {
		boot(s, b)
		if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); !errors.Is(err, tpmseal.ErrNoPolicy) {
			t.Errorf("modified %s: got %v, want ErrNoPolicy", name, err)
		}
	}
}

// The TPM, not this package's PCR comparison, enforces the policy: a
// policy that claims the modified path's digest but carries the approved
// path's signature is refused by the TPM.
func TestTPMEnforcesSignatureOverPCRs(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	_, sealed, pols := enroll(t, s, key, "")

	evil := bootPath{"initrd-evil", releaseA.cmdline}
	boot(s, evil)
	forged := pols[0]
	ev, err := tpmseal.ReadPCRs(s.TPM(), pcrs)
	if err != nil {
		t.Fatal(err)
	}
	other, err := tpmseal.Sign(key, pcrs, ev) // only to get evil's digest
	if err != nil {
		t.Fatal(err)
	}
	forged.Digest = other.Digest
	if _, err := tpmseal.Unseal(s.TPM(), sealed, []tpmseal.Policy{forged}, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("forged policy: got %v, want ErrPolicy", err)
	}
}

// After an A/B update the trusted host still restarts unattended: the box
// signs the new release's predicted PCRs before rebooting, and the sealed
// object is untouched (HW-5a: the seal is to a policy, not to values).
func TestABUpdateKeepsUnattendedRestart(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	sec, sealed, pols := enroll(t, s, key, "")
	before := append([]byte(nil), sealed.Private...)

	pb, err := tpmseal.Sign(key, pcrs, predict(releaseB))
	if err != nil {
		t.Fatal(err)
	}
	pols = append(pols, pb)

	boot(s, releaseB)
	got, err := tpmseal.Unseal(s.TPM(), sealed, pols, "")
	if err != nil {
		t.Fatalf("unseal on release B: %v", err)
	}
	if !bytes.Equal(got, sec) || !bytes.Equal(sealed.Private, before) {
		t.Fatal("update changed the secret or the sealed object")
	}
	// Release A still boots too (rollback to the other slot).
	boot(s, releaseA)
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); err != nil {
		t.Fatalf("unseal on release A after update: %v", err)
	}
}

// A boot path signed by any key other than the box's does not unlock (A8).
func TestPolicySignedByOtherKeyDoesNotUnlock(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	_, sealed, _ := enroll(t, s, key, "")

	attacker := newKey(t)
	p, err := tpmseal.Sign(attacker, pcrs, predict(bootPath{"initrd-evil", "usrhash=evil"}))
	if err != nil {
		t.Fatal(err)
	}
	boot(s, bootPath{"initrd-evil", "usrhash=evil"})
	if _, err := tpmseal.Unseal(s.TPM(), sealed, []tpmseal.Policy{p}, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("attacker-signed policy: got %v, want ErrPolicy", err)
	}
	// Even for the genuine boot path.
	q, err := tpmseal.Sign(attacker, pcrs, predict(releaseA))
	if err != nil {
		t.Fatal(err)
	}
	boot(s, releaseA)
	if _, err := tpmseal.Unseal(s.TPM(), sealed, []tpmseal.Policy{q}, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("attacker-signed policy for the real path: got %v, want ErrPolicy", err)
	}
}

// A slot sealed on one PC does not open on another (the drive moved to an
// unknown host), and says so without trying the policy.
func TestOtherPCDoesNotUnlock(t *testing.T) {
	a, b := swtpm.Start(t), swtpm.Start(t)
	boot(a, releaseA)
	boot(b, releaseA)
	key := newKey(t)
	_, sealed, pols := enroll(t, a, key, "")

	if _, err := tpmseal.Unseal(b.TPM(), sealed, pols, ""); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("other TPM: got %v, want ErrOtherTPM", err)
	}
	// Relabelling the slot with the other TPM's identity does not help:
	// its storage key cannot load the object.
	idB, err := tpmseal.Identity(b.TPM())
	if err != nil {
		t.Fatal(err)
	}
	relabelled := *sealed
	relabelled.SRKName = idB
	if _, err := tpmseal.Unseal(b.TPM(), &relabelled, pols, ""); !errors.Is(err, tpmseal.ErrOtherTPM) {
		t.Fatalf("relabelled slot: got %v, want ErrOtherTPM", err)
	}
	idA, err := tpmseal.Identity(a.TPM())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(idA, sealed.SRKName) || bytes.Equal(idA, idB) {
		t.Fatal("TPM identity is not the sealing TPM's SRK name")
	}
}

// The optional boot PIN (CRED-8, off by default): without it or with a
// wrong one the TPM releases nothing; with it, the slot opens.
func TestBootPIN(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	sec, sealed, pols := enroll(t, s, key, "4711-correct")
	if !sealed.HasPIN() {
		t.Fatal("slot sealed with a PIN does not say so")
	}

	boot(s, releaseA)
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); !errors.Is(err, tpmseal.ErrNeedPIN) {
		t.Fatalf("no PIN: got %v, want ErrNeedPIN", err)
	}
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, "0000"); !errors.Is(err, tpmseal.ErrPIN) {
		t.Fatalf("wrong PIN: got %v, want ErrPIN", err)
	}
	got, err := tpmseal.Unseal(s.TPM(), sealed, pols, "4711-correct")
	if err != nil {
		t.Fatalf("right PIN: %v", err)
	}
	if !bytes.Equal(got, sec) {
		t.Fatal("unsealed a different secret")
	}
	// A slot without a PIN must not be convertible into one that needs
	// none by editing the record: the object's policy still demands it.
	stripped := *sealed
	stripped.PINSalt = nil
	if _, err := tpmseal.Unseal(s.TPM(), &stripped, pols, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("PIN stripped from the record: got %v, want ErrPolicy", err)
	}
}

// A boot path that measures nothing into a selected PCR cannot be
// approved: a policy over an unextended PCR would accept any boot path.
func TestUnmeasuredPCRRefused(t *testing.T) {
	s := swtpm.Start(t)
	s.Reboot() // nothing measured
	key := newKey(t)
	if _, err := tpmseal.SignCurrent(s.TPM(), key, pcrs); !errors.Is(err, tpmseal.ErrUnmeasured) {
		t.Fatalf("unextended PCRs: got %v, want ErrUnmeasured", err)
	}
	if _, err := tpmseal.SignCurrent(s.TPM(), key, nil); err == nil {
		t.Fatal("empty selection accepted")
	}
}

// A sealed record whose public area was swapped for an object under a
// different policy is refused before use.
func TestSwappedObjectRefused(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	_, sealed, pols := enroll(t, s, key, "")
	// The attacker's own object, sealed under the attacker's policy key,
	// presented with the box's policy key in the record.
	attacker := newKey(t)
	theirs, err := tpmseal.Seal(s.TPM(), secret(t), &attacker.PublicKey, "", "")
	if err != nil {
		t.Fatal(err)
	}
	swapped := *sealed
	swapped.Public, swapped.Private = theirs.Public, theirs.Private
	if _, err := tpmseal.Unseal(s.TPM(), &swapped, pols, ""); !errors.Is(err, tpmseal.ErrPolicy) {
		t.Fatalf("swapped object: got %v, want ErrPolicy", err)
	}
}

func TestPolicyKeyRoundTrip(t *testing.T) {
	k := newKey(t)
	der, err := tpmseal.MarshalPolicyKey(k)
	if err != nil {
		t.Fatal(err)
	}
	back, err := tpmseal.ParsePolicyKey(der)
	if err != nil || !back.Equal(k) {
		t.Fatalf("round trip: %v", err)
	}
}
