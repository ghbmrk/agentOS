package tpmseal_test

// REQ: CRED-8, HW-5a, A8, HW-8

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

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

// interposer sits on the TPM's bus and answers CreatePrimary with its own
// public key under the real SRK's name, hoping the box salts its sessions
// to a key the interposer holds.
type interposer struct {
	t   transport.TPM
	pub *ecdsa.PublicKey
	// sessions counts sessions started after a forged answer: each would
	// carry a salt encrypted to the interposer's key.
	sessions int
	forged   bool
}

func (i *interposer) Send(cmd []byte) ([]byte, error) {
	if i.forged && len(cmd) >= 10 && binary.BigEndian.Uint32(cmd[6:10]) == uint32(tpm2.TPMCCStartAuthSession) {
		i.sessions++
	}
	rsp, err := i.t.Send(cmd)
	if err != nil || len(cmd) < 10 || binary.BigEndian.Uint32(cmd[6:10]) != uint32(tpm2.TPMCCCreatePrimary) ||
		len(rsp) < 18 || binary.BigEndian.Uint32(rsp[6:10]) != 0 {
		return rsp, err
	}
	// header (10), object handle (4), parameter size (4), TPM2B_PUBLIC.
	out, err := tpm2.Unmarshal[tpm2.TPM2BPublic](rsp[18:])
	if err != nil {
		return rsp, nil
	}
	pub, err := out.Contents()
	if err != nil {
		return rsp, nil
	}
	ecc, err := pub.Unique.ECC()
	if err != nil {
		return rsp, nil
	}
	x, y := make([]byte, 32), make([]byte, 32)
	i.pub.X.FillBytes(x)
	i.pub.Y.FillBytes(y)
	i.forged = true
	forged := bytes.Replace(rsp, ecc.X.Buffer, x, 1)
	return bytes.Replace(forged, ecc.Y.Buffer, y, 1), nil
}

// An interposer that substitutes the storage root key's public area while
// keeping its name is caught before any session is salted to its key: at
// seal time (no recorded name yet) and at unseal time. (This interposer
// is passive, so the TPM would reject the session anyway; an active one
// holding its key could re-salt to the real SRK, which is why no salt may
// ever be sent to its key.)
func TestSubstitutedSRKPublicRefused(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	key := newKey(t)
	_, sealed, pols := enroll(t, s, key, "")
	evil := newKey(t)
	bus := &interposer{t: s.TPM(), pub: &evil.PublicKey}

	if _, err := tpmseal.Seal(bus, secret(t), &key.PublicKey, "", "Test PC"); err == nil {
		t.Fatal("sealed through the interposer")
	}
	if _, err := tpmseal.Unseal(bus, sealed, pols, ""); err == nil {
		t.Fatal("unsealed through the interposer")
	}
	if bus.sessions != 0 {
		t.Fatalf("%d sessions salted to the interposer's key", bus.sessions)
	}
	if _, err := tpmseal.Identity(bus); err == nil {
		t.Fatal("identity from a substituted storage root key")
	}
	// The bus without the interposer still works.
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, ""); err != nil {
		t.Fatal(err)
	}
}

// A PIN slot takes the TPM's lockout hierarchy, so the guess counter can't
// be reset with the factory-empty lockout password; a lockout password
// someone else set is refused rather than guessed; turning the PIN off
// gives the hierarchy back.
func TestPINSlotTakesTheLockoutHierarchy(t *testing.T) {
	s := swtpm.Start(t)
	if err := s.ThiefLockReset(); err != nil {
		t.Fatalf("factory TPM: empty-password reset should work: %v", err)
	}
	auth, err := tpmseal.NewLockoutAuth()
	if err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.TakeLockout(s.TPM(), auth, true); err != nil {
		t.Fatalf("box's own lockout authorization: %v", err)
	}
	other, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), other, false); !errors.Is(err, tpmseal.ErrLockoutOwned) {
		t.Fatalf("lockout set by someone else: got %v, want ErrLockoutOwned", err)
	}
	// Turning the PIN off gives the lockout hierarchy back: empty again.
	if err := tpmseal.ReleaseLockout(s.TPM(), auth); err != nil {
		t.Fatal(err)
	}
	if err := s.ThiefLockReset(); err != nil {
		t.Fatalf("lockout not back to empty after release: %v", err)
	}
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatalf("taking the released lockout again: %v", err)
	}
	if err := s.ThiefLockReset(); err == nil {
		t.Fatal("empty-password reset still works after the box took the lockout hierarchy")
	}
}

// After PINMaxTries wrong PINs the TPM refuses even the right one.
func TestPINLockout(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	auth, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	_, sealed, pols := enroll(t, s, newKey(t), "4711-correct")
	for i := 0; i < tpmseal.PINMaxTries; i++ {
		if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, "0000"); !errors.Is(err, tpmseal.ErrPIN) {
			t.Fatalf("wrong PIN %d: got %v, want ErrPIN", i+1, err)
		}
	}
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, "4711-correct"); !errors.Is(err, tpmseal.ErrLockout) {
		t.Fatalf("right PIN in lockout: got %v, want ErrLockout", err)
	}
	if err := s.ThiefLockReset(); err == nil {
		t.Fatal("thief reset the lockout")
	}
}

// Only the exact PIN opens the slot: no prefix, extension, case or
// spacing variant does.
func TestPINVariantsDoNotOpen(t *testing.T) {
	s := swtpm.Start(t)
	boot(s, releaseA)
	auth, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	_, sealed, pols := enroll(t, s, newKey(t), "Zebra-4711")
	for _, pin := range []string{"Zebra-471", "Zebra-47110", "zebra-4711", "Zebra-4711 ", " Zebra-4711", "Zebra-4711\x00"} {
		if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, pin); !errors.Is(err, tpmseal.ErrPIN) {
			t.Fatalf("PIN %q: got %v, want ErrPIN", pin, err)
		}
	}
	if _, err := tpmseal.Unseal(s.TPM(), sealed, pols, "Zebra-4711"); err != nil {
		t.Fatalf("exact PIN: %v", err)
	}
}

// A vault that believes it holds the lockout authorization, but whose
// value the TPM no longer has (a restored vault, a TPM re-keyed by other
// software), is told so rather than trusted.
func TestHeldLockoutIsProved(t *testing.T) {
	s := swtpm.Start(t)
	auth, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	stale, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), stale, true); !errors.Is(err, tpmseal.ErrLockoutOwned) {
		t.Fatalf("held but wrong: got %v, want ErrLockoutOwned", err)
	}
}

// Giving back a lockout the box no longer holds (its value is stale) is
// told apart from a TPM that is only refusing for now.
func TestReleaseWithStaleValue(t *testing.T) {
	s := swtpm.Start(t)
	auth, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	stale, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.ReleaseLockout(s.TPM(), stale); !errors.Is(err, tpmseal.ErrLockoutOwned) {
		t.Fatalf("stale value: got %v, want ErrLockoutOwned", err)
	}
	// Now in lockout for the lockout hierarchy: the right value is
	// refused for the moment, and that is not ErrLockoutOwned.
	if err := tpmseal.ReleaseLockout(s.TPM(), auth); err == nil || errors.Is(err, tpmseal.ErrLockoutOwned) {
		t.Fatalf("right value during lockout: got %v", err)
	}
}

// HOST-1f (HW-8, D7): the dictionary-attack settings a PIN slot changes
// are read first and can be put back exactly as they were, only while the
// lockout authorization is empty: with it set, RestoreDA sends nothing
// that needs it (Security H1), so the hierarchy is not locked by a probe.
func TestDASettingsAreGivenBackAsTheyWere(t *testing.T) {
	s := swtpm.Start(t)
	orig := tpmseal.DAParams{MaxTries: 7, Interval: 600, Recovery: 3600}
	if err := tpmseal.RestoreDA(s.TPM(), orig); err != nil {
		t.Fatal(err)
	}
	if got, err := tpmseal.ReadDA(s.TPM()); err != nil || got != orig {
		t.Fatalf("read %+v, %v; want %+v", got, err, orig)
	}
	auth, _ := tpmseal.NewLockoutAuth()
	if err := tpmseal.TakeLockout(s.TPM(), auth, false); err != nil {
		t.Fatal(err)
	}
	if got, _ := tpmseal.ReadDA(s.TPM()); got != tpmseal.PINDA {
		t.Fatalf("PIN slot's settings %+v, want %+v", got, tpmseal.PINDA)
	}
	if set, err := tpmseal.LockoutAuthSet(s.TPM()); err != nil || !set {
		t.Fatalf("lockout authorization set: %v, %v", set, err)
	}
	if err := tpmseal.RestoreDA(s.TPM(), orig); !errors.Is(err, tpmseal.ErrLockoutSet) {
		t.Fatalf("restore while the box holds the lockout: %v", err)
	}
	// Nothing was tried against the lockout authorization: the box's own
	// value still works at once (a wrong one would lock it for a day).
	if err := tpmseal.TakeLockout(s.TPM(), auth, true); err != nil {
		t.Fatalf("lockout hierarchy disturbed by the refused restore: %v", err)
	}
	if err := tpmseal.ReleaseLockout(s.TPM(), auth); err != nil {
		t.Fatal(err)
	}
	if err := tpmseal.RestoreDA(s.TPM(), orig); err != nil {
		t.Fatal(err)
	}
	if got, _ := tpmseal.ReadDA(s.TPM()); got != orig {
		t.Fatalf("after release and restore %+v, want %+v", got, orig)
	}
	// MaxTries 0 (no protection) is what some PCs have; it is put back too.
	none := tpmseal.DAParams{MaxTries: 0, Interval: 0, Recovery: 0}
	if err := tpmseal.RestoreDA(s.TPM(), none); err != nil {
		t.Fatal(err)
	}
	if got, _ := tpmseal.ReadDA(s.TPM()); got != none {
		t.Fatalf("zero settings %+v", got)
	}
}

// Security H4: a stored triple is exactly three decimal uint32 values in
// the form String writes; anything else is refused, never written.
func TestParseDAIsStrict(t *testing.T) {
	p := tpmseal.DAParams{MaxTries: 32, Interval: 7200, Recovery: 86400}
	got, err := tpmseal.ParseDA(p.String())
	if err != nil || got != p {
		t.Fatalf("round trip %+v, %v", got, err)
	}
	if p.String() != "32,7200,86400" {
		t.Fatalf("format %q", p.String())
	}
	if got, err := tpmseal.ParseDA("0,0,0"); err != nil || got != (tpmseal.DAParams{}) {
		t.Fatalf("zeros: %+v, %v", got, err)
	}
	if got, err := tpmseal.ParseDA("4294967295,1,2"); err != nil || got.MaxTries != 4294967295 {
		t.Fatalf("max uint32: %+v, %v", got, err)
	}
	for _, bad := range []string{"", "32", "32,7200", "32,7200,86400,1", " 32,7200,86400", "32,7200,86400\n",
		"+32,7200,86400", "-1,7200,86400", "032,7200,86400", "4294967296,1,2", "32,,86400", "0x20,7200,86400", "32, 7200,86400"} {
		if _, err := tpmseal.ParseDA(bad); err == nil {
			t.Errorf("ParseDA(%q) accepted", bad)
		}
	}
}
