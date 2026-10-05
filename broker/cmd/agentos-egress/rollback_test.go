package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, CRED-9

// copyFile and putBack stand in for someone with the drive: they copy a
// file while it is out of the owner's hands and later put it back.
func (r *pcRig) copyFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (r *pcRig) putBack(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (r *pcRig) trusted(t *testing.T) {
	t.Helper()
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("trust: %v", err)
	}
}

// V6 on the trusted PC: copy the drive, the owner replaces a leaked
// provider key, the copy is put back. The trusted PC does not restart
// unattended on it, the passphrase and a code do not open it either, and
// the owner is told why. The current drive still restarts unattended.
func TestOldDriveCopyIsRefusedOnTrustedPC(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	oldVault, oldKeys := r.copyFile(t, r.vault), r.copyFile(t, r.keys)
	if err := r.c.put("openai", []byte(synthetic(t, "sk-canary-replaced-"))); err != nil {
		t.Fatal(err)
	}

	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("current drive after a write: phase %v, notes %q", r.phase(), r.notes)
	}

	r.putBack(t, r.vault, oldVault)
	r.putBack(t, r.keys, oldKeys)
	bootGood(r.tpm)
	r.notes = nil
	r.start(t, r.tpm)
	if r.phase() != locked || r.c.model() != nil {
		t.Fatal("old copy restarted unattended")
	}
	if !r.noted("older than this PC has seen") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errRolledBack {
		t.Fatalf("passphrase on the old copy: %v, want errRolledBack", err)
	}
	if r.phase() != locked {
		t.Fatal("old copy left pending")
	}
}

// A copy from before the PC was trusted carries no slot and no anchor for
// it, so the PC sees an unknown host; the PC's counter for this vault
// still gives the copy away before any code is asked for.
func TestCopyFromBeforeTrustIsRefused(t *testing.T) {
	r := newPCRig(t)
	oldVault, oldKeys := r.copyFile(t, r.vault), r.copyFile(t, r.keys)
	r.trusted(t)

	r.putBack(t, r.vault, oldVault)
	r.putBack(t, r.keys, oldKeys)
	bootGood(r.tpm)
	r.start(t, r.tpm)
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errRolledBack {
		t.Fatalf("pre-trust copy: %v, want errRolledBack", err)
	}
}

// Moving the drive is not a rollback: writes on a second trusted PC leave
// the first PC's counter alone, and both restart unattended in turn.
func TestDriveMovesBetweenTrustedPCs(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	other := swtpm.Start(t)
	bootGood(other)
	r.start(t, other)
	r.trusted(t)
	for i, pc := range []*swtpm.TPM{other, r.tpm, other, r.tpm} {
		bootGood(pc)
		r.start(t, pc)
		if r.phase() != open {
			t.Fatalf("step %d: phase %v, notes %q", i, r.phase(), r.notes)
		}
		if err := r.c.put("openai", []byte(synthetic(t, "sk-canary-move-"))); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

// A PC removed from the trusted list keeps its counter: an old copy put
// back there is still refused, on the unknown-host path it now takes.
func TestUntrustedPCStillCatchesOldCopy(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	oldVault := r.copyFile(t, r.vault)
	if err := r.c.put("openai", []byte(synthetic(t, "sk-canary-replaced-"))); err != nil {
		t.Fatal(err)
	}
	hosts, err := r.c.hosts()
	if err != nil || len(hosts) != 1 {
		t.Fatal(hosts, err)
	}
	if _, err := r.c.untrust(r.code(), hosts[0].ID); err != nil {
		t.Fatal(err)
	}
	r.putBack(t, r.vault, oldVault)
	bootGood(r.tpm)
	r.start(t, r.tpm)
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errRolledBack {
		t.Fatalf("old copy on a formerly trusted PC: %v", err)
	}
}

// F1 in the vault process: the keys file from before the PC was removed,
// put back beside the current vault, would bring its slot back. The vault
// records the keys file it goes with, so the PC does not restart
// unattended on it and the passphrase does not open it either.
func TestOldKeysFileIsRefusedAfterUntrust(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	oldKeys := r.copyFile(t, r.keys)
	hosts, err := r.c.hosts()
	if err != nil || len(hosts) != 1 {
		t.Fatal(hosts, err)
	}
	if _, err := r.c.untrust(r.code(), hosts[0].ID); err != nil {
		t.Fatal(err)
	}
	r.putBack(t, r.keys, oldKeys)
	bootGood(r.tpm)
	r.notes = nil
	r.start(t, r.tpm)
	if r.phase() != locked || r.c.model() != nil {
		t.Fatal("removed PC restarted unattended on the old keys file")
	}
	if !r.noted("older than this PC has seen") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errRolledBack {
		t.Fatalf("passphrase with the old keys file: %v, want errRolledBack", err)
	}
}

// B3 and the arbitrator's ruling: the owner hierarchy undefines this PC's
// counter. The PC then refuses its unattended slot, tells the owner once
// in the agreed words, still lets the owner unlock in person, and makes a
// new counter when the owner trusts it again; a copy from before is then
// refused.
func TestMissingCounterFailsLoud(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	oldVault, oldKeys := r.copyFile(t, r.vault), r.copyFile(t, r.keys)
	if err := r.c.put("openai", []byte(synthetic(t, "sk-canary-replaced-"))); err != nil {
		t.Fatal(err)
	}
	ref, err := tpmseal.ParseCounterRef(r.c.v.Anchors()[0].Ref)
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := r.tpm.Open()
	if err != nil {
		t.Fatal(err)
	}
	h := tpm2.TPMHandle(ref.Handle)
	_, err = tpm2.NVUndefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		NVIndex:    tpm2.NamedHandle{Handle: h, Name: tpm2.TPM2BName{Buffer: ref.Name}},
	}.Execute(tpm)
	tpm.Close()
	if err != nil {
		t.Fatalf("undefine: %v", err)
	}

	bootGood(r.tpm)
	r.notes = nil
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("restarted unattended without the counter")
	}
	r.unknownHostUnlock(t)
	n := 0
	for _, s := range r.notes {
		if s == noteCounterReset {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("counter-reset notice shown %d times: %q", n, r.notes)
	}

	if _, err := r.c.trust(r.code(), ""); err != nil {
		t.Fatalf("re-trust: %v", err)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("re-trusted PC: phase %v, notes %q", r.phase(), r.notes)
	}
	r.putBack(t, r.vault, oldVault)
	r.putBack(t, r.keys, oldKeys)
	bootGood(r.tpm)
	r.start(t, r.tpm)
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errRolledBack {
		t.Fatalf("old copy after re-trust: %v", err)
	}
}

// UX-45-3: a TPM that does not answer the rollback check is reported in
// plain words, with the detail kept out of the owner's notice.
func TestSilentTPMIsReportedPlainly(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	r.c.lock()
	r.notes = nil
	r.c.host.(*tpmHost).openTPM = func() (transport.TPMCloser, error) { return nil, errors.New("tpm: device busy") }
	r.c.bootTrusted()
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err == nil {
		t.Fatal("unlocked without the rollback check")
	}
	if !r.noted(noteTPMSilent) {
		t.Fatalf("owner not told plainly: %q", r.notes)
	}
	for _, s := range r.notes {
		if strings.Contains(s, "device busy") {
			t.Fatalf("raw TPM error shown to the owner: %q", s)
		}
	}
}

// Trusting a PC anchors the vault to its counter first; the anchor is
// inside the sealed file.
func TestTrustAnchorsTheVault(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	a := r.c.v.Anchors()
	if len(a) != 1 || a[0].Pending || len(a[0].Ref) == 0 {
		t.Fatalf("anchors after trust: %+v", a)
	}
	hosts, _ := r.c.hosts()
	if len(hosts) != 1 || a[0].Host != hosts[0].ID {
		t.Fatalf("anchor host %q, trusted host %+v", a[0].Host, hosts)
	}
	// Another PC, with no counter for this vault, binds nothing.
	other := swtpm.Start(t)
	srk, err := tpmseal.Identity(other.TPM())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.c.v.Bind(&tpmCounter{openTPM: other.Open, srk: srk}); err != nil {
		t.Fatalf("PC without a counter: %v", err)
	}
	// Unlocking on that PC tells the owner it cannot check for an older
	// copy.
	bootGood(other)
	r.notes = nil
	r.start(t, other)
	r.unknownHostUnlock(t)
	if !r.noted(noteUnanchored) {
		t.Fatalf("owner not told this PC cannot check: %q", r.notes)
	}
}

// R10a in the vault process: re-encryption rewraps this PC's TPM slot
// through the TPM, so the PC still restarts unattended on the new key; the
// R10a and B5 in the vault process: re-encryption gives this PC a fresh
// slot under a new policy key, so it still restarts unattended, while the
// old policy key and the old key-encryption key, which whoever kept the
// old data key may hold, are in no slot any more.
func TestReencryptKeepsThisTrustedPC(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	before := r.copyFile(t, r.vault)
	oldSlot := tpmSlot(t, r.keys)
	oldKEK := unsealSlot(t, r, oldSlot)
	if n, err := r.c.reencrypt("", cardFactor{}); err != nil || n != 0 {
		t.Fatalf("reencrypt: dropped %d, %v", n, err)
	}
	after := r.copyFile(t, r.vault)
	if keyIDOf(t, before) == keyIDOf(t, after) {
		t.Fatal("the data key did not change")
	}
	newSlot := tpmSlot(t, r.keys)
	if bytes.Equal(newSlot.PolicyKey, oldSlot.PolicyKey) {
		t.Fatal("this PC's slot is still under the old policy key")
	}
	if bytes.Equal(unsealSlot(t, r, newSlot), oldKEK) {
		t.Fatal("this PC's slot kept its old key-encryption key")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("trusted PC after re-encryption: phase %v, notes %q", r.phase(), r.notes)
	}
	r.unknownHostUnlockAfterLock(t)
}

// The arbitrator's ruling: another trusted PC is sealed again from its
// recorded SRK while it is away, so it restarts unattended on the new
// key without the owner visiting it. A PC with a boot PIN cannot be, and
// the owner is told to trust it again.
func TestReencryptReachesOtherPCs(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t) // PC A
	pin := swtpm.Start(t)
	bootGood(pin)
	r.start(t, pin)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	b := swtpm.Start(t)
	bootGood(b)
	r.start(t, b)
	r.trusted(t) // PC B, where the rotation runs
	r.notes = nil
	if n, err := r.c.reencrypt("", cardFactor{}); err != nil || n != 1 {
		t.Fatalf("reencrypt: dropped %d, %v; want 1 (the PIN PC)", n, err)
	}
	if !r.noted("must be trusted again") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	if got := r.tpmSlots(t); got != 2 {
		t.Fatalf("%d trusted-host slots after re-encryption, want A and B", got)
	}

	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("PC A after re-encryption elsewhere: phase %v, notes %q", r.phase(), r.notes)
	}
	bootGood(pin)
	r.start(t, pin)
	if r.phase() != locked || r.c.needPIN {
		t.Fatal("the PIN PC kept a slot")
	}
}

// A wrong boot PIN for this PC's slot refuses the rotation with nothing
// changed, rather than sealing the mistyped PIN into the new slot.
func TestReencryptChecksThisPCsPIN(t *testing.T) {
	r := newPCRig(t)
	r.unknownHostUnlock(t)
	if _, err := r.c.trust(r.code(), "246810"); err != nil {
		t.Fatal(err)
	}
	before := r.copyFile(t, r.vault)
	if _, err := r.c.reencrypt("135790", cardFactor{}); err != errWrongPIN {
		t.Fatalf("wrong PIN: %v", err)
	}
	if !bytes.Equal(before, r.copyFile(t, r.vault)) {
		t.Fatal("vault changed")
	}
	if n, err := r.c.reencrypt("246810", cardFactor{}); err != nil || n != 0 {
		t.Fatalf("right PIN: %d, %v", n, err)
	}
}

func tpmSlot(t *testing.T, keys string) *tpmseal.Sealed {
	t.Helper()
	slots, err := vault.ReadSlots(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range slots {
		if s.Kind == vault.SlotTPM {
			sealed, err := sealedOf(s)
			if err != nil {
				t.Fatal(err)
			}
			return sealed
		}
	}
	t.Fatal("no trusted-host slot")
	return nil
}

func unsealSlot(t *testing.T, r *pcRig, s *tpmseal.Sealed) []byte {
	t.Helper()
	pols, err := r.c.host.(*tpmHost).readPolicies()
	if err != nil {
		t.Fatal(err)
	}
	tpm, err := r.tpm.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()
	kek, err := tpmseal.Unseal(tpm, s, pols, "")
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func keyIDOf(t *testing.T, raw []byte) string {
	t.Helper()
	var env struct {
		KeyID []byte `json:"key_id"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return string(env.KeyID)
}

// unknownHostUnlockAfterLock checks the card still opens the vault.
func (r *pcRig) unknownHostUnlockAfterLock(t *testing.T) {
	t.Helper()
	r.c.lock()
	r.unknownHostUnlock(t)
}
