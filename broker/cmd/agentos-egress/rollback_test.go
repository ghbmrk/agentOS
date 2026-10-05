package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/tpmseal/swtpm"
)

// REQ: CRED-8, CRED-9, REC-2

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
}

// R10a in the vault process: re-encryption rewraps this PC's TPM slot
// through the TPM, so the PC still restarts unattended on the new key; the
// owner slot is proven by its factor; the rollback counter keeps binding.
func TestReencryptKeepsThisTrustedPC(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	before := r.copyFile(t, r.vault)
	if n, err := r.c.reencrypt("", cardFactor{}); err != nil || n != 0 {
		t.Fatalf("reencrypt: dropped %d, %v", n, err)
	}
	after := r.copyFile(t, r.vault)
	if keyIDOf(t, before) == keyIDOf(t, after) {
		t.Fatal("the data key did not change")
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != open {
		t.Fatalf("trusted PC after re-encryption: phase %v, notes %q", r.phase(), r.notes)
	}
	r.unknownHostUnlockAfterLock(t)
}

// Another trusted PC's slot cannot be proven here; it is dropped and the
// owner is told.
func TestReencryptDropsOtherPCs(t *testing.T) {
	r := newPCRig(t)
	r.trusted(t)
	other := swtpm.Start(t)
	bootGood(other)
	r.start(t, other)
	r.trusted(t)
	if n, err := r.c.reencrypt("", cardFactor{}); err != nil || n != 1 {
		t.Fatalf("reencrypt: dropped %d, %v; want 1", n, err)
	}
	if !r.noted("must be trusted again") {
		t.Fatalf("owner not told: %q", r.notes)
	}
	bootGood(r.tpm)
	r.start(t, r.tpm)
	if r.phase() != locked {
		t.Fatal("dropped PC still restarts unattended")
	}
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
