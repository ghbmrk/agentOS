package recovery

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-4, CRED-8, CRED-9

// oldSecrets is what a copy of the drive taken now yields to whoever later
// holds a factor it opens with: the data key, the backup MAC key and the
// code-generator seed (R10a).
type oldSecrets struct {
	key, mac, seed []byte
}

func (x *box) snapshot() oldSecrets {
	x.t.Helper()
	mac, err := macKey(x.b.V)
	must(x.t, err)
	s, _ := x.b.V.Secret(SeedName)
	return oldSecrets{dataKey(x.t, x.b.KeysPath, x.rk), mac, []byte(s.Reveal())}
}

// opensLater reports whether the old data key still opens the drive's
// vault file as written now.
func (o oldSecrets) opensLater(x *box) bool {
	v, err := vault.Open(x.b.VaultPath, o.key)
	if err != nil {
		return false
	}
	v.Close()
	return true
}

func (x *box) secretNow(name string) []byte {
	s, _ := x.b.V.Secret(name)
	return []byte(s.Reveal())
}

// A lost card re-encrypts: the drive moves to a fresh data key, and the
// backup MAC key, the code-generator seed and the grid are replaced, so a
// lost card plus an earlier copy opens nothing written afterwards.
func TestALostCardRotationReencrypts(t *testing.T) {
	x := newBox(t)
	old := x.snapshot()
	tpm := Proof{Host: func() vault.Factor { return fakeTPM{[]byte("sealed-to-host-a-tpm")} }}
	if _, err := BeginRotate(x.b, []Part{PartPassphrase, PartRecovery}, Auth{Code: true, Local: true}, tpm, testGen, nil, t0); !errors.Is(err, ErrLostCardParts) {
		t.Fatalf("lost card kept the grid: %v", err)
	}
	done, err := x.rotate([]Part{PartPassphrase, PartRecovery, PartGrid}, Auth{Code: true, Local: true}, tpm)
	must(t, err)
	if old.opensLater(x) {
		t.Fatal("the old data key opens the vault written after a lost-card rotation")
	}
	if bytes.Equal(x.secretNow(MACKeyName), old.mac) {
		t.Fatal("backup MAC key kept")
	}
	seed := x.secretNow(SeedName)
	if bytes.Equal(seed, old.seed) || len(seed) != TOTPSeedBytes {
		t.Fatal("code-generator seed kept")
	}
	if done.Enrollment == nil || done.Enrollment.URI != otpauth(seed) {
		t.Fatal("no enrollment for the new code-generator seed")
	}
	// The rig's vault has one trusted host, which V.Reencrypt drops; the
	// vault process reseals what it can and counts the rest.
	if done.Retrust != 1 {
		t.Fatalf("trusted hosts to trust again: %d", done.Retrust)
	}
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after the rotation finished")
	}
	// Both new factors open the drive, and backups resume under the new
	// recovery key.
	nk, _ := ParseRecoveryKey(done.RecoveryKey)
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(done.VaultPassphrase)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.restore(x.backup(), nk, t0); err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(DoneNotes([]Part{PartPassphrase, PartRecovery, PartGrid}, true), " ")
	for _, want := range []string{"nothing made from now on", "code generator"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("lost-card done notes miss %q: %s", want, notes)
		}
	}
}

// A recovery-key change with the card in hand re-encrypts and replaces the
// MAC key; the code generator is kept, so the owner's phone keeps working.
func TestARecoveryKeyRotationReencrypts(t *testing.T) {
	x := newBox(t)
	old := x.snapshot()
	done, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)
	if old.opensLater(x) {
		t.Fatal("the old data key opens the vault written after a recovery-key rotation")
	}
	if bytes.Equal(x.secretNow(MACKeyName), old.mac) {
		t.Fatal("backup MAC key kept")
	}
	if !bytes.Equal(x.secretNow(SeedName), old.seed) || done.Enrollment != nil {
		t.Fatal("a rotation with the card in hand replaced the code generator")
	}
}

// Re-encryption rewraps every passphrase and recovery slot, so a
// recovery-key change on a drive with a passphrase slot needs the
// passphrase too: typed from the card, or replaced in the same rotation.
func TestARecoveryKeyRotationNeedsThePassphraseSlotProved(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	if _, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}, testGen, nil, t0); !errors.Is(err, ErrNeedPassphrase) {
		t.Fatalf("recovery-key rotation without the passphrase: %v", err)
	}
	old := x.snapshot()
	_, err := x.rotate([]Part{PartRecovery}, Auth{Recovery: x.rk}, Proof{Passphrase: []byte(x.card.VaultPassphrase)})
	must(t, err)
	if old.opensLater(x) {
		t.Fatal("not re-encrypted")
	}
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(x.card.VaultPassphrase)); err != nil {
		t.Fatalf("the kept passphrase no longer opens the drive: %v", err)
	}
}

// An ordinary passphrase change with the card in hand does not
// re-encrypt (arbitrator ruling, egress V7): the data key and MAC key stay.
func TestAPassphraseChangeKeepsTheDataKey(t *testing.T) {
	x := newBox(t)
	old := x.snapshot()
	_, err := x.rotate([]Part{PartPassphrase}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)
	if !old.opensLater(x) || !bytes.Equal(x.secretNow(MACKeyName), old.mac) {
		t.Fatal("a passphrase change re-encrypted")
	}
}

// The vault process supplies re-encryption (custody.reencrypt: a new
// policy key and resealed PCs); Commit hands it the new owner factors.
func TestTheVaultProcessReencrypts(t *testing.T) {
	x := newBox(t)
	var kinds []string
	x.b.Reencrypt = func(owner ...vault.Factor) (int, error) {
		for _, f := range owner {
			kinds = append(kinds, f.Kind())
		}
		_, err := x.b.V.Reencrypt(owner...)
		return 3, err
	}
	done, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)
	if done.Retrust != 3 || strings.Join(kinds, ",") != vault.SlotRecovery {
		t.Fatalf("vault process re-encryption: %d %v", done.Retrust, kinds)
	}
	x.b.Reencrypt = func(...vault.Factor) (int, error) { return 0, errors.New("tpm gone") }
	_, err = x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: mustRK(t, done.RecoveryKey)})
	if !errors.Is(err, ErrCardNotStored) {
		t.Fatalf("failed re-encryption: %v", err)
	}
	if _, ok := RotationUnfinished(x.b); !ok {
		t.Fatal("a failed re-encryption cleared the rotation marker")
	}
}

// Removing a trusted host re-encrypts too (egress V7): Refresh moves the
// vault to a fresh key and replaces the MAC key and code-generator seed.
func TestRefreshAfterAHostIsRemoved(t *testing.T) {
	x := newBox(t)
	old := x.snapshot()
	for _, a := range []Auth{{}, {Code: true}, {Local: true}} {
		if _, err := Refresh(x.b, a, x.rk, nil, nil); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("auth %+v: %v", a, err)
		}
	}
	r, err := Refresh(x.b, Auth{Code: true, Local: true}, x.rk, nil, nil)
	must(t, err)
	if old.opensLater(x) || bytes.Equal(x.secretNow(MACKeyName), old.mac) || bytes.Equal(x.secretNow(SeedName), old.seed) {
		t.Fatal("refresh kept an old secret")
	}
	if r.Enrollment == nil || r.Retrust != 1 {
		t.Fatalf("refresh result: %+v", r)
	}
	if _, _, err := x.restore(x.backup(), x.rk, t0); err != nil {
		t.Fatal(err)
	}
}

// The backup key's binding names the recovery slot's own salt, which a
// re-encryption keeps, so backups continue after one (Defect: P2-8).
func TestBackupsContinueAfterReencryption(t *testing.T) {
	x := newBox(t)
	if _, err := x.b.V.Reencrypt(Factor(x.rk)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := x.restore(x.backup(), x.rk, t0); err != nil {
		t.Fatal(err)
	}
	// A new recovery slot still breaks the binding.
	must(t, x.b.V.Rekey(Factor(x.rk), Factor(mustKey(t))))
	var buf bytes.Buffer
	if err := Backup(x.b, x.roots(), &buf, t0); err == nil {
		t.Fatal("backup sealed to a key bound to a replaced recovery slot")
	}
}

func mustRK(t *testing.T, s string) RecoveryKey {
	t.Helper()
	k, err := ParseRecoveryKey(s)
	must(t, err)
	return k
}
