package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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
	lostParts := []Part{PartPassphrase, PartRecovery, PartSetup, PartGrid}
	for i := 2; i < len(lostParts); i++ {
		kept := append(append([]Part(nil), lostParts[:i]...), lostParts[i+1:]...)
		if _, err := BeginRotate(x.b, kept, Auth{Code: true, Local: true}, tpm, testGen, nil, t0); !errors.Is(err, ErrLostCardParts) {
			t.Fatalf("lost card kept %s: %v", lostParts[i], err)
		}
	}
	done, err := x.rotate(lostParts, Auth{Code: true, Local: true}, tpm)
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
	notes := strings.Join(DoneNotes(lostParts, true), " ")
	for _, want := range []string{"nothing made from now on", "Delete the old AgentOS entry"} {
		if !strings.Contains(notes, want) {
			t.Fatalf("lost-card done notes miss %q: %s", want, notes)
		}
	}
}

// A recovery-key change with the card in hand re-encrypts and replaces the
// MAC key and the code-generator seed (security C1 on #64).
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
	if bytes.Equal(x.secretNow(SeedName), old.seed) || done.Enrollment == nil {
		t.Fatal("a recovery-key rotation kept the code generator")
	}
	if !strings.Contains(strings.Join(DoneNotes([]Part{PartRecovery}, false), " "), ResetNote) {
		t.Fatal("no reset note")
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
		if _, err := Refresh(x.b, a, x.rk, nil, nil, t0); !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("auth %+v: %v", a, err)
		}
	}
	r, err := Refresh(x.b, Auth{Code: true, Local: true}, x.rk, nil, nil, t0)
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

// The rotation is final only once a code from the new seed is confirmed:
// until then the page can show the seed again, on the box's Wi-Fi page to
// the holder of the new recovery key only, and wrong codes are bounded
// (UX-64-1, L3 F2 on #64).
func TestTheNewCodeGeneratorIsConfirmedWithACode(t *testing.T) {
	x := newBox(t)
	if _, err := ShowEnrollment(x.b, x.rk, true); !errors.Is(err, ErrNoEnrollment) {
		t.Fatalf("enrollment shown before any reset: %v", err)
	}
	done, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)
	nk := mustRK(t, done.RecoveryKey)
	if !EnrollmentPending(x.b) {
		t.Fatal("no pending enrollment after a reset")
	}
	// Refused: off the Wi-Fi page, with the old card's key, with any other.
	for _, c := range []struct {
		rk    RecoveryKey
		local bool
	}{{nk, false}, {x.rk, true}, {mustKey(t), true}, {RecoveryKey{}, true}} {
		if _, err := ShowEnrollment(x.b, c.rk, c.local); err == nil {
			t.Fatalf("seed shown with %+v", c.local)
		}
	}
	again, err := ShowEnrollment(x.b, nk, true)
	must(t, err)
	if again.URI != done.Enrollment.URI {
		t.Fatal("shown again with another seed")
	}
	seed := x.secretNow(SeedName)
	if _, err := ConfirmEnrollment(x.b, totp(seed, t0), false, t0); err == nil {
		t.Fatal("confirmed off the Wi-Fi page")
	}
	wrong := []string{totp(x.seed, t0), totp(seed, t0.Add(5*time.Minute)), "000000x", "000000", "111111"}
	for _, code := range wrong {
		if ok, err := ConfirmEnrollment(x.b, code, true, t0); ok || err != nil {
			t.Fatalf("confirmed with %q: %v", code, err)
		}
	}
	// The bound holds even for the right code, until the seed is shown
	// again with the recovery key.
	if ok, err := ConfirmEnrollment(x.b, totp(seed, t0), true, t0); ok || !errors.Is(err, ErrEnrollTries) {
		t.Fatalf("past the bound: %v %v", ok, err)
	}
	_, err = ShowEnrollment(x.b, nk, true)
	must(t, err)
	if ok, err := ConfirmEnrollment(x.b, totp(seed, t0.Add(-30*time.Second)), true, t0); !ok || err != nil {
		t.Fatalf("a current code was refused: %v", err)
	}
	if EnrollmentPending(x.b) {
		t.Fatal("still pending after the code matched")
	}
	if _, err := ShowEnrollment(x.b, nk, true); !errors.Is(err, ErrNoEnrollment) {
		t.Fatalf("seed shown after confirmation: %v", err)
	}
}

// The enrollment marker is written before the seed: a crash between them
// leaves the old seed marked, never a new seed unmarked (L3 F1).
func TestTheEnrollmentMarkerPrecedesTheNewSeed(t *testing.T) {
	x := newBox(t)
	crashed := errors.New("crash")
	var marked bool
	crashPoint = func(step string) error {
		marked = EnrollmentPending(x.b) && bytes.Equal(x.secretNow(SeedName), x.seed)
		return crashed
	}
	t.Cleanup(func() { crashPoint = func(string) error { return nil } })
	_, err := Refresh(x.b, Auth{Code: true, Local: true}, x.rk, nil, nil, t0)
	if !errors.Is(err, crashed) || !marked {
		t.Fatalf("marker before seed: %v %v", err, marked)
	}
	// The interrupted Refresh is owed: backups wait for it, and the page
	// offers Finish securing the box (security R2), which completes it.
	if parts, ok := RotationUnfinished(x.b); !ok || fmt.Sprint(parts) != "[refresh]" {
		t.Fatalf("owed after a crash: %v", parts)
	}
	var buf bytes.Buffer
	if err := Backup(x.b, x.roots(), &buf, t0); !errors.Is(err, ErrRotationUnfinished) {
		t.Fatalf("backup during an unfinished refresh: %v", err)
	}
	crashPoint = func(string) error { return nil }
	_, err = Refresh(x.b, Auth{Code: true, Local: true}, x.rk, nil, nil, t0)
	must(t, err)
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after Refresh finished")
	}
}

// A typed passphrase that is not the proof is checked before anything
// changes (L3 F5).
func TestAMistypedPassphraseChangesNothing(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	keys, _ := os.ReadFile(x.b.KeysPath)
	if _, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk, Passphrase: []byte("tulip orbit mosaic typo")}, testGen, nil, t0); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("mistyped passphrase: %v", err)
	}
	if _, err := Refresh(x.b, Auth{Code: true, Local: true}, x.rk, []byte("tulip orbit mosaic typo"), nil, t0); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("refresh with a mistyped passphrase: %v", err)
	}
	if now, _ := os.ReadFile(x.b.KeysPath); !bytes.Equal(now, keys) {
		t.Fatal("keys file changed")
	}
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marked")
	}
}

// A marker that cannot be read owes everything (L3 minor).
func TestAnUnreadableRotationMarkerFailsClosed(t *testing.T) {
	x := newBox(t)
	must(t, x.b.V.Put(RotationName, KindRotation, []byte("{this is not json")))
	if parts, ok := RotationUnfinished(x.b); !ok || len(parts) != len(AllParts)+1 {
		t.Fatalf("unreadable marker: %v %v", parts, ok)
	}
	if _, err := x.rotate([]Part{PartPassphrase, PartRecovery}, Auth{Code: true, Local: true}, Proof{Recovery: x.rk}); !errors.Is(err, ErrRotationOwed) {
		t.Fatalf("narrow rotation: %v", err)
	}
	_, err := x.rotate(AllParts, Auth{Code: true, Local: true}, Proof{Recovery: x.rk})
	must(t, err)
	if _, ok := RotationUnfinished(x.b); ok {
		t.Fatal("marker left after rotating everything")
	}
}

// The done page names what an older copy still exposes and which PCs to
// trust again (security R1, UX-64-2 on #64).
func TestDonePageLines(t *testing.T) {
	x := newBox(t)
	if n := ExposedNote(x.b); !strings.Contains(n, "(openai)") || strings.Contains(n, SeedName) || strings.Contains(n, MACKeyName) {
		t.Fatalf("exposed note: %q", n)
	}
	for _, c := range []struct {
		n     int
		names []string
		want  string
	}{
		{0, nil, ""},
		{1, []string{"study-pc"}, "1 other PC (study-pc) must be trusted again: on each, open the box page, unlock, and tick Keep this PC trusted."},
		{3, nil, "3 other PCs must be trusted again: on each, open the box page, unlock, and tick Keep this PC trusted."},
	} {
		if got := RetrustNote(c.n, c.names); got != c.want {
			t.Fatalf("retrust %d: %q", c.n, got)
		}
	}
}
