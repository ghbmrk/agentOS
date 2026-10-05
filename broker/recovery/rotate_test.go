package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-4

func cardPart(c Card, p Part) string {
	switch p {
	case PartWiFi:
		return c.WiFiPassword
	case PartSetup:
		return c.SetupSecret + c.SetupCode
	case PartPassphrase:
		return c.VaultPassphrase
	case PartGrid:
		return fmt.Sprintf("%x", c.GridSeed)
	}
	return c.RecoveryKey
}

func TestEveryCardSecretRotatesAloneAsATier4Action(t *testing.T) {
	for _, p := range AllParts {
		x := newBox(t)
		for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: mustKey(t)}} {
			if _, err := BeginRotate(x.b, []Part{p}, a, Factor(x.rk), testGen, nil, t0); !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("auth %+v: %v", a, err)
			}
		}
		nc, err := x.rotate([]Part{p}, Auth{Code: true, Local: true}, Factor(x.rk))
		must(t, err)
		// The new card carries the rotated part; the rest are blank (the
		// owner keeps those parts of the old card).
		for _, q := range AllParts {
			got := cardPart(nc, q)
			if q == p && (got == "" || got == cardPart(x.card, q)) {
				t.Errorf("rotating %s: not replaced", p)
			}
			if q != p && got != "" {
				t.Errorf("rotating %s: %s is on the new card", p, q)
			}
		}
		if nc.WiFiName != x.card.WiFiName {
			t.Errorf("rotating %s renamed the Wi-Fi", p)
		}
		stored, err := x.b.LoadCard()
		must(t, err)
		switch p {
		case PartWiFi, PartSetup, PartGrid:
			if cardPart(stored, p) != cardPart(nc, p) {
				t.Errorf("rotating %s: vault card not updated", p)
			}
		case PartPassphrase:
			if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(nc.VaultPassphrase)); err != nil {
				t.Errorf("new passphrase does not open the drive: %v", err)
			}
		case PartRecovery:
			if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(x.rk)); err == nil {
				t.Error("old recovery key still opens the drive")
			}
			nk, _ := ParseRecoveryKey(nc.RecoveryKey)
			if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(nk)); err != nil {
				t.Errorf("new recovery key does not open the drive: %v", err)
			}
		}
	}
}

// Replacing a factor needs one that opens the drive now: the old card's
// value, or the vault process's TPM factor when the card is lost.
func TestReplacingAFactorNeedsAFactorThatOpensTheDrive(t *testing.T) {
	x := newBox(t)
	for _, have := range []vault.Factor{nil, Factor(mustKey(t)), vault.Passphrase("not the passphrase at all")} {
		if _, err := BeginRotate(x.b, []Part{PartRecovery}, Auth{Code: true, Local: true}, have, testGen, nil, t0); err == nil {
			t.Fatalf("rotated with %v", have)
		}
	}
	// Card lost: the box's own TPM slot proves the drive.
	nc, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, fakeTPM{[]byte("sealed-to-host-a-tpm")})
	must(t, err)
	nk, _ := ParseRecoveryKey(nc.RecoveryKey)
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, Factor(nk)); err != nil {
		t.Fatal(err)
	}
	// Parts that rewrite no slot need no factor.
	_, err = x.rotate([]Part{PartWiFi, PartGrid}, Auth{Code: true, Local: true}, nil)
	must(t, err)
}

// Nothing changes until the owner types a value back from the saved card.
func TestRotationTakesEffectOnlyWhenTheOwnerHasTheNewCard(t *testing.T) {
	x := newBox(t)
	keys, _ := os.ReadFile(x.b.KeysPath)
	p, err := BeginRotate(x.b, AllParts, Auth{Recovery: x.rk}, nil, testGen, nil, t0)
	must(t, err)
	if !strings.Contains(p.Prompt, "recovery key") {
		t.Fatalf("prompt: %q", p.Prompt)
	}
	now, _ := os.ReadFile(x.b.KeysPath)
	stored, _ := x.b.LoadCard()
	if !bytes.Equal(keys, now) || stored.WiFiPassword != x.card.WiFiPassword {
		t.Fatal("generating a card changed the drive")
	}
	for i := 0; i < 2; i++ {
		if _, err := p.Commit(x.b, "WRONG", t0); !errors.Is(err, ErrConfirm) {
			t.Fatalf("wrong answer: %v", err)
		}
	}
	nc, err := p.Commit(x.b, strings.ToLower(p.answer), t0.Add(time.Minute))
	must(t, err)
	if !strings.HasSuffix(nc.RecoveryKey, p.answer) {
		t.Fatal("typed back the wrong group")
	}
	if _, err := p.Commit(x.b, p.answer, t0); !errors.Is(err, ErrPendingLapsed) {
		t.Fatalf("committed twice: %v", err)
	}
	// Three wrong answers, or the time limit, discard it.
	nk, _ := ParseRecoveryKey(nc.RecoveryKey)
	q, err := BeginRotate(x.b, []Part{PartGrid}, Auth{Recovery: nk}, nil, testGen, nil, t0)
	must(t, err)
	if q.answer != GridCheck(q.Card().GridSeed) {
		t.Fatal("grid-only rotation is not confirmed by the grid's check code")
	}
	for i := 0; i < 3; i++ {
		q.Commit(x.b, "WRONG", t0)
	}
	if _, err := q.Commit(x.b, q.answer, t0); !errors.Is(err, ErrPendingLapsed) {
		t.Fatalf("after three wrong: %v", err)
	}
	r, err := BeginRotate(x.b, []Part{PartWiFi}, Auth{Recovery: nk}, nil, testGen, nil, t0)
	must(t, err)
	if _, err := r.Commit(x.b, r.answer, t0.Add(PendingTTL+time.Second)); !errors.Is(err, ErrPendingLapsed) {
		t.Fatalf("after the time limit: %v", err)
	}
}

// failing is a factor that stops opening the drive once the key-slot file
// changes, so the second slot rewrite of a rotation fails.
type failing struct {
	vault.Factor
	path string
	orig []byte
}

func (f failing) KEK(s vault.Slot) ([]byte, error) {
	if now, _ := os.ReadFile(f.path); !bytes.Equal(now, f.orig) {
		return nil, vault.ErrNoSlotOpens
	}
	return f.Factor.KEK(s)
}

func TestAPartialRotationReturnsWhatIsInEffect(t *testing.T) {
	x := newBox(t)
	orig, _ := os.ReadFile(x.b.KeysPath)
	p, err := BeginRotate(x.b, []Part{PartPassphrase, PartRecovery, PartWiFi}, Auth{Code: true, Local: true},
		failing{Factor(x.rk), x.b.KeysPath, orig}, testGen, nil, t0)
	must(t, err)
	nc, err := p.Commit(x.b, p.answer, t0)
	if !errors.Is(err, ErrCardNotStored) {
		t.Fatalf("partial rotation: %v", err)
	}
	if nc.VaultPassphrase != p.Card().VaultPassphrase || nc.RecoveryKey != "" || nc.WiFiPassword != "" {
		t.Fatal("returned card does not match what is in effect")
	}
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(nc.VaultPassphrase)); err != nil {
		t.Fatal(err)
	}
	// Backups still go to the recovery key that still opens the drive.
	bk := x.backup()
	if _, _, err := x.restore(bk, x.rk, t0); err != nil {
		t.Fatal(err)
	}
}

func TestRotateEverythingWithTheRecoveryKey(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	nc, err := x.rotate(AllParts, Auth{Recovery: x.rk}, nil)
	must(t, err)
	for _, p := range []string{nc.WiFiPassword, nc.SetupSecret, nc.VaultPassphrase, nc.RecoveryKey} {
		for _, o := range []string{x.card.WiFiPassword, x.card.SetupSecret, x.card.VaultPassphrase, x.card.RecoveryKey} {
			if p == "" || p == o {
				t.Fatal("rotate-all kept a value")
			}
		}
	}
	if bytes.Equal(nc.GridSeed, x.card.GridSeed) {
		t.Fatal("rotate-all kept the grid")
	}
	if _, err := vault.OpenSealed(x.b.VaultPath, x.b.KeysPath, vault.Passphrase(x.card.VaultPassphrase)); err == nil {
		t.Fatal("old passphrase still opens the drive")
	}
	// A new grid forgets the old grid's spent cells and ends the session.
	store := owner.FileStore{Path: filepath.Join(x.dir, "broker", "owner.json")}
	must(t, EndSession(store, true))
	st, err := store.Load()
	if err != nil || len(st.GridUsed) != 0 || !st.UnlockedUntil.IsZero() {
		t.Fatalf("owner state after a new grid: %+v %v", st, err)
	}
	for _, s := range []string{nc.String(), nc.GoString(), fmt.Sprintf("%v %+v", nc, nc)} {
		if strings.Contains(s, nc.VaultPassphrase) || strings.Contains(s, nc.WiFiPassword) {
			t.Fatalf("card formats a secret: %q", s)
		}
	}
	if len(DoneNotes(AllParts)) != 4 {
		t.Fatal("done page notes")
	}
}

func TestRotationProtectsOnlyAgainstLaterCopies(t *testing.T) {
	x := newBox(t)
	bk := x.backup() // taken before rotation
	nc, err := x.rotate([]Part{PartRecovery}, Auth{Code: true, Local: true}, Factor(x.rk))
	must(t, err)
	nk, _ := ParseRecoveryKey(nc.RecoveryKey)
	// CRED-8: the earlier backup still opens with the old key, as the
	// owner's guide says; a backup taken now needs the new one.
	if _, _, err := x.restore(bk, x.rk, t0); err != nil {
		t.Fatalf("old backup, old key: %v", err)
	}
	bk2 := x.backup()
	if _, _, err := x.restore(bk2, x.rk, t0); err == nil {
		t.Fatal("new backup opened with the rotated-out key")
	}
	if _, _, err := x.restore(bk2, nk, t0); err != nil {
		t.Fatalf("new backup, new key: %v", err)
	}
}

// REQ: CRED-1, REC-1

// The vault never holds a factor that opens the drive or its backups: one
// vault read must not outlive a rotation or open past backups.
func TestTheVaultHoldsNeitherTheRecoveryKeyNorThePassphrase(t *testing.T) {
	x := newBox(t)
	nc, err := x.rotate([]Part{PartPassphrase, PartRecovery}, Auth{Recovery: x.rk}, nil)
	must(t, err)
	nk, _ := ParseRecoveryKey(nc.RecoveryKey)
	var bad [][]byte
	for _, v := range []string{x.card.RecoveryKey, x.card.VaultPassphrase, nc.RecoveryKey, nc.VaultPassphrase} {
		bad = append(bad, []byte(v), []byte(normalizeTyped(v)))
	}
	bad = append(bad, x.rk.b[:], nk.b[:])
	for _, e := range x.b.V.List() {
		s, _ := x.b.V.Secret(e.Name)
		for _, b := range bad {
			if bytes.Contains([]byte(s.Reveal()), b) {
				t.Fatalf("vault entry %s holds a factor", e.Name)
			}
		}
	}
	if c, _ := x.b.LoadCard(); c.RecoveryKey != "" || c.VaultPassphrase != "" {
		t.Fatal("stored card carries a factor")
	}
}

// REQ: REC-1, REC-2, CRED-1

// Reserved entries are read only under their own kind; a value written
// under a reserved name as another kind fails closed.
func TestReservedEntriesOfAnotherKindFailClosed(t *testing.T) {
	x := newBox(t)
	attacker := mustKey(t)
	pub, _ := backupPublic(attacker)
	must(t, x.b.V.Put(BackupKeyName, vault.KindAPIKey, append(pub, pub...)))
	var buf bytes.Buffer
	if err := Backup(x.b, x.roots(), &buf, t0); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("backup with a wrong-kind key: %v", err)
	}
	// The right kind but bound to another recovery slot is refused too.
	y := newBox(t)
	other, _ := y.b.V.Secret(BackupKeyName)
	must(t, x.b.V.Put(BackupKeyName, KindBackupKey, []byte(other.Reveal())))
	if err := Backup(x.b, x.roots(), &buf, t0); err == nil {
		t.Fatal("backup sealed to a key bound to another slot")
	}
	z := newBox(t)
	must(t, z.b.V.Put(MACKeyName, vault.KindAPIKey, make([]byte, 32)))
	if err := Backup(z.b, z.roots(), &buf, t0); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("backup with a wrong-kind MAC key: %v", err)
	}
	must(t, z.b.V.Put(CardName, vault.KindAPIKey, []byte(`{"WiFiName":"attacker-network"}`)))
	if _, err := z.b.LoadCard(); !errors.Is(err, ErrWrongKind) {
		t.Fatalf("card of the wrong kind: %v", err)
	}
}

// REQ: CRED-7

func TestCardSecretsAreRedactedFromAgentOutput(t *testing.T) {
	x := newBox(t)
	nc, err := x.rotate([]Part{PartWiFi}, Auth{Code: true, Local: true}, nil)
	must(t, err)
	red, err := x.b.V.Redactor()
	must(t, err)
	for _, v := range []string{nc.WiFiPassword, x.card.SetupSecret} {
		out := string(red.Redact([]byte("the agent saw " + v + " somewhere")))
		if strings.Contains(out, v) {
			t.Fatalf("card secret not redacted: %q", out)
		}
	}
	// The rotated-out Wi-Fi password is no longer a vault value.
	if s, ok := x.b.V.Secret(CardName + "-wifi"); !ok || s.Reveal() != nc.WiFiPassword {
		t.Fatal("card part entry not updated")
	}
}
