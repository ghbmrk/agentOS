package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: REC-4

func TestEveryCardSecretRotatesAloneAsATier4Action(t *testing.T) {
	get := func(c Card, p Part) string {
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
	for _, p := range AllParts {
		x := newBox(t)
		for _, a := range []Auth{{}, {Code: true}, {Local: true}, {Recovery: mustKey(t)}} {
			if _, err := Rotate(x.b, []Part{p}, a, testGen, nil); !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("auth %+v: %v", a, err)
			}
		}
		nc, err := Rotate(x.b, []Part{p}, Auth{Code: true, Local: true}, testGen, nil)
		must(t, err)
		for _, q := range AllParts {
			if changed := get(nc, q) != get(x.card, q); changed != (q == p) {
				t.Errorf("rotating %s: %s changed=%v", p, q, changed)
			}
		}
		if nc.WiFiName != x.card.WiFiName {
			t.Errorf("rotating %s renamed the Wi-Fi", p)
		}
		stored, err := x.b.LoadCard()
		if err != nil || get(stored, p) != get(nc, p) {
			t.Errorf("rotating %s: vault card not updated: %v", p, err)
		}
		// The drive follows the card.
		switch p {
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

func TestRotateEverythingWithTheRecoveryKey(t *testing.T) {
	x := newBox(t)
	x.withPassphrase()
	nc, err := Rotate(x.b, AllParts, Auth{Recovery: x.rk}, testGen, nil)
	must(t, err)
	for _, p := range []string{nc.WiFiPassword, nc.SetupSecret, nc.VaultPassphrase, nc.RecoveryKey} {
		for _, o := range []string{x.card.WiFiPassword, x.card.SetupSecret, x.card.VaultPassphrase, x.card.RecoveryKey} {
			if p == o {
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
}

func TestRotationProtectsOnlyAgainstLaterCopies(t *testing.T) {
	x := newBox(t)
	bk := x.backup() // taken before rotation
	nc, err := Rotate(x.b, []Part{PartRecovery}, Auth{Code: true, Local: true}, testGen, nil)
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

// REQ: CRED-7

func TestCardSecretsAreRedactedFromAgentOutput(t *testing.T) {
	x := newBox(t)
	nc, err := Rotate(x.b, []Part{PartWiFi}, Auth{Code: true, Local: true}, testGen, nil)
	must(t, err)
	red, err := x.b.V.Redactor()
	must(t, err)
	for _, v := range []string{nc.WiFiPassword, nc.SetupSecret, nc.VaultPassphrase, nc.RecoveryKey} {
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
