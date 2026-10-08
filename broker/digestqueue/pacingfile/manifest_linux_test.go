//go:build linux

package pacingfile

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/grants"
)

// REQ: CH-15, CH-11, OP-1
func TestProvisionedManifestFileRoundTripPreservesStrictDebtAndAdmission(t *testing.T) {
	ledger, _ := sessionFixture(t)
	image := manifestImage(t, ledger, 2, 1000)
	file := ledger + ".settings"
	if err := os.WriteFile(file, image, 0600); err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(image)
	f, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := ReadProvisionedManifest(f, pin)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Mutating/replacing the source after decode cannot change this settings value.
	if err = os.WriteFile(file, manifestImage(t, ledger, 3, 1000), 0600); err != nil {
		t.Fatal(err)
	}
	var slot StartupSlot
	p, err := settings.Start(&slot, grants.Config{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	<-p.done
	if p.State() != StartupReady {
		t.Fatal("strict healthy image refused")
	}
	if err = p.Use(func(g *grants.Gate) error {
		if !g.Reserve(false) || !g.Reserve(false) || g.Reserve(false) {
			t.Fatal("decoded settings changed/limit lost")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if next, err := settings.Start(&slot, grants.Config{Now: time.Now}); next != nil || err != ErrStartupOccupied {
		t.Fatal("settings bypassed owner slot", err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Restore only the trusted fixture config bytes, not the accounting image.
	// Reopen validates the unchanged caller pin and spent ledger debt.
	f, err = os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ReadProvisionedManifest(f, pin); changed != nil || err != ErrManifest {
		t.Fatal("replacement accepted under old pin", err)
	}
	f.Close()
	settings, err = ReadProvisionedManifest(bytes.NewReader(image), pin)
	if err != nil {
		t.Fatal(err)
	}
	next, err := settings.Start(&slot, grants.Config{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	<-next.done
	if err = next.Use(func(g *grants.Gate) error {
		if g.PacingHealth() != nil || g.Reserve(false) {
			t.Fatal("manifest restart initialized fresh debt")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = slot.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// REQ: CH-15, CH-11
func TestProvisionedManifestMissingOrMismatchedLedgerRemainsHeldWithoutWrite(t *testing.T) {
	for _, kind := range []string{"missing", "different-limit"} {
		t.Run(kind, func(t *testing.T) {
			ledger, _ := sessionFixture(t)
			before, err := os.ReadFile(ledger)
			if err != nil {
				t.Fatal(err)
			}
			limit := 2
			if kind == "missing" {
				if err = os.Remove(ledger); err != nil {
					t.Fatal(err)
				}
			} else {
				limit = 3
			}
			b := manifestImage(t, ledger, limit, 1000)
			settings, err := ReadProvisionedManifest(bytes.NewReader(b), sha256.Sum256(b))
			if err != nil {
				t.Fatal(err)
			}
			var slot StartupSlot
			p, err := settings.Start(&slot, grants.Config{Now: time.Now})
			if err != nil {
				t.Fatal(err)
			}
			<-p.done
			defer slot.Drain(context.Background())
			if p.State() != StartupRecovery {
				t.Fatal("invalid ledger available")
			}
			if err = p.Use(func(g *grants.Gate) error {
				if g.PacingHealth() != grants.ErrPacingRecovery || g.Reserve(true) {
					t.Fatal("invalid ledger granted urgent permission")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(ledger)
			if kind == "missing" {
				if !os.IsNotExist(err) {
					t.Fatal("initialized missing image", err)
				}
			} else if err != nil || !bytes.Equal(before, after) {
				t.Fatal("mismatched allowance rewritten", err)
			}
		})
	}
}
