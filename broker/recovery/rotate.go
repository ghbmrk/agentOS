package recovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/ghbmrk/agentos/broker/vault"
)

// Part is one Owner Card secret (REC-4).
type Part string

const (
	PartWiFi       Part = "wifi"
	PartSetup      Part = "setup"
	PartPassphrase Part = "passphrase"
	PartGrid       Part = "grid"
	PartRecovery   Part = "recovery"
)

// AllParts is every card secret, for setup's one-line "replace everything
// on this card" offer for kits others may have handled (REC-4).
var AllParts = []Part{PartWiFi, PartSetup, PartPassphrase, PartGrid, PartRecovery}

// Card holds one Owner Card's values, field for field as card.Card (P2-2),
// which generates and prints them. The vault keeps the whole card, so
// rotating one part prints a whole new card; whoever can read it already
// holds the data key, which every part but the Wi-Fi password protects.
type Card struct {
	WiFiName        string
	WiFiPassword    string
	SetupSecret     string
	SetupCode       string
	VaultPassphrase string
	GridSeed        []byte
	RecoveryKey     string
}

// String keeps card secrets out of logs.
func (Card) String() string { return "[owner card]" }

// GoString keeps card secrets out of logs.
func (Card) GoString() string { return "[owner card]" }

// Generator makes a fresh card: card.Generate (P2-2) on the box.
type Generator func(io.Reader) (*Card, error)

// EncodeCard is the form the vault stores. Only the vault holds it
// (CRED-1).
func EncodeCard(c Card) ([]byte, error) { return json.Marshal(c) }

// DecodeCard reads EncodeCard's output.
func DecodeCard(b []byte) (Card, error) {
	var c Card
	err := json.Unmarshal(b, &c)
	return c, err
}

// Provision adds the recovery slot and stores the card in a vault created
// with the card's passphrase (vault.CreateSealed), proving have: what the
// vault process writes at setup (§8.1). Codes and the grid follow from
// the card's grid seed and the code-generator seed already in the vault.
func Provision(b *Box, c Card, have vault.Factor) error {
	rk, err := ParseRecoveryKey(c.RecoveryKey)
	if err != nil {
		return err
	}
	if err := vault.Rekey(b.KeysPath, have, Factor(rk)); err != nil {
		return err
	}
	return storeCard(b, c, rk)
}

func storeCard(b *Box, c Card, rk RecoveryKey) error {
	enc, err := EncodeCard(c)
	if err != nil {
		return err
	}
	if err := b.V.Put(CardName, KindCard, enc); err != nil {
		return err
	}
	// Each printed secret is also its own entry, so the vault's redactor,
	// which matches whole values, covers it in agent-bound output (CRED-7).
	for name, v := range map[string]string{"wifi": c.WiFiPassword, "setup": c.SetupSecret,
		"passphrase": c.VaultPassphrase, "recovery": c.RecoveryKey} {
		if len(v) < vault.MinValueLen {
			return fmt.Errorf("recovery: card %s too short", name)
		}
		if err := b.V.Put(CardName+"-"+name, KindCardPart, []byte(v)); err != nil {
			return err
		}
	}
	pub, err := backupPublic(rk)
	if err != nil {
		return err
	}
	return b.V.Put(BackupKeyName, KindBackupKey, pub)
}

// ErrCardNotStored is returned with a rotated card whose new slots are
// already written but which the vault could not store: the caller must
// still show the card, or the owner loses the new values.
var ErrCardNotStored = errors.New("recovery: the new card is in effect but was not saved; print it now")

// Rotate replaces the chosen card secrets (REC-4). It is a tier-4 action
// (CH-3). The vault's passphrase and recovery slots are rewritten first,
// then the new card is stored. It returns the new card for the local page
// to print. The caller applies a new Wi-Fi password to the access point
// and, after a new grid, clears spent cells (EndSession). Rotation
// protects only against copies made afterwards: a drive copy or backup
// taken earlier still opens with the old passphrase or recovery key
// (CRED-8), so after a suspected loss the owner also rotates the
// credentials in the vault.
func Rotate(b *Box, parts []Part, auth Auth, gen Generator, r io.Reader) (Card, error) {
	if err := auth.check(b); err != nil {
		return Card{}, err
	}
	if len(parts) == 0 {
		return Card{}, errors.New("recovery: nothing to rotate")
	}
	cur, err := b.LoadCard()
	if err != nil {
		return Card{}, err
	}
	curKey, err := ParseRecoveryKey(cur.RecoveryKey)
	if err != nil {
		return Card{}, err
	}
	fresh, err := gen(r)
	if err != nil {
		return Card{}, err
	}
	next := cur
	next.GridSeed = append([]byte(nil), cur.GridSeed...)
	for _, p := range parts {
		switch p {
		case PartWiFi:
			next.WiFiPassword = fresh.WiFiPassword
		case PartSetup:
			next.SetupSecret, next.SetupCode = fresh.SetupSecret, fresh.SetupCode
		case PartPassphrase:
			next.VaultPassphrase = fresh.VaultPassphrase
		case PartGrid:
			next.GridSeed = append([]byte(nil), fresh.GridSeed...)
		case PartRecovery:
			next.RecoveryKey = fresh.RecoveryKey
		default:
			return Card{}, fmt.Errorf("recovery: unknown card part %q", p)
		}
	}
	nextKey, err := ParseRecoveryKey(next.RecoveryKey)
	if err != nil {
		return Card{}, err
	}
	// The current recovery key proves the drive for each rewrite: it is
	// in the vault, and unlike the passphrase it costs no Argon2id run.
	if next.VaultPassphrase != cur.VaultPassphrase {
		if err := vault.Rekey(b.KeysPath, Factor(curKey), vault.Passphrase(next.VaultPassphrase)); err != nil {
			return Card{}, err
		}
	}
	if next.RecoveryKey != cur.RecoveryKey {
		if err := vault.Rekey(b.KeysPath, Factor(curKey), Factor(nextKey)); err != nil {
			return Card{}, err
		}
	}
	if err := storeCard(b, next, nextKey); err != nil {
		return next, ErrCardNotStored
	}
	return next, nil
}
