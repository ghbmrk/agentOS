package recovery

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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
// which generates and prints them.
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

// storedCard is what the vault keeps of a card: the values the box runs
// on. The vault passphrase and the recovery key are never stored, so one
// vault read (a compromised vault process, or a TPM unlock and one code)
// yields no factor that opens copies of the drive or backups, or that
// survives rotating it.
type storedCard struct {
	WiFiName     string
	WiFiPassword string
	SetupSecret  string
	SetupCode    string
	GridSeed     []byte
}

// EncodeCard is the form the vault stores: the card without its vault
// passphrase and recovery key. Only the vault holds it (CRED-1).
func EncodeCard(c Card) ([]byte, error) {
	return json.Marshal(storedCard{c.WiFiName, c.WiFiPassword, c.SetupSecret, c.SetupCode, c.GridSeed})
}

// DecodeCard reads EncodeCard's output.
func DecodeCard(b []byte) (Card, error) {
	var s storedCard
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return Card{}, err
	}
	return Card{WiFiName: s.WiFiName, WiFiPassword: s.WiFiPassword, SetupSecret: s.SetupSecret, SetupCode: s.SetupCode, GridSeed: s.GridSeed}, nil
}

// Provision adds the recovery slot, the backup keys, and the card's
// stored values to a vault created with the card's passphrase
// (vault.CreateSealed), proving have: what the vault process writes at
// setup (§8.1). Codes and the grid follow from the card's grid seed and
// the code-generator seed already in the vault.
func Provision(b *Box, c Card, have vault.Factor) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	rk, err := ParseRecoveryKey(c.RecoveryKey)
	if err != nil {
		return err
	}
	if err := vault.Rekey(b.KeysPath, have, Factor(rk)); err != nil {
		return err
	}
	if err := storeBackupKey(b, rk); err != nil {
		return err
	}
	if err := ensureMACKey(b.V); err != nil {
		return err
	}
	return storeCard(b, c)
}

func storeCard(b *Box, c Card) error {
	if _, _, err := reserved(b.V, CardName, KindCard); err != nil {
		return err
	}
	enc, err := EncodeCard(c)
	if err != nil {
		return err
	}
	// Each stored secret is also its own entry, so the vault's redactor,
	// which matches whole values, covers it in agent-bound output (CRED-7).
	for name, v := range map[string]string{"wifi": c.WiFiPassword, "setup": c.SetupSecret} {
		if len(v) < vault.MinValueLen {
			return fmt.Errorf("recovery: card %s too short", name)
		}
		if _, _, err := reserved(b.V, CardName+"-"+name, KindCardPart); err != nil {
			return err
		}
		if err := b.V.Put(CardName+"-"+name, KindCardPart, []byte(v)); err != nil {
			return err
		}
	}
	return b.V.Put(CardName, KindCard, enc)
}

// PendingTTL bounds how long a generated card waits for the owner to
// confirm they saved it.
const PendingTTL = 30 * time.Minute

// Pending is a rotation generated but not yet in effect (REC-4). The local
// page shows Card() with a "Save card" download and asks for Prompt; the
// rotation takes effect only when the owner types that value back from
// the saved card (Commit), so the drive never runs on a card the owner
// does not hold. It lapses after PendingTTL or three wrong answers.
type Pending struct {
	// Prompt says which value of the new card to type back.
	Prompt string

	mu      sync.Mutex
	parts   map[Part]bool
	next    Card
	have    vault.Factor
	answer  string
	expires time.Time
	wrong   int
	done    bool
}

// Card is the new card to save and print. Secrets not being rotated are
// blank: the vault does not hold the passphrase or recovery key, and the
// owner keeps those parts of the old card.
func (p *Pending) Card() Card { return p.next }

// ErrLostCardParts is a lost-card rotation that keeps a factor the lost
// card carries.
var ErrLostCardParts = errors.New("recovery: without the current card, the passphrase and recovery key are both replaced")

// ErrPendingLapsed is a rotation that expired, was used, or was answered
// wrong three times. Nothing changed; start again.
var ErrPendingLapsed = errors.New("recovery: this new card has lapsed; nothing changed, start again")

// ErrConfirm is a typed-back value that does not match the new card.
var ErrConfirm = errors.New("recovery: that does not match the new card; check the saved copy")

// ErrCardNotStored is returned with the parts of a rotated card that are
// already in effect when a later step failed: the caller must still show
// that card, or the owner loses the new values.
var ErrCardNotStored = errors.New("recovery: part of the new card is in effect but was not saved; print it now")

// BeginRotate generates replacements for the chosen card secrets (REC-4).
// It is a tier-4 action (CH-3). Rewriting the passphrase or recovery slot
// needs a factor that opens the drive now: the current recovery key or
// passphrase typed from the old card, or the vault process's own TPM
// factor when the card is lost, in which case both the passphrase and the
// recovery key must be among the parts. When have is nil the recovery key
// in auth serves.
func BeginRotate(b *Box, parts []Part, auth Auth, have vault.Factor, gen Generator, r io.Reader, now time.Time) (*Pending, error) {
	if err := auth.check(b); err != nil {
		return nil, err
	}
	if len(parts) == 0 {
		return nil, errors.New("recovery: nothing to rotate")
	}
	set := map[Part]bool{}
	for _, p := range parts {
		switch p {
		case PartWiFi, PartSetup, PartPassphrase, PartGrid, PartRecovery:
			set[p] = true
		default:
			return nil, fmt.Errorf("recovery: unknown card part %q", p)
		}
	}
	if have == nil && auth.Recovery.Valid() {
		have = Factor(auth.Recovery)
	}
	if (set[PartPassphrase] || set[PartRecovery]) && !b.opensWith(have) {
		return nil, errors.New("recovery: replacing the passphrase or recovery key needs the current one from the card")
	}
	// No current card (proved by the box's own TPM slot): the lost card
	// may be in other hands, so both factors it carries are replaced.
	if have != nil && have.Kind() == vault.SlotTPM && !(set[PartPassphrase] && set[PartRecovery]) {
		return nil, ErrLostCardParts
	}
	cur, err := b.LoadCard()
	if err != nil {
		return nil, err
	}
	fresh, err := gen(r)
	if err != nil {
		return nil, err
	}
	next := Card{WiFiName: cur.WiFiName}
	if set[PartWiFi] {
		next.WiFiPassword = fresh.WiFiPassword
	}
	if set[PartSetup] {
		next.SetupSecret, next.SetupCode = fresh.SetupSecret, fresh.SetupCode
	}
	if set[PartPassphrase] {
		next.VaultPassphrase = fresh.VaultPassphrase
	}
	if set[PartGrid] {
		next.GridSeed = append([]byte(nil), fresh.GridSeed...)
	}
	if set[PartRecovery] {
		if _, err := ParseRecoveryKey(fresh.RecoveryKey); err != nil {
			return nil, err
		}
		next.RecoveryKey = fresh.RecoveryKey
	}
	p := &Pending{parts: set, next: next, have: have, expires: now.Add(PendingTTL)}
	switch {
	case set[PartRecovery]:
		p.Prompt = "Type the last group of the new recovery key."
		p.answer = next.RecoveryKey[strings.LastIndexByte(next.RecoveryKey, '-')+1:]
	case set[PartPassphrase]:
		p.Prompt = "Type the last word of the new vault passphrase."
		p.answer = next.VaultPassphrase[strings.LastIndexByte(next.VaultPassphrase, ' ')+1:]
	case set[PartWiFi]:
		p.Prompt = "Type the last four characters of the new Wi-Fi password."
		w := strings.ReplaceAll(next.WiFiPassword, "-", "")
		p.answer = w[len(w)-4:]
	case set[PartSetup]:
		p.Prompt = "Type the new setup code."
		p.answer = next.SetupCode
	default:
		p.Prompt = "Type the check code printed under the new grid."
		p.answer = GridCheck(next.GridSeed)
	}
	return p, nil
}

// GridCheck is a four-symbol code the card prints under a grid (P2-2), so
// a grid-only rotation can be confirmed from the saved card.
func GridCheck(seed []byte) string {
	k := hkdf(seed, nil, "agentos-grid-check-v1", 4)
	out := make([]byte, 4)
	for i, x := range k {
		out[i] = Alphabet[x&31]
	}
	return string(out)
}

func normalizeTyped(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '-' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, strings.ToUpper(s))
}

// Commit puts the rotation into effect once the owner types back the
// prompted value. The passphrase and recovery slots are rewritten first,
// then the backup key (bound to the new recovery slot), then the card's
// stored values. The caller applies a new Wi-Fi password to the access
// point last, with a note that devices must rejoin, and after a new grid
// clears spent cells (EndSession). If a step fails after the first slot
// is rewritten, Commit returns the parts already in effect with
// ErrCardNotStored. Rotation protects only against copies made
// afterwards: a drive copy or backup taken earlier still opens with the
// old passphrase or recovery key (CRED-8).
func (p *Pending) Commit(b *Box, typed string, now time.Time) (Card, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || p.wrong >= 3 || now.After(p.expires) {
		return Card{}, ErrPendingLapsed
	}
	if !hmac.Equal([]byte(normalizeTyped(typed)), []byte(normalizeTyped(p.answer))) {
		p.wrong++
		return Card{}, ErrConfirm
	}
	p.done = true
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, err := b.LoadCard()
	if err != nil {
		return Card{}, err
	}
	in := Card{WiFiName: cur.WiFiName}
	wrote := false
	fail := func(err error) (Card, error) {
		if wrote {
			return in, errors.Join(ErrCardNotStored, err)
		}
		return Card{}, err
	}
	have := p.have
	if p.parts[PartPassphrase] {
		next := vault.Passphrase(p.next.VaultPassphrase)
		if err := vault.Rekey(b.KeysPath, have, next); err != nil {
			return fail(err)
		}
		wrote = true
		in.VaultPassphrase = p.next.VaultPassphrase
		if have.Kind() == vault.SlotPassphrase {
			have = next
		}
	}
	if p.parts[PartRecovery] {
		nk, err := ParseRecoveryKey(p.next.RecoveryKey)
		if err != nil {
			return fail(err)
		}
		if err := vault.Rekey(b.KeysPath, have, Factor(nk)); err != nil {
			return fail(err)
		}
		wrote = true
		in.RecoveryKey = p.next.RecoveryKey
		if err := storeBackupKey(b, nk); err != nil {
			// The old backup key no longer matches the recovery slot, so
			// Backup refuses until it is rewritten (backupKey).
			return fail(err)
		}
		if err := keyChanged(b, now); err != nil {
			return fail(err)
		}
	}
	stored := cur
	if p.parts[PartWiFi] {
		stored.WiFiPassword = p.next.WiFiPassword
	}
	if p.parts[PartSetup] {
		stored.SetupSecret, stored.SetupCode = p.next.SetupSecret, p.next.SetupCode
	}
	if p.parts[PartGrid] {
		stored.GridSeed = p.next.GridSeed
	}
	if err := storeCard(b, stored); err != nil {
		return fail(err)
	}
	in.WiFiPassword, in.SetupSecret, in.SetupCode, in.GridSeed = p.next.WiFiPassword, p.next.SetupSecret, p.next.SetupCode, p.next.GridSeed
	return in, nil
}

// DoneNotes are the actions the local page offers after a rotation.
func DoneNotes(parts []Part) []string {
	var out []string
	for _, p := range parts {
		switch p {
		case PartRecovery:
			out = append(out, "Back up now. Backups made before today still open with your old card.")
		case PartPassphrase:
			out = append(out, "Copies of the drive made before now still open with the old passphrase. Destroy the old card's passphrase sheet.")
		case PartWiFi:
			out = append(out, "The box's Wi-Fi password changes now. Rejoin with the new card.")
		case PartGrid:
			out = append(out, "Destroy the old grid. Its cells no longer work.")
		}
	}
	return out
}
