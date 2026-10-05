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

	"github.com/ghbmrk/agentos/broker/owner"
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
	if err := b.V.Rekey(have, Factor(rk)); err != nil {
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
	proof   Proof
	answer  string
	expires time.Time
	wrong   int
	done    bool
}

// Card is the new card to save and print. Secrets not being rotated are
// blank: the vault does not hold the passphrase or recovery key, and the
// owner keeps those parts of the old card.
func (p *Pending) Card() Card { return p.next }

// ErrLostCardParts is a lost-card rotation that keeps a factor or the
// setup secret the lost card carries, or the grid, whose seed an earlier
// copy of the drive holds.
var ErrLostCardParts = errors.New("recovery: without the current card, the passphrase, recovery key, setup secret and grid are all replaced")

// LostCardWiFiNote goes beside the Wi-Fi part on a lost-card rotation,
// which the page ticks in advance but the owner may untick.
const LostCardWiFiNote = "Whoever finds your card could join the box's Wi-Fi. Your devices will need the new password."

// ErrNeedPassphrase is a recovery-key rotation, with the card in hand, on
// a drive with a passphrase slot but no passphrase given: re-encryption
// rewraps that slot, so it must be proved too.
var ErrNeedPassphrase = errors.New("recovery: replacing the recovery key also needs the vault passphrase from the card")

// ErrPendingLapsed is a rotation that expired, was used, or was answered
// wrong three times. Nothing changed; start again.
var ErrPendingLapsed = errors.New("recovery: this new card has lapsed; nothing changed, start again")

// ErrConfirm is a typed-back value that does not match the new card.
var ErrConfirm = errors.New("recovery: that does not match the new card; check the saved copy")

// ErrCardNotStored is returned with the parts of a rotated card that are
// already in effect when a later step failed: the caller must still show
// that card, or the owner loses the new values.
var ErrCardNotStored = errors.New("recovery: part of the new card is in effect but was not saved; print it now")

// Proof is what opens the drive now, for rewriting its slots: the current
// recovery key or passphrase typed from the old card, or, when the card is
// lost, the vault process's own TPM factor. The vault wipes a factor's
// secret bytes after each call, so a fresh factor is built for each use.
type Proof struct {
	Recovery RecoveryKey
	// Passphrase is the typed passphrase; Pending wipes its copy when the
	// rotation commits or lapses.
	Passphrase []byte
	// Host builds the vault process's TPM factor afresh on each call.
	Host func() vault.Factor
}

func (p Proof) factor() vault.Factor {
	switch {
	case p.Recovery.Valid():
		return Factor(p.Recovery)
	case len(p.Passphrase) > 0:
		return vault.Passphrase(string(p.Passphrase))
	case p.Host != nil:
		return p.Host()
	}
	return nil
}

// lost reports a proof without the current card.
func (p Proof) lost() bool { return !p.Recovery.Valid() && len(p.Passphrase) == 0 && p.Host != nil }

// BeginRotate generates replacements for the chosen card secrets (REC-4).
// It is a tier-4 action (CH-3). Rewriting the passphrase or recovery slot
// needs proof that opens the drive now; when the card is lost (proved by
// the host), both the passphrase and the recovery key must be among the
// parts. An empty proof takes the recovery key in auth.
func BeginRotate(b *Box, parts []Part, auth Auth, proof Proof, gen Generator, r io.Reader, now time.Time) (*Pending, error) {
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
	if proof.factor() == nil && auth.Recovery.Valid() {
		proof.Recovery = auth.Recovery
	}
	if (set[PartPassphrase] || set[PartRecovery]) && !b.opensWith(proof.factor()) {
		return nil, errors.New("recovery: replacing the passphrase or recovery key needs the current one from the card")
	}
	// No current card: the lost card may be in other hands, so both
	// factors it carries are replaced, and its setup secret (ID-1), and
	// the grid, which an earlier copy of the drive holds the seed of, as
	// it does the code-generator seed that Commit replaces (R10a).
	if proof.lost() && !(set[PartPassphrase] && set[PartRecovery] && set[PartSetup] && set[PartGrid]) {
		return nil, ErrLostCardParts
	}
	// A new recovery key re-encrypts, which rewraps the passphrase slot
	// too: it needs the passphrase, typed or replaced here.
	if set[PartRecovery] && !set[PartPassphrase] && len(proof.Passphrase) == 0 && hasSlot(b, vault.SlotPassphrase) {
		return nil, ErrNeedPassphrase
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
	// Pending keeps its own copy of a typed passphrase, wiped when done.
	proof.Passphrase = append([]byte(nil), proof.Passphrase...)
	p := &Pending{parts: set, next: next, proof: proof, expires: now.Add(PendingTTL)}
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

// hasSlot reports whether the drive has a slot of kind; an unreadable
// keys file counts as having one, so the check fails closed.
func hasSlot(b *Box, kind string) bool {
	slots, err := vault.ReadSlots(b.KeysPath)
	if err != nil {
		return true
	}
	for _, s := range slots {
		if s.Kind == kind {
			return true
		}
	}
	return false
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
//
// A new recovery key or a lost card re-encrypts (R10a; egress V7): once
// the slots are replaced, the vault moves to a fresh data key with every
// slot rewrapped (Box.Reencrypt) and gets a new backup MAC key, so the
// old factors with an earlier copy open nothing written afterwards. It
// also replaces the code-generator seed, which an earlier copy holds; the
// page shows Done.Enrollment until ConfirmEnrollment accepts a code from
// it, and the caller ends the owner channel's session. A passphrase change with the card in hand does not
// re-encrypt (arbitrator ruling on #45).
func (p *Pending) Commit(b *Box, typed string, now time.Time) (Done, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || p.wrong >= 3 || now.After(p.expires) {
		p.lapse()
		return Done{}, ErrPendingLapsed
	}
	if !hmac.Equal([]byte(normalizeTyped(typed)), []byte(normalizeTyped(p.answer))) {
		p.wrong++
		if p.wrong >= 3 {
			p.lapse()
		}
		return Done{}, ErrConfirm
	}
	p.done = true
	defer p.lapse()
	b.mu.Lock()
	defer b.mu.Unlock()
	cur, err := b.LoadCard()
	if err != nil {
		return Done{}, err
	}
	in := Card{WiFiName: cur.WiFiName}
	wrote := false
	fail := func(err error) (Done, error) {
		if wrote {
			return Done{Card: in}, errors.Join(ErrCardNotStored, err)
		}
		return Done{}, err
	}
	proof := p.proof
	var slots []Part
	for _, q := range []Part{PartPassphrase, PartRecovery} {
		if p.parts[q] {
			slots = append(slots, q)
		}
	}
	if len(slots) > 0 {
		// Recorded before the first slot write and cleared only when a
		// rotation covering these parts completes, so a crash or failure
		// between the writes is not silent: Backup refuses meanwhile and
		// the page asks to rotate again.
		if err := markRotation(b, slots, now); err != nil {
			return Done{}, err
		}
	}
	if p.parts[PartPassphrase] {
		if err := b.V.Rekey(proof.factor(), vault.Passphrase(p.next.VaultPassphrase)); err != nil {
			return fail(err)
		}
		wrote = true
		in.VaultPassphrase = p.next.VaultPassphrase
		if len(proof.Passphrase) > 0 {
			proof.Passphrase = []byte(p.next.VaultPassphrase)
			defer wipe(proof.Passphrase)
		}
	}
	var done Done
	if p.parts[PartRecovery] {
		nk, err := ParseRecoveryKey(p.next.RecoveryKey)
		if err != nil {
			return fail(err)
		}
		if err := b.V.Rekey(proof.factor(), Factor(nk)); err != nil {
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
		// BeginRotate saw to it that the owner factors prove every
		// passphrase and recovery slot: a lost card replaced both, and
		// otherwise the passphrase was replaced, typed, or has no slot.
		owner := []vault.Factor{Factor(nk)}
		switch {
		case p.parts[PartPassphrase]:
			owner = append(owner, vault.Passphrase(p.next.VaultPassphrase))
		case len(proof.Passphrase) > 0:
			owner = append(owner, vault.Passphrase(string(proof.Passphrase)))
		}
		r, err := refresh(b, owner, nil)
		done.Refreshed = r
		if err != nil {
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
	if err := clearRotation(b, slots); err != nil {
		return fail(err)
	}
	in.WiFiPassword, in.SetupSecret, in.SetupCode, in.GridSeed = p.next.WiFiPassword, p.next.SetupSecret, p.next.SetupCode, p.next.GridSeed
	done.Card = in
	return done, nil
}

// Done is a committed rotation: the new card (only the rotated parts) and
// what a re-encrypting rotation also changed.
type Done struct {
	Card
	Refreshed
}

// Refreshed is what a re-encryption changed besides the data key.
type Refreshed struct {
	// Enrollment is the new code-generator seed for the local page to
	// show, when the seed was replaced.
	Enrollment *Enrollment
	// Retrust counts the trusted PCs the owner must trust again (CRED-9).
	Retrust int
}

// refresh re-encrypts once the lost factors' slots are replaced, then
// replaces the backup MAC key and the code-generator seed: values
// Reencrypt carries over and an earlier copy holds (egress V7; security
// C1 on #64). owner must prove every passphrase and recovery slot. A
// failure part way is safe to repeat: each step starts again from fresh
// values.
func refresh(b *Box, owner []vault.Factor, r io.Reader) (Refreshed, error) {
	var out Refreshed
	n, err := b.reencrypt(owner...)
	out.Retrust = n
	if err != nil {
		return out, err
	}
	if err := rotateMACKey(b.V); err != nil {
		return out, err
	}
	e, err := newSeed(b, r)
	if err != nil {
		return out, err
	}
	if err := b.V.Put(EnrollName, KindEnroll, []byte("agentos-enrollment-v1")); err != nil {
		return out, err
	}
	out.Enrollment = &e
	return out, nil
}

// Refresh re-encrypts after a trusted PC is removed (CRED-9; egress V7):
// whoever holds that PC may hold its slot's key-encryption key, and so,
// with an earlier copy of the drive, the data key, which would also open
// later copies. It is part of the same tier-4 action as the removal, and
// takes the card's recovery key and, when the drive has a passphrase
// slot, its passphrase, since re-encryption rewraps both slots. It moves
// the vault to a fresh data key and replaces the backup MAC key and the
// code-generator seed; the page shows the enrollment, and the caller ends
// the owner channel's session. The grid's seed is not replaced here: the
// page offers a grid rotation (REC-4) alongside.
func Refresh(b *Box, auth Auth, rk RecoveryKey, passphrase []byte, r io.Reader) (Refreshed, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := auth.check(b); err != nil {
		return Refreshed{}, err
	}
	if !rk.Valid() {
		return Refreshed{}, errors.New("recovery: re-encryption needs the recovery key from the card")
	}
	owner := []vault.Factor{Factor(rk)}
	if len(passphrase) > 0 {
		owner = append(owner, vault.Passphrase(string(passphrase)))
	}
	return refresh(b, owner, r)
}

// The enrollment marker: a vault entry that exists while a code-generator
// seed that refresh replaced has not been confirmed with a code from it.
const (
	EnrollName = "recovery-enrollment-pending"
	KindEnroll = "enrollment_pending"
)

// ErrNoEnrollment is ShowEnrollment with no unconfirmed seed.
var ErrNoEnrollment = errors.New("recovery: the code generator is already confirmed")

// ShowEnrollment shows the replaced seed again ("Show the code again")
// until ConfirmEnrollment accepts a code from it (UX-64-1 on #64). Like
// the first showing, it is for the box's own Wi-Fi page only.
func ShowEnrollment(b *Box) (Enrollment, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok, err := reserved(b.V, EnrollName, KindEnroll); err != nil || !ok {
		if err == nil {
			err = ErrNoEnrollment
		}
		return Enrollment{}, err
	}
	seed, ok, err := reserved(b.V, SeedName, vault.KindTOTPSeed)
	if err != nil || !ok {
		return Enrollment{}, errors.New("recovery: no code-generator seed in the vault")
	}
	defer wipe(seed)
	return Enrollment{URI: otpauth(seed)}, nil
}

// ConfirmEnrollment reports whether code is the new seed's code now (or
// one 30-second step either side) and, when it is, ends the enrollment:
// a rotation is final only then. It is not a sign-in and spends no code.
func ConfirmEnrollment(b *Box, code string, now time.Time) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok, err := reserved(b.V, EnrollName, KindEnroll); err != nil || !ok {
		if err == nil {
			err = ErrNoEnrollment
		}
		return false, err
	}
	seed, ok, err := reserved(b.V, SeedName, vault.KindTOTPSeed)
	if err != nil || !ok {
		return false, errors.New("recovery: no code-generator seed in the vault")
	}
	defer wipe(seed)
	match := false
	for _, d := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if hmac.Equal([]byte(owner.TOTP(seed, now.Add(d))), []byte(code)) {
			match = true
		}
	}
	if !match {
		return false, nil
	}
	return true, b.V.Delete(EnrollName)
}

// EnrollmentPending reports a replaced seed not yet confirmed, for the
// page to keep showing it.
func EnrollmentPending(b *Box) bool {
	_, ok := entryKind(b.V, EnrollName)
	return ok
}

// lapse wipes the typed passphrase this rotation held.
func (p *Pending) lapse() {
	wipe(p.proof.Passphrase)
	p.proof.Passphrase = nil
}

// Lost reports a rotation made without the current card.
func (p *Pending) Lost() bool { return p.proof.lost() }

// DoneNotes are the actions the local page offers after a rotation; lost
// is a rotation made without the current card.
func DoneNotes(parts []Part, lost bool) []string {
	var out []string
	if lost {
		out = append(out,
			"Your lost card still opens backups and drive copies made before today, but nothing made from now on. Back up now, then delete the older backups.")
	}
	if lost || containsPart(parts, PartRecovery) {
		out = append(out, ResetNote)
	}
	for _, p := range parts {
		switch p {
		case PartRecovery:
			if !lost {
				out = append(out, "Back up now. Backups made before today still open with your old card.")
			}
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

// ResetNote follows every rotation or Refresh that replaced the
// code-generator seed.
const ResetNote = "Your code generator was reset. Delete the old AgentOS entry from it, then scan the new code on this page; codes from the old one no longer work."

// ExposedNote names the credentials an older copy of the drive still
// holds, for the lost-card and Refresh done pages (security R1 on #64);
// empty when the vault holds none.
func ExposedNote(b *Box) string {
	var names []string
	for _, e := range b.V.List() {
		if e.Kind == vault.KindAPIKey {
			names = append(names, e.Name)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "Credentials stored before today (" + strings.Join(names, ", ") + ") can still be read from older copies; replace those you can at their sites."
}

// RetrustNote is the done page's and digest's line for Done.Retrust
// (UX-64-2 on #64): names are the PCs' names where the vault process has
// them; n counts them all.
func RetrustNote(n int, names []string) string {
	if n <= 0 {
		return ""
	}
	pcs := fmt.Sprintf("%d other PCs", n)
	if n == 1 {
		pcs = "1 other PC"
	}
	if len(names) > 0 {
		pcs += " (" + strings.Join(names, ", ") + ")"
	}
	return pcs + " must be trusted again: on each, open the box page, unlock, and tick Keep this PC trusted."
}

// The rotation marker: a vault entry that exists while a rotation that
// rewrites the passphrase or recovery slot has not completed.
const (
	RotationName = "recovery-rotation-pending"
	KindRotation = "rotation_pending"
)

type rotationMark struct {
	Format  string    `json:"format"`
	Started time.Time `json:"started"`
	Parts   []Part    `json:"parts"`
}

// ErrRotationUnfinished is a backup refused while a rotation is unfinished.
var ErrRotationUnfinished = errors.New("recovery: a card rotation did not finish; rotate the passphrase and recovery key again before backing up")

func markRotation(b *Box, parts []Part, now time.Time) error {
	raw, ok, err := reserved(b.V, RotationName, KindRotation)
	if err != nil {
		return err
	}
	m := rotationMark{Format: "agentos-rotation-v1", Started: now.UTC()}
	if ok {
		// Keep what an earlier unfinished rotation still owes.
		var old rotationMark
		if json.Unmarshal(raw, &old) == nil {
			m.Parts = old.Parts
		}
	}
	for _, p := range parts {
		if !containsPart(m.Parts, p) {
			m.Parts = append(m.Parts, p)
		}
	}
	enc, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return b.V.Put(RotationName, KindRotation, enc)
}

// clearRotation removes the marker when this rotation covered every part
// it owes.
func clearRotation(b *Box, done []Part) error {
	raw, ok, err := reserved(b.V, RotationName, KindRotation)
	if err != nil || !ok {
		return err
	}
	var m rotationMark
	if err := json.Unmarshal(raw, &m); err == nil {
		for _, p := range m.Parts {
			if !containsPart(done, p) {
				return nil
			}
		}
	}
	return b.V.Delete(RotationName)
}

func containsPart(ps []Part, p Part) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

// RotationUnfinished reports the parts an unfinished rotation still owes,
// for the local page to resume it.
func RotationUnfinished(b *Box) ([]Part, bool) {
	k, ok := entryKind(b.V, RotationName)
	if !ok {
		return nil, false
	}
	var m rotationMark
	if s, ok := b.V.Secret(RotationName); ok && k == KindRotation && json.Unmarshal([]byte(s.Reveal()), &m) == nil && len(m.Parts) > 0 {
		return m.Parts, true
	}
	return AllParts, true
}
