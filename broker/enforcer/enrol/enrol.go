// Package enrol is the enforcer's owner enrolment (SPEC NET-4 Enrolment and
// recovery, NET-2 Hardening, HW-10, D-178; briefs/ENF.md slice c): the
// setup secret printed inside the case, the first passkey, the recovery
// code, a replacement passkey after the 10-minute wait, factory reset, and
// the handover that replaces the setup network with the Owner network.
//
// It keeps only verifiers of the two codes, never the codes. The case code
// enrols a passkey only when the enforcer has none: at first boot, or after
// a factory reset by that same code, which keeps the policy and drops the
// passkey, so no loosening is possible until a new one enrols. The
// recovery code, made here and shown once, enrols a replacement passkey
// only after Wait, cancelable by the passkey in force, with a text and a
// page alert at the start. Every enrolment ends with the new passkey
// signing the policy in force as its own (Keep), so the policy's stored
// versions verify under one passkey only.
//
// It is enforcer code: it imports the standard library, broker/kernel/key,
// broker/enforcer/policy and broker/enforcer/alert only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package enrol

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/alert"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Wait is how long a recovery waits before its passkey replaces the one in
// force: NET-4's loosening wait, since enrolling a passkey is a loosening.
const Wait = time.Duration(policy.Wait) * time.Millisecond

// Limits on guessing a code and on what anyone who reaches the page can
// make the book hold: failed codes per FailWindow, live enrolment tickets,
// and how long a ticket lasts.
const (
	MaxFailures = 10
	FailWindow  = time.Hour
	MaxTickets  = 4
	TicketLife  = 5 * time.Minute
	// CodeLen is a generated code's length in base32 letters: 100 bits.
	CodeLen = 20
	// MinCaseCode is the shortest case code Factory takes, in letters
	// after Normal: 80 bits if base32.
	MinCaseCode = 16
)

// DomainEnrol prefixes what a new passkey signs to show it holds its
// private key: the ticket's own ID and the key, so a tap proves one
// enrolment once.
const DomainEnrol = "agentos.enforcer.enrol.v1\x00"

// Phase is where enrolment stands.
type Phase string

const (
	// Factory: no passkey has ever enrolled; the setup network is up and
	// the case code enrols the first passkey.
	Factory Phase = "factory"
	// Enrolled: a passkey is in force; the recovery code can start a
	// replacement.
	Enrolled Phase = "enrolled"
	// Reset: a factory reset by the case code dropped the passkey and kept
	// the policy; the case code enrols the next passkey.
	Reset Phase = "reset"
)

var (
	ErrCode           = errors.New("enrol: that code is not right")
	ErrLimited        = errors.New("enrol: too many wrong codes; wait an hour")
	ErrPhase          = errors.New("enrol: not possible now")
	ErrGone           = errors.New("enrol: this enrolment expired or was already used; start again")
	ErrBusy           = errors.New("enrol: too many enrolments in progress; wait a few minutes")
	ErrProof          = errors.New("enrol: the new passkey did not sign")
	ErrKey            = errors.New("enrol: not a passkey for the enforcer's own name")
	ErrNotProvisioned = errors.New("enrol: no case code was provisioned")
	ErrKept           = errors.New("enrol: the policy is already this passkey's")
	ErrConfig         = errors.New("enrol: bad config")
)

// Store keeps the book's state across restarts: the enforcer's sealed
// store in the daemon (slice l), a map in tests.
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Card is the Owner network as the page shows it at enrolment: its name,
// its password grouped for typing, and its Wi-Fi QR text (ap.Card).
type Card struct {
	SSID, Shown, QR string
}

// Network is the access point's side of enrolment (slice g): Replace
// replaces the setup network with the Owner, Household and Guests networks
// and pushes the access point's new configuration, so the sticker's
// password opens nothing, and returns the Owner network's card. Called
// again once replaced, it changes nothing and returns the same card.
type Network interface {
	Replace() (Card, error)
}

// Alerts is the part of the enforcer's alerts (alert.Alerts) enrolment
// drives: a text and page alert for each enrolment and each use of the
// recovery code, and the page's recovery-pending state.
type Alerts interface {
	Raise(k alert.Kind, device string) (alert.Record, error)
	Recovery(pending bool)
}

// Config is what the daemon (slice l) wires in.
type Config struct {
	// Name is the enforcer's own local name, the passkey's RP ID.
	Name    string
	Store   Store
	Network Network
	Alerts  Alerts
	// Lock serialises the book's calls to the policy engine with the
	// page's and the daemon's (page.Config.Lock); nil means the book's own.
	// The book takes it, so callers must not hold it.
	Lock sync.Locker
	Now  func() time.Time // nil means time.Now
	Rand io.Reader        // nil means crypto/rand
}

// verifier is a code's salted SHA-256. The codes are long and random, so a
// slow hash adds nothing.
type verifier struct {
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
}

func newVerifier(r io.Reader, code string) (verifier, error) {
	v := verifier{Salt: make([]byte, 16)}
	if _, err := io.ReadFull(r, v.Salt); err != nil {
		return v, err
	}
	v.Hash = v.sum(code)
	return v, nil
}

func (v verifier) sum(code string) []byte {
	h := sha256.New()
	h.Write([]byte("agentos.enforcer.code.v1\x00"))
	h.Write(v.Salt)
	h.Write([]byte(Normal(code)))
	return h.Sum(nil)
}

func (v *verifier) matches(code string) bool {
	return v != nil && len(v.Hash) == sha256.Size && subtle.ConstantTimeCompare(v.sum(code), v.Hash) == 1
}

// replacement is a passkey waiting out Wait after the recovery code.
type replacement struct {
	Key      []byte   `json:"key"` // key.PublicKey.Encode
	Recovery verifier `json:"recovery"`
	DueMS    int64    `json:"due_ms"`
}

type state struct {
	Phase Phase    `json:"phase"`
	Case  verifier `json:"case"`
	// Owner is the passkey in force; none in Factory and Reset.
	Owner []byte `json:"owner,omitempty"`
	// Policy is the passkey the policy's stored versions are signed by;
	// Keeping is the one a Keep has started moving them to.
	Policy   []byte       `json:"policy,omitempty"`
	Keeping  []byte       `json:"keeping,omitempty"`
	Recovery *verifier    `json:"recovery,omitempty"`
	Pending  *replacement `json:"pending,omitempty"`
}

// Policy is the part of policy.Engine the book drives.
type Policy interface {
	Current() policy.Document
	Pending() []policy.Pending
	Cancel(id string) error
	Rekey(owner key.PublicKey, next policy.Proposal, sig []byte) error
	Disown() error
}

// Book is the enforcer's enrolment state.
type Book struct {
	cfg   Config
	mu    sync.Mutex
	st    state
	pol   Policy
	fails []int64
	tix   map[string]*ticket
}

// ticket is one enrolment between its code and its new passkey's tap.
// ticket is one Begin waiting for its Finish. It is good only for the
// state that issued it: every save drops all tickets.
type ticket struct {
	pk      key.PublicKey
	msg     []byte
	expires int64
}

// Normal is a code as the book compares it: letters upper-cased, spaces and
// dashes dropped, so the owner can type it as printed or not.
func Normal(code string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ' || r == '-' || r == '\t':
			return -1
		case r >= 'a' && r <= 'z':
			return r - 'a' + 'A'
		}
		return r
	}, code)
}

// Provision provisions an empty store with the case code's verifier: the
// image's first boot does it with the code the seller or the flasher
// printed for the case (HW-10). It refuses a store that holds anything.
func Provision(store Store, caseCode string, r io.Reader) error {
	if r == nil {
		r = rand.Reader
	}
	if b, err := store.Load(); err != nil {
		return err
	} else if b != nil {
		return fmt.Errorf("%w: already provisioned", ErrPhase)
	}
	if len(Normal(caseCode)) < MinCaseCode {
		return fmt.Errorf("%w: case code too short", ErrConfig)
	}
	v, err := newVerifier(r, caseCode)
	if err != nil {
		return err
	}
	b, err := json.Marshal(state{Phase: Factory, Case: v})
	if err != nil {
		return err
	}
	return store.Save(b)
}

// Open loads the book. The store must have been provisioned (Provision).
func Open(cfg Config) (*Book, error) {
	if cfg.Name == "" || cfg.Store == nil || cfg.Network == nil || cfg.Alerts == nil {
		return nil, ErrConfig
	}
	if cfg.Lock == nil {
		cfg.Lock = &sync.Mutex{}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	b := &Book{cfg: cfg, tix: map[string]*ticket{}}
	raw, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, ErrNotProvisioned
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b.st); err != nil {
		return nil, fmt.Errorf("enrol: stored state: %v", err)
	}
	if err := b.st.check(cfg.Name); err != nil {
		return nil, err
	}
	b.cfg.Alerts.Recovery(b.st.Pending != nil)
	return b, nil
}

// check refuses a stored state no sequence of the book's calls makes.
func (st state) check(name string) error {
	bad := func(why string) error { return fmt.Errorf("enrol: stored state: %s", why) }
	if len(st.Case.Hash) != sha256.Size {
		return bad("no case code")
	}
	for _, k := range [][]byte{st.Owner, st.Policy, st.Keeping} {
		if k != nil {
			if _, err := passkey(name, k); err != nil {
				return bad("a passkey not on this name")
			}
		}
	}
	switch st.Phase {
	case Factory:
		if st.Owner != nil || st.Policy != nil || st.Recovery != nil || st.Pending != nil {
			return bad("factory state with a passkey")
		}
	case Enrolled:
		if st.Owner == nil || st.Recovery == nil {
			return bad("enrolled with no passkey or recovery code")
		}
	case Reset:
		if st.Owner != nil || st.Recovery != nil || st.Pending != nil {
			return bad("reset with a passkey")
		}
	default:
		return bad("unknown phase")
	}
	if st.Pending != nil {
		if _, err := passkey(name, st.Pending.Key); err != nil {
			return bad("pending passkey not on this name")
		}
	}
	return nil
}

func passkey(name string, b []byte) (key.PublicKey, error) {
	pk, err := key.DecodePublicKey(b)
	if err != nil || pk.Alg() != key.AlgES256 {
		return key.PublicKey{}, ErrKey
	}
	if want, err := key.ES256(name, pk.Bytes()); err != nil || want != pk {
		return key.PublicKey{}, ErrKey
	}
	return pk, nil
}

func (b *Book) key(raw []byte) key.PublicKey {
	if raw == nil {
		return key.PublicKey{}
	}
	pk, _ := passkey(b.cfg.Name, raw) // checked at Open and at every write
	return pk
}

// OpenPolicy opens the policy engine on store under the passkey its versions
// are signed by, and binds it to the book. If the enforcer stopped inside a
// Keep, after the engine saved and before the book did, the versions are
// already the new passkey's: it opens them under that one and finishes the
// Keep.
func (b *Book) OpenPolicy(store policy.Store) (*policy.Engine, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, err := policy.Open(b.key(b.st.Policy), store)
	if err != nil && b.st.Keeping != nil {
		if e, err = policy.Open(b.key(b.st.Keeping), store); err == nil {
			st := b.st
			st.Policy, st.Keeping = st.Keeping, nil
			err = b.save(st)
		}
	}
	if err != nil {
		return nil, err
	}
	if b.st.Owner == nil || !bytes.Equal(b.st.Owner, b.st.Policy) {
		if err := e.Disown(); err != nil {
			return nil, err
		}
	}
	b.pol = e
	return e, nil
}

// Phase is where enrolment stands.
func (b *Book) Phase() Phase {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st.Phase
}

// Owner is the passkey in force: the only one the page takes a tap from.
// It is the zero key in Factory and Reset.
func (b *Book) Owner() key.PublicKey {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.key(b.st.Owner)
}

// Kept reports whether the policy's versions are signed by the passkey in
// force. Until they are, the policy takes no proposal and the page asks
// the owner to keep it (KeepProposal).
func (b *Book) Kept() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.st.Owner != nil && bytes.Equal(b.st.Owner, b.st.Policy)
}

// Recovery is the replacement passkey waiting out Wait, and when it
// applies: the page shows it until then.
func (b *Book) Recovery() (due time.Time, pending bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.Pending == nil {
		return time.Time{}, false
	}
	return time.UnixMilli(b.st.Pending.DueMS), true
}

func (b *Book) nowMS() int64 { return b.cfg.Now().UnixMilli() }

// guess checks code against v, counting a miss against MaxFailures.
func (b *Book) guess(v *verifier, code string) error {
	now := b.nowMS()
	b.fails = slices.DeleteFunc(b.fails, func(t int64) bool { return t <= now-FailWindow.Milliseconds() })
	if len(b.fails) >= MaxFailures {
		return ErrLimited
	}
	if !v.matches(code) {
		b.fails = append(b.fails, now)
		return ErrCode
	}
	return nil
}

// Begin starts an enrolment of pk with code: the case code when no passkey
// is in force (Factory, Reset), the recovery code when one is (Enrolled,
// with no replacement already waiting). It returns a ticket and the
// message pk must sign to show it holds its key; Finish takes the tap.
func (b *Book) Begin(code string, pk key.PublicKey) (id string, msg []byte, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, err := passkey(b.cfg.Name, pk.Encode()); err != nil {
		return "", nil, ErrKey
	}
	switch b.st.Phase {
	case Factory, Reset:
		err = b.guess(&b.st.Case, code)
	case Enrolled:
		if b.st.Pending != nil {
			return "", nil, ErrPhase
		}
		if bytes.Equal(pk.Encode(), b.st.Owner) {
			return "", nil, ErrPhase // the recovery code replaces the passkey, never re-enrols it
		}
		err = b.guess(b.st.Recovery, code)
	}
	if err != nil {
		return "", nil, err
	}
	now := b.nowMS()
	for k, t := range b.tix {
		if t.expires <= now {
			delete(b.tix, k)
		}
	}
	if len(b.tix) >= MaxTickets {
		return "", nil, ErrBusy
	}
	idb := make([]byte, 16)
	if _, err := io.ReadFull(b.cfg.Rand, idb); err != nil {
		return "", nil, err
	}
	id = hex.EncodeToString(idb)
	msg = append([]byte(DomainEnrol+id+"\x00"), pk.Encode()...)
	b.tix[id] = &ticket{pk: pk, msg: msg, expires: now + TicketLife.Milliseconds()}
	return id, msg, nil
}

// Result is what an enrolment shows the owner once: the new recovery code,
// and either the Owner network's card (a passkey now in force) or when the
// replacement applies (a recovery).
type Result struct {
	Recovery string
	Card     Card
	Due      time.Time // zero unless a recovery is waiting
}

// Finish takes the new passkey's tap over its ticket's message. Each
// ticket works once. With no passkey in force, the access point drops the
// setup network first (Network.Replace), and only then does the passkey
// enrol, so a sticker never outlives an enrolment; a failed handover
// enrols nothing. With one in force, the replacement waits Wait, and the
// owner is texted and the page shows it.
func (b *Book) Finish(id string, sig []byte) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.tix[id]
	delete(b.tix, id)
	if !ok || t.expires <= b.nowMS() {
		return Result{}, ErrGone
	}
	if !t.pk.Verify(t.msg, sig) {
		return Result{}, ErrProof
	}
	code, rec, err := b.code()
	if err != nil {
		return Result{}, err
	}
	st := b.st
	switch st.Phase {
	case Factory, Reset:
		card, err := b.cfg.Network.Replace()
		if err != nil {
			return Result{}, fmt.Errorf("enrol: the setup network was not replaced, so nothing was enrolled: %w", err)
		}
		st.Phase, st.Owner, st.Recovery = Enrolled, t.pk.Encode(), &rec
		if err := b.take(&st); err != nil {
			return Result{}, err
		}
		b.cfg.Alerts.Raise(alert.Enrolment, "")
		return Result{Recovery: code, Card: card}, nil
	case Enrolled:
		due := b.nowMS() + Wait.Milliseconds()
		st.Pending = &replacement{Key: t.pk.Encode(), Recovery: rec, DueMS: due}
		if err := b.save(st); err != nil {
			return Result{}, err
		}
		b.cfg.Alerts.Raise(alert.RecoveryCodeUsed, "")
		b.cfg.Alerts.Recovery(true)
		return Result{Recovery: code, Due: time.UnixMilli(due)}, nil
	}
	return Result{}, ErrPhase
}

// code makes a recovery code and its verifier.
func (b *Book) code() (string, verifier, error) {
	raw := make([]byte, CodeLen*5/8)
	if _, err := io.ReadFull(b.cfg.Rand, raw); err != nil {
		return "", verifier{}, err
	}
	c := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	v, err := newVerifier(b.cfg.Rand, c)
	return c, v, err
}

// take saves st, which puts a new passkey in force. A loosening the old
// passkey signed and still waiting does not outlive it: it is cancelled
// first. A policy holding nothing yet passes to the new passkey at once;
// any other waits for its Keep.
func (b *Book) take(st *state) error {
	if b.pol == nil {
		return ErrConfig // OpenPolicy first
	}
	b.cfg.Lock.Lock()
	defer b.cfg.Lock.Unlock()
	for _, p := range b.pol.Pending() {
		if err := b.pol.Cancel(p.ID); err != nil {
			return err
		}
	}
	if err := b.save(*st); err != nil {
		return err
	}
	if err := b.pol.Rekey(b.key(st.Owner), policy.Proposal{}, nil); err == nil {
		st.Policy = st.Owner // the policy held nothing to keep
		return b.save(*st)
	}
	return b.pol.Disown() // until the new passkey keeps it
}

// Cancel drops the replacement waiting and spends the recovery code that
// started it: whoever used it cannot start another, and the owner is
// shown, once, the new code that replaces it. The page calls it only
// after a tap of the passkey in force (NET-4).
func (b *Book) Cancel() (string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.Pending == nil {
		return "", ErrPhase
	}
	code, rec, err := b.code()
	if err != nil {
		return "", err
	}
	st := b.st
	st.Pending, st.Recovery = nil, &rec
	if err := b.save(st); err != nil {
		return "", err
	}
	b.cfg.Alerts.Recovery(false)
	return code, nil
}

// Tick puts the waiting replacement in force once Wait has passed: its
// recovery code replaces the old one, the old passkey takes no more taps,
// and the owner is texted. It reports whether it did.
func (b *Book) Tick() (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.st.Pending
	if p == nil || p.DueMS > b.nowMS() {
		return false, nil
	}
	st := b.st
	rec := p.Recovery
	st.Owner, st.Recovery, st.Pending = p.Key, &rec, nil
	if err := b.take(&st); err != nil {
		return false, err
	}
	b.cfg.Alerts.Recovery(false)
	b.cfg.Alerts.Raise(alert.Enrolment, "")
	return true, nil
}

// FactoryReset drops the passkey in force, the recovery code and any
// replacement waiting, and keeps the policy: with no passkey, nothing can
// loosen it until the case code enrols a new one (NET-2 Hardening). A
// loosening waiting is cancelled, so none lands meanwhile. The Owner
// network and its password stay.
func (b *Book) FactoryReset(caseCode string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.Phase == Factory {
		return ErrPhase
	}
	if err := b.guess(&b.st.Case, caseCode); err != nil {
		return err
	}
	if b.pol == nil {
		return ErrConfig
	}
	b.cfg.Lock.Lock()
	defer b.cfg.Lock.Unlock()
	for _, p := range b.pol.Pending() {
		if err := b.pol.Cancel(p.ID); err != nil {
			return err
		}
	}
	if err := b.pol.Disown(); err != nil {
		return err
	}
	st := b.st
	st.Phase, st.Owner, st.Recovery, st.Pending = Reset, nil, nil, nil
	if err := b.save(st); err != nil {
		return err
	}
	b.cfg.Alerts.Recovery(false)
	return nil
}

// KeepDiff is the line the page shows, and the new passkey signs, to keep
// the policy in force as its own.
const KeepDiff = "Keep every rule exactly as it is now, signed by this passkey. Nothing is loosened or tightened."

// KeepProposal is the policy in force, unchanged, at version, for the
// passkey in force to sign (Keep). The page draws it and picks the version
// as it does for any proposal (ENF-b-2).
func (b *Book) KeepProposal(version uint64) (policy.Proposal, key.Root, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.Owner == nil || bytes.Equal(b.st.Owner, b.st.Policy) || b.pol == nil {
		return policy.Proposal{}, key.Root{}, ErrKept
	}
	b.cfg.Lock.Lock()
	d := b.pol.Current()
	b.cfg.Lock.Unlock()
	d.Version = version
	p := policy.Proposal{Doc: d, Diff: []byte(KeepDiff)}
	r, err := p.Root(b.key(b.st.Owner))
	return p, r, err
}

// Keep moves the policy's stored versions to the passkey in force, with
// its signature over KeepProposal's root. The book records which passkey
// it is moving to before the engine saves, so a stop in between is
// finished by OpenPolicy.
func (b *Book) Keep(p policy.Proposal, sig []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.st.Owner == nil || bytes.Equal(b.st.Owner, b.st.Policy) || b.pol == nil {
		return ErrKept
	}
	st := b.st
	st.Keeping = st.Owner
	if err := b.save(st); err != nil {
		return err
	}
	b.cfg.Lock.Lock()
	err := b.pol.Rekey(b.key(st.Owner), p, sig)
	b.cfg.Lock.Unlock()
	if err != nil {
		return err
	}
	st.Policy, st.Keeping = st.Owner, nil
	return b.save(st)
}

// save writes st and, only if that succeeds, makes it the book's state.
func (b *Book) save(st state) error {
	// A ticket begun under the state before this one authorises nothing
	// under it: not after an enrolment, a recovery started, cancelled or
	// applied, or a reset.
	clear(b.tix)
	if err := st.check(b.cfg.Name); err != nil {
		return err
	}
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := b.cfg.Store.Save(raw); err != nil {
		return err
	}
	b.st = st
	return nil
}
