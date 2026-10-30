// Package claim is a preloaded box's claim (HW-10): the seller writes a
// one-time claim code to the box and prints it on a sticker; the first
// phone to present it claims the box, the code is then burned, and every
// later attempt is refused with "already claimed". The code unlocks
// nothing: no secret exists before the claim (HW-1), and the first-boot
// path generates the Owner Card only after it (firstboot.ClaimedCard).
//
// Wrong codes are counted on disk before the answer goes out; after
// MaxWrong of them the claim screen locks until the box itself restarts
// (a new kernel boot), so a daemon restart or a crash never resets it, and
// each lock halves the tries the next boot allows (ASSUMPTIONS.md K3).
//
// A code that starts with the sticker's first two groups draws on a
// per-boot reserve of ReserveTries instead of that shared allowance, so a
// client on the access point that burns each boot's shared try never
// locks out the sticker holder (K8, R3 of the #1067 review).
//
// Both the code's verifier and its first groups' verifier are Argon2id at
// the cost in KDF, so a stranger probing the prefix online pays one
// derivation per post, and a disk read pays one per guess offline (K2, K9).
package claim

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/argon2"
)

// Store persists the claim state (change.FileStore, change.MemStore).
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// StatePath is where a preloaded box keeps its claim state: the seller
// flow (agentos-seller) writes it into the image root-owned 0600, and the
// box opens it there with change.FileStore.
const StatePath = "/var/lib/agentos/claim.json"

// The claim's refusals. Their text is the claim screen's (CH-21).
var (
	ErrAlreadyClaimed = errors.New("claim: I am already claimed")
	ErrWrongCode      = errors.New("claim: that is not my claim code")
	ErrLocked         = errors.New("claim: too many wrong codes; restart me to try again")
	ErrNoCode         = errors.New("claim: I hold no claim code")
)

// MaxWrong is the wrong codes the first boot allows before the screen locks.
const MaxWrong = 5

// CodeSymbols is the claim code's length: 16 symbols of 5 bits (80 bits),
// printed in four groups of four.
const CodeSymbols = 16

// alphabet is the Owner Card's (broker/card C1): no I, O, 0 or 1.
const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

// Journal events. Fixed strings and counts only: never the typed code.
const (
	EventSealed   = "claim: code sealed by the seller flow"
	EventClaimed  = "claim: box claimed; code burned"
	EventAgain    = "claim: refused, already claimed"
	EventWrong    = "claim: wrong code"
	EventLocked   = "claim: screen locked after wrong codes"
	EventRefused  = "claim: refused while locked"
	EventUnlocked = "claim: screen unlocked by a restart"
	EventReserve  = "claim: sticker reserve: wrong code"
)

// ReserveTries is the wrong codes per boot that start with the sticker's
// first PrefixSymbols symbols; they never count against the shared
// allowance. Once spent, such codes count as any wrong code.
const ReserveTries = 3

// PrefixSymbols is the sticker's first two groups (40 bits).
const PrefixSymbols = 8

// verifierSize is each verifier's length. The prefix verifier is as long
// as the code's: a short tag would let a client without the sticker find a
// prefix that reaches the reserve online (N1 of the #1080 review).
const verifierSize = 32

// KDF is the Argon2id cost of the code's verifiers, kept in the state.
type KDF struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
}

// productionKDF is 64 MiB, three passes, four lanes: about 75 ms per
// derivation on a 4-core cloud host, and 50 to 100 ms on the controller
// (Ryzen 5 7640HS, 32 GB). A try makes one derivation, or two when the
// code starts with the sticker's first groups.
var productionKDF = KDF{Time: 3, MemoryKiB: 64 << 10, Threads: 4}

// sealKDF is the cost Seal gives a new state; kdfFloor is the least Open
// accepts, so a state cannot make a guess cheap. Tests lower both;
// nothing else may.
var sealKDF, kdfFloor = productionKDF, productionKDF

// kdfCeiling bounds what a state can make the box spend on one try.
var kdfCeiling = KDF{Time: 16, MemoryKiB: 1 << 20, Threads: 16}

func (k *KDF) within(lo, hi KDF) bool {
	return k != nil && k.Time >= lo.Time && k.Time <= hi.Time && k.MemoryKiB >= lo.MemoryKiB &&
		k.MemoryKiB <= hi.MemoryKiB && k.Threads >= lo.Threads && k.Threads <= hi.Threads && k.Threads > 0
}

// derive is one verifier: Argon2id of the domain and s under salt.
var derive = func(k KDF, salt []byte, domain, s string) []byte {
	return argon2.IDKey([]byte(domain+"\x00"+s), salt, k.Time, k.MemoryKiB, k.Threads, verifierSize)
}

// state is everything the claim keeps on disk. It holds no secret: the
// code only as a salted Argon2id verifier, removed at the claim, and the
// claimant's token only as a hash.
type state struct {
	Salt     []byte `json:"salt,omitempty"`
	KDF      *KDF   `json:"kdf,omitempty"`
	Verifier []byte `json:"verifier,omitempty"`
	Claimed  bool   `json:"claimed"`
	Owner    []byte `json:"owner,omitempty"`
	// Wrong counts wrong codes since the screen last unlocked; Total all
	// of them. Locks counts locks, so each boot after one allows fewer.
	Wrong int `json:"wrong"`
	Total int `json:"total"`
	Locks int `json:"locks"`
	// LockedBoot is the kernel boot the screen locked in; "" when open.
	LockedBoot string `json:"locked_boot,omitempty"`
	// Prefix is the verifier of the code's first PrefixSymbols symbols
	// (same salt and cost, its own domain). A state sealed without it has
	// no reserve.
	Prefix []byte `json:"prefix,omitempty"`
	// Reserve counts the reserve's wrong codes in boot ReserveBoot.
	Reserve     int    `json:"reserve"`
	ReserveBoot string `json:"reserve_boot,omitempty"`
}

// Config configures Open. Store is required.
type Config struct {
	Store Store
	// BootID names the current kernel boot; KernelBootID when nil. A lock
	// lifts only when it changes.
	BootID func() (string, error)
	// Journal records attempts (fixed strings with counts).
	Journal func(event string)
	// Rand makes the claimant's token; crypto/rand.Reader when nil.
	Rand io.Reader
}

// Claim is the box's claim state.
type Claim struct {
	mu      sync.Mutex
	st      state
	store   Store
	journal func(string)
	rand    io.Reader
	boot    string
	// stuck is set when a wrong count could not be saved: the screen
	// stays locked for this process (fail closed).
	stuck bool
}

// KernelBootID reads Linux's boot_id, which changes on every boot.
func KernelBootID() (string, error) {
	b, err := readFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("claim: empty boot_id")
	}
	return id, nil
}

// NewCode makes a claim code for the seller flow, grouped XXXX-XXXX-XXXX-XXXX.
func NewCode(r io.Reader) (string, error) {
	if r == nil {
		r = rand.Reader
	}
	var sb strings.Builder
	buf := make([]byte, 1)
	for i := 0; i < CodeSymbols; {
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		// 256 is a multiple of 32: no bias.
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[buf[0]%32])
		i++
	}
	return sb.String(), nil
}

// Normalize is the typed code as the box compares it: upper case, without
// spaces or dashes.
func Normalize(s string) string {
	s = strings.ToUpper(s)
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '-', '\t':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Seal is the seller flow's write: the box keeps the code as a salted
// hash only. It refuses a box that already holds a claim state.
func Seal(st Store, code string, r io.Reader, journal func(string)) error {
	if r == nil {
		r = rand.Reader
	}
	if b, err := st.Load(); err != nil {
		return err
	} else if b != nil {
		return errors.New("claim: I already hold a claim state")
	}
	c := Normalize(code)
	if len(c) != CodeSymbols || strings.Trim(c, alphabet) != "" {
		return errors.New("claim: not a claim code")
	}
	k := sealKDF
	s := state{Salt: make([]byte, 16), KDF: &k}
	if _, err := io.ReadFull(r, s.Salt); err != nil {
		return err
	}
	s.Verifier = s.verifier(c)
	s.Prefix = s.prefixVerifier(c[:PrefixSymbols])
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := st.Save(b); err != nil {
		return err
	}
	if journal != nil {
		journal(EventSealed)
	}
	return nil
}

func (s *state) verifier(code string) []byte {
	return derive(*s.KDF, s.Salt, "agentos claim v2", code)
}

func (s *state) prefixVerifier(prefix string) []byte {
	return derive(*s.KDF, s.Salt, "agentos claim prefix v2", prefix)
}

func tokenHash(tok string) []byte {
	h := sha256.Sum256([]byte("agentos claimant v1\x00" + tok))
	return h[:]
}

// Claimed reports whether the box whose claim state is st is claimed,
// without changing the state (Open may lift a lock). ErrNoCode means the
// box was never sealed (the download path); a state that holds neither a
// code nor a claim is an error. The vault process's `init -setup` asks
// this before making the setup vault, so no secret exists before the
// claim (HW-10).
func Claimed(st Store) (bool, error) {
	if st == nil {
		return false, errors.New("claim: no store")
	}
	b, err := st.Load()
	if err != nil {
		return false, err
	}
	if b == nil {
		return false, ErrNoCode
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return false, fmt.Errorf("claim: state: %w", err)
	}
	if !s.Claimed && len(s.Verifier) != verifierSize {
		return false, errors.New("claim: state holds neither a code nor a claim")
	}
	return s.Claimed, nil
}

// Open loads the claim state. ErrNoCode means the box was never sealed
// (the download path, HW-10, which pairs by the flasher's QR instead). A
// lock from an earlier boot lifts here.
func Open(cfg Config) (*Claim, error) {
	if cfg.Store == nil {
		return nil, errors.New("claim: no store")
	}
	if cfg.BootID == nil {
		cfg.BootID = KernelBootID
	}
	if cfg.Journal == nil {
		cfg.Journal = func(string) {}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	boot, err := cfg.BootID()
	if err != nil {
		return nil, fmt.Errorf("claim: boot id: %w", err)
	}
	b, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, ErrNoCode
	}
	c := &Claim{store: cfg.Store, journal: cfg.Journal, rand: cfg.Rand, boot: boot}
	if err := json.Unmarshal(b, &c.st); err != nil {
		return nil, fmt.Errorf("claim: state: %w", err)
	}
	if !c.st.Claimed && len(c.st.Verifier) != verifierSize {
		return nil, errors.New("claim: state holds neither a code nor a claim")
	}
	if !c.st.Claimed && !c.st.KDF.within(kdfFloor, kdfCeiling) {
		// A state from before the KDF, or one that would make a guess
		// cheap or a try ruinous: reinstall and reseal.
		return nil, errors.New("claim: state's code cost is out of bounds")
	}
	if c.st.LockedBoot != "" && c.st.LockedBoot != boot {
		c.st.LockedBoot = ""
		c.st.Wrong = 0
		if err := c.save(); err != nil {
			return nil, err
		}
		c.journal(EventUnlocked)
	}
	return c, nil
}

func (c *Claim) save() error {
	b, err := json.Marshal(c.st)
	if err != nil {
		return err
	}
	return c.store.Save(b)
}

// allowed is the wrong codes this boot allows: MaxWrong, halved per lock,
// at least one.
func (c *Claim) allowed() int {
	n := MaxWrong
	for i := 0; i < c.st.Locks && n > 1; i++ {
		n /= 2
	}
	return n
}

func (c *Claim) lockedLocked() bool { return c.stuck || c.st.LockedBoot != "" }

// Status is what the claim screen shows.
type Status struct {
	Claimed bool
	Locked  bool
	// TriesLeft is the wrong codes still allowed before the screen locks.
	TriesLeft int
	// Reserve is the sticker holder's tries left this boot (ReserveTries
	// at most; 0 when the state has no reserve or the screen is stuck).
	// While it is above 0 a locked screen still takes the sticker's code.
	Reserve int
	// Reinstall marks a box whose claim state is lost: no phone holds its
	// setup, so its screens say only "reinstall me" (firstboot's
	// RouteReinstall). Claim never sets it.
	Reinstall bool
}

// Status reports the claim's state.
func (c *Claim) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := Status{Claimed: c.st.Claimed, Locked: !c.st.Claimed && c.lockedLocked()}
	if !s.Claimed && !s.Locked {
		s.TriesLeft = c.allowed() - c.st.Wrong
	}
	if !s.Claimed && !c.stuck {
		s.Reserve = c.reserveLeft()
	}
	return s
}

// reserveLeft is the reserve's tries left this boot.
func (c *Claim) reserveLeft() int {
	if len(c.st.Prefix) != verifierSize {
		return 0
	}
	if c.st.ReserveBoot != c.boot {
		return ReserveTries
	}
	return max(ReserveTries-c.st.Reserve, 0)
}

// Claimed reports whether the box is claimed.
func (c *Claim) Claimed() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.st.Claimed }

// Try presents a code. The right code on an unclaimed, unlocked box
// claims it, as does the right code while the reserve has tries this boot: the code is burned and the returned token names the phone
// that claimed it (Claimant). The claim is saved before Try returns; if
// the save fails the box stays unclaimed.
func (c *Claim) Try(code string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st.Claimed {
		c.journal(EventAgain)
		return "", ErrAlreadyClaimed
	}
	if c.stuck {
		c.journal(EventRefused)
		return "", ErrLocked
	}
	n := Normalize(code)
	// The prefix is checked only while the reserve has tries. A miss there
	// rules the code out without its own derivation; each derivation is
	// the online cost of a post (K9).
	prefixChecked, prefixRight := false, false
	if c.reserveLeft() > 0 && len(n) >= PrefixSymbols {
		prefixChecked = true
		prefixRight = subtle.ConstantTimeCompare(c.st.prefixVerifier(n[:PrefixSymbols]), c.st.Prefix) == 1
	}
	if prefixRight {
		if subtle.ConstantTimeCompare(c.st.verifier(n), c.st.Verifier) == 1 {
			return c.claim()
		}
		if c.st.ReserveBoot != c.boot {
			c.st.ReserveBoot, c.st.Reserve = c.boot, 0
		}
		c.st.Reserve++
		c.st.Total++
		// Saved before the answer, like the shared count.
		if err := c.save(); err != nil {
			c.stuck = true
			c.journal(EventLocked)
			return "", fmt.Errorf("%w (%v)", ErrLocked, err)
		}
		c.journal(fmt.Sprintf("%s (%d of %d this boot, %d in all)", EventReserve, c.st.Reserve, ReserveTries, c.st.Total))
		return "", ErrWrongCode
	}
	if c.lockedLocked() {
		c.journal(EventRefused)
		return "", ErrLocked
	}
	right := !prefixChecked && subtle.ConstantTimeCompare(c.st.verifier(n), c.st.Verifier) == 1
	if !right {
		allow := c.allowed()
		c.st.Wrong++
		c.st.Total++
		locked := c.st.Wrong >= allow
		if locked {
			c.st.LockedBoot = c.boot
			c.st.Locks++
		}
		// The count is on disk before the answer goes out, so a crash or
		// a daemon restart never gives tries back.
		if err := c.save(); err != nil {
			c.stuck = true
			c.journal(EventLocked)
			return "", fmt.Errorf("%w (%v)", ErrLocked, err)
		}
		c.journal(fmt.Sprintf("%s (%d of %d, %d in all)", EventWrong, c.st.Wrong, allow, c.st.Total))
		if locked {
			c.journal(EventLocked)
			return "", ErrLocked
		}
		return "", ErrWrongCode
	}
	return c.claim()
}

// claim burns the code and returns the claimant's token; c.mu is held.
func (c *Claim) claim() (string, error) {
	tb := make([]byte, 32)
	if _, err := io.ReadFull(c.rand, tb); err != nil {
		return "", err
	}
	tok := hex.EncodeToString(tb)
	prev := c.st
	c.st = state{Claimed: true, Owner: tokenHash(tok), Total: prev.Total, Locks: prev.Locks}
	if err := c.save(); err != nil {
		c.st = prev
		return "", err
	}
	c.journal(EventClaimed)
	return tok, nil
}

// Claimant reports whether tok is the token of the phone that claimed the
// box.
func (c *Claim) Claimant(tok string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.st.Claimed || len(tok) != 64 {
		return false
	}
	return subtle.ConstantTimeCompare(tokenHash(tok), c.st.Owner) == 1
}

// readFile is os.ReadFile refusing a link at p (REV-CHK-links, #3945): boot_id
// is a plain procfs file, never a link.
func readFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
