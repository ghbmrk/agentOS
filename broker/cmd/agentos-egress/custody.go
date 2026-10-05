package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/tpmseal"
	"github.com/ghbmrk/agentos/broker/vault"
)

// SeedName is the vault entry holding the owner's code-generator seed.
const SeedName = "owner-totp-seed"

// Unlock limits. MaxWrongCodes wrong codes within WrongWindow refuse
// further unlocks until the oldest ages out; the count survives restarts.
// MinAttemptGap spaces passphrase attempts, each of which costs an Argon2id
// derivation (256 MiB); a refused attempt is not counted as wrong.
const (
	MaxWrongCodes = 3
	WrongWindow   = 24 * time.Hour
	MinAttemptGap = 2 * time.Second
)

// Wrong verifies from the broker are bounded here on their own (K7), so a
// taken-over agentosd cannot grind codes. There are two buckets, each over
// a sliding VerifyWindow. Counted checks (the owner's deliberate codes)
// may be wrong MaxWrongCounted times, above the channel's own
// WrongToChallenge (10), after which each attempt needs a texted
// challenge. Silent checks of codes in chat (O5) may be wrong
// MaxWrongSilent times; a full silent bucket refuses silent checks only,
// so a spoofer's flood never refuses the owner's counted code.
const (
	MaxWrongCounted = 20
	MaxWrongSilent  = 10
	VerifyWindow    = 10 * time.Minute
)

// pausedError refuses a verify until the oldest wrong one in its bucket
// ages out.
type pausedError struct{ until time.Time }

func (e *pausedError) Error() string { return "too many wrong codes; checks are paused" }

// unlockErr is an error safe to show on the unlock socket, with its HTTP
// status.
type unlockErr struct {
	msg    string
	status int
}

func (e *unlockErr) Error() string { return e.msg }

func uerr(status int, msg string) *unlockErr { return &unlockErr{msg, status} }

var (
	errBusy            = uerr(http.StatusConflict, "an unlock is already in progress or the vault is open")
	errTooSoon         = uerr(http.StatusTooManyRequests, "wait a moment before trying again")
	errWrongPassphrase = uerr(http.StatusForbidden, "the passphrase does not open this vault")
	errNoCodeGenerator = uerr(http.StatusForbidden, "no code generator is enrolled in this vault")
	errNotPending      = uerr(http.StatusConflict, "no unlock is waiting for a code")
	errExpired         = uerr(http.StatusForbidden, "the code did not arrive in time; unlock again")
	errLocked          = uerr(http.StatusConflict, "the vault is locked")
	errUnlockCancelled = uerr(http.StatusConflict, "the unlock was cancelled")
	errBadCredential   = uerr(http.StatusBadRequest, "credential name or value refused")
	errInternal        = uerr(http.StatusInternalServerError, "internal error")

	// Trusted hosts (CRED-8, CRED-9).
	errNoTPM        = uerr(http.StatusConflict, "this PC has no TPM, so it cannot be a trusted host")
	errBadPIN       = uerr(http.StatusBadRequest, "a boot PIN has 6 to 64 characters")
	errWrongPIN     = uerr(http.StatusForbidden, "wrong PIN; this PC's TPM limits how many tries it allows")
	errPINLockout   = uerr(http.StatusTooManyRequests, "Too many wrong PINs. Unlock with your passphrase and a code instead.")
	errNotTrusted   = uerr(http.StatusConflict, "this PC is not a trusted host; unlock with the vault passphrase and a code")
	errBootChanged  = uerr(http.StatusConflict, "This PC started the box in a way it hasn't before. Unlock with your passphrase and a code.")
	errNoSuchHost   = uerr(http.StatusNotFound, "no trusted host with that id")
	errHostNotSaved = uerr(http.StatusInternalServerError, "could not make this PC trusted; nothing was changed")
	errLockoutOwned = uerr(http.StatusConflict, "Another system on this PC controls the TPM, so the box can't protect a boot PIN here. Trust this PC without a PIN instead.")

	// Rollback (V6): the drive's vault is older than this PC's counter.
	errRolledBack = uerr(http.StatusConflict, "this drive's vault is older than this PC has seen, so it may be an old copy put back; nothing was unlocked. If you did not restore it, keep the drive and restore from your backup with the recovery key")
)

// noteCounterReset is the owner's notice, once, when this PC's rollback
// counter for the vault is gone (vault.ErrCounterMissing; arbitrator
// ruling on #45, B3). Wording fixed by that ruling.
const noteCounterReset = "This PC's copy check was reset. If you cleared this PC's security chip, that's expected: unlock with your card to trust it again. If you didn't, an older copy of your drive may have been opened."

// noteTPMSilent is the owner's notice when this PC's TPM does not answer
// the rollback check; the detail goes to the log only (UX-45-3).
const noteTPMSilent = "This PC's security chip didn't respond, so the box stayed locked. Restart the PC. If it happens again, move the drive to another PC and unlock there with your passphrase and a code."

// noteRolledBack is the owner's notice for an old copy of the drive (V6).
const noteRolledBack = "the vault on this drive is older than this PC has seen: it may be an old copy of the drive put back, so it stayed locked. If you did not restore it, the drive was out of your hands; restore from your backup with the recovery key."

func errWrongCode(left int) error {
	if left == 1 {
		return uerr(http.StatusForbidden, "wrong code; 1 try left")
	}
	return uerr(http.StatusForbidden, fmt.Sprintf("wrong code; %d tries left", left))
}

func errLockedOut(until time.Time) error {
	return uerr(http.StatusTooManyRequests, "Too many wrong codes. Unlock again after "+until.Local().Format("Mon 15:04")+".")
}

func errClockSkew(seconds int64) error {
	return uerr(http.StatusForbidden, fmt.Sprintf("that code is for another time: the box clock and your phone differ by about %d s; this try was not counted", seconds))
}

type phase int

const (
	locked  phase = iota
	opening       // the passphrase is being checked (Argon2id)
	pending       // decrypted, waiting for the code-generator code
	open          // serving the model route
)

func (p phase) String() string { return [...]string{"locked", "opening", "pending", "open"}[p] }

// unlockState is what must survive a restart: recent wrong codes (CH-18)
// and the last code-generator step accepted (O6), so neither a crash nor a
// restart resets the cap or lets a code be used twice.
type unlockState struct {
	Wrong    []int64 `json:"wrong"`
	LastStep int64   `json:"last_step"`
}

// loadState reads the state file. A missing file is a fresh start; an
// unreadable one fails closed.
func loadState(path string) (unlockState, error) {
	var st unlockState
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		return st, fmt.Errorf("unlock state %s is unreadable; refusing to start", path)
	}
	return st, nil
}

// custody is the unknown-host unlock (CRED-8): the vault passphrase
// decrypts the vault, and a code from the owner's code generator, checked
// against the seed inside the vault, authorizes it. Until the code arrives
// the vault is held but nothing is served. No right code within ttl, or a
// lock, discards the key. Only an open vault serves the model route.
type custody struct {
	// keysPath, if set, is the keys file; while it exists the state file
	// must too.
	keysPath string
	// open decrypts the vault with a passphrase (vault.OpenSealed).
	open func(passphrase string) (*vault.Vault, error)
	// build makes the egress proxy over an open vault.
	build func(*vault.Vault) (*egress.Proxy, error)
	ttl   time.Duration
	now   func() time.Time
	// notify reports unlock events for the owner (CRED-8 visibility).
	notify func(string)
	// statePath holds unlockState; written before each reply that
	// changes it.
	statePath string
	// host is this PC's TPM (trusted.go); nil without one.
	host trustedHost

	mu          sync.Mutex
	st          unlockState
	ph          phase
	gen         int // bumped by lock, so an unlock in flight is cancelled
	v           *vault.Vault
	proxy       *egress.Proxy
	ticket      string // binds a confirm to its unlock
	expires     time.Time
	timer       *time.Timer
	lastAttempt time.Time
	// needPIN: this PC is trusted with a boot PIN and waits for it.
	needPIN bool
	// counterReset: the owner was told this PC's rollback counter is
	// gone (noteCounterReset); cleared when the PC is trusted again.
	counterReset bool
	// bootChanged: this PC is trusted but booted a path the box never
	// approved; bootUpdated: and it runs another release than last time.
	// The fallback unlock may then keep the PC trusted (confirmKeep).
	bootChanged, bootUpdated bool
	// bootSecure: only the Secure Boot state (PCR 7) changed.
	bootSecure bool
	// deriving: an Argon2id derivation is running. With phase opening it
	// is a first unlock; with phase pending, a new passphrase that will
	// supersede the pending unlock if it opens the vault.
	deriving bool
	// proof is the hash of the ticket of the last confirmed unlock and the
	// step its code spent, redeemable once on the verify socket until
	// proofUntil, so the phone that unlocked signs in (P2-4f).
	proof      [32]byte
	proofStep  int64
	proofUntil time.Time
	// wrongPassAt is when the owner was last told of a wrong passphrase;
	// wrongPassQuiet counts those since, untold (WrongPassNoteEvery).
	wrongPassAt    time.Time
	wrongPassQuiet int
	// supersedeAt and supersedeQuiet do the same for restarted unlocks.
	supersedeAt    time.Time
	supersedeQuiet int
	// wrongCounted and wrongSilent are the wrong verifies per bucket.
	wrongCounted []time.Time
	wrongSilent  []time.Time
}

// newCustody loads the durable unlock state into c.
func newCustody(c *custody) (*custody, error) {
	if c.keysPath != "" {
		if _, err := os.Lstat(c.keysPath); err == nil {
			if _, err := os.Lstat(c.statePath); errors.Is(err, os.ErrNotExist) {
				// init writes the state with the keys; losing it would
				// reset the wrong-code cap and allow a code replay.
				return nil, fmt.Errorf("unlock state %s is missing although %s exists; refusing to start (restore it from the same backup as the keys)", c.statePath, c.keysPath)
			}
		}
	}
	st, err := loadState(c.statePath)
	if err != nil {
		return nil, err
	}
	c.st = st
	return c, nil
}

// status reports the phase and, while pending, when the code is due.
func (c *custody) status() (phase, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ph, c.expires
}

// WrongPassNoteEvery bounds how often the owner is told of wrong vault
// passphrases. They are not counted toward any lockout (nobody without the
// card can lock the owner out), but repeated ones may be someone on the
// box's Wi-Fi starving the owner's unlock, so the owner hears of them.
const WrongPassNoteEvery = 10 * time.Minute

// times words a count for the owner: "once", "twice", "3 times".
func times(n int) string {
	switch n {
	case 1:
		return "once"
	case 2:
		return "twice"
	}
	return fmt.Sprintf("%d times", n)
}

// ProofTTL is how long the proof of a confirmed unlock can sign the
// unlocking phone in (P2-4f).
const ProofTTL = time.Minute

// noteWrongPassLocked tells the owner of a wrong passphrase, at most once
// per WrongPassNoteEvery, with the count of those not told.
func (c *custody) noteWrongPassLocked(now time.Time) {
	if !c.wrongPassAt.IsZero() && now.Sub(c.wrongPassAt) < WrongPassNoteEvery {
		c.wrongPassQuiet++
		return
	}
	msg := "wrong vault passphrase tried on the box's Wi-Fi"
	if c.wrongPassQuiet > 0 {
		msg += fmt.Sprintf(" (%d more since the last notice)", c.wrongPassQuiet)
	}
	c.wrongPassAt, c.wrongPassQuiet = now, 0
	c.notify(msg)
}

// noteSupersedeLocked tells the owner that a pending unlock was started
// over, at most once per WrongPassNoteEvery with the count of those not
// told, so someone on the Wi-Fi holding the card cannot turn restarts into
// a stream of texts (#65 security R1).
func (c *custody) noteSupersedeLocked(now time.Time) {
	if !c.supersedeAt.IsZero() && now.Sub(c.supersedeAt) < WrongPassNoteEvery {
		c.supersedeQuiet++
		return
	}
	msg := "The box unlock was started over with your card; the earlier one was cancelled."
	if c.supersedeQuiet > 0 {
		msg += " It was started over " + times(c.supersedeQuiet) + " more since the last notice."
	}
	c.supersedeAt, c.supersedeQuiet = now, 0
	c.notify(msg)
}

// unlock checks the passphrase and, if it opens the vault, returns the
// ticket its confirm must carry. A passphrase alone never opens the model
// route. One derivation runs at a time: the phase stays opening until it
// returns, even if lock cancels it meanwhile.
func (c *custody) unlock(passphrase string) (string, error) {
	c.mu.Lock()
	// A pending unlock can be superseded by a new correct passphrase, so a
	// phone that lost its ticket (a closed page, a local UI restart) does
	// not wait out the expiry. The pending unlock stays answerable while
	// the new passphrase is checked; this is atomic here, so it cannot
	// race a confirm (#50 potency PU1).
	if c.ph == open || c.ph == opening || c.deriving {
		c.mu.Unlock()
		return "", errBusy
	}
	now := c.now()
	if until, out := c.lockedOut(now); out {
		c.mu.Unlock()
		return "", errLockedOut(until)
	}
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < MinAttemptGap {
		c.mu.Unlock()
		return "", errTooSoon
	}
	c.lastAttempt = now
	c.deriving = true
	if c.ph == locked {
		c.ph = opening
	}
	gen := c.gen
	c.mu.Unlock()

	v, err := c.open(passphrase)
	if err == nil && c.host != nil {
		// V6: before the seed in it is trusted for the code check.
		err = c.host.bind(v)
		switch {
		case err == nil:
		case errors.Is(err, vault.ErrCounterMissing):
			// Nothing here can tell whether the file is current; the
			// owner unlocks in person (passphrase and code), warned.
			err = nil
			c.noteCounterReset()
		default:
			v.Close()
			v = nil
			if !errors.Is(err, vault.ErrRolledBack) {
				log.Printf("rollback check on unlock: %v", err)
				c.notify(noteTPMSilent)
			}
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.deriving = false
	if c.ph == opening {
		c.ph = locked
	}
	if c.gen != gen || c.ph == open {
		// Locked meanwhile, or the pending unlock was confirmed.
		if v != nil {
			v.Close()
		}
		if c.gen != gen {
			return "", errUnlockCancelled
		}
		return "", errBusy
	}
	if err != nil {
		if errors.Is(err, vault.ErrNoSlotOpens) {
			c.noteWrongPassLocked(now)
			return "", errWrongPassphrase
		}
		if errors.Is(err, vault.ErrRolledBack) {
			c.notify(noteRolledBack)
			return "", errRolledBack
		}
		return "", errInternal
	}
	if until, out := c.lockedOut(c.now()); out {
		// Wrong codes on the pending unlock reached the cap during the
		// derivation (#65 L3 follow-up 2).
		v.Close()
		return "", errLockedOut(until)
	}
	if !hasKind(v, SeedName, vault.KindTOTPSeed) {
		v.Close()
		return "", errNoCodeGenerator
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		v.Close()
		return "", errInternal
	}
	superseded := c.ph == pending
	if superseded {
		c.timer.Stop()
		c.v.Close()
		c.noteSupersedeLocked(now)
	}
	c.ph, c.v, c.ticket = pending, v, hex.EncodeToString(b)
	c.expires = now.Add(c.ttl)
	c.timer = time.AfterFunc(c.ttl, c.expire)
	if c.wrongPassQuiet > 0 {
		// A burst that stopped still reports its total.
		c.notify(fmt.Sprintf("%d more wrong vault passphrases were tried on the box's Wi-Fi since the last notice", c.wrongPassQuiet))
		c.wrongPassQuiet = 0
	}
	if !superseded {
		c.notify("vault passphrase accepted; waiting for a code-generator code")
	}
	return c.ticket, nil
}

// confirm checks a code-generator code against the seed inside the vault.
// A wrong code counts toward the durable cap and leaves the unlock pending
// until its expiry, unless the cap is reached; then the key is discarded.
func (c *custody) confirm(ticket, code string) error {
	_, err := c.confirmKeep(ticket, code, false)
	return err
}

// confirmKeep is confirm with "Keep this PC trusted": when this trusted PC
// booted a path the box never approved, keep approves the running path
// with the same proof (passphrase, code, local page; CRED-9 tier 4), so
// the next restart is unattended again. It reports whether it did.
func (c *custody) confirmKeep(ticket, code string, keep bool) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != pending || subtle.ConstantTimeCompare([]byte(ticket), []byte(c.ticket)) != 1 {
		return false, errNotPending
	}
	now := c.now()
	if !now.Before(c.expires) {
		c.discard()
		c.notify("vault unlock expired without a code; key discarded")
		return false, errExpired
	}
	if err := c.checkCode(code, now); err != nil {
		var ue *unlockErr
		switch {
		case !errors.As(err, &ue) || ue == errInternal:
			c.discard()
			return false, errInternal
		case ue.status == http.StatusTooManyRequests:
			c.discard()
			c.notify("too many wrong codes for a vault unlock; key discarded")
		case strings.HasPrefix(ue.msg, "wrong code"):
			c.notify("wrong code for a vault unlock")
		}
		return false, err
	}
	keep = keep && c.bootChanged && c.host != nil
	c.proof, c.proofStep, c.proofUntil = sha256.Sum256([]byte(ticket)), c.st.LastStep, now.Add(ProofTTL)
	if err := c.serve(c.v); err != nil {
		c.discard()
		return false, err
	}
	if c.supersedeQuiet > 0 {
		// Restarts that stopped still report their total.
		c.notify("The box unlock was started over " + times(c.supersedeQuiet) + " more before it was unlocked.")
		c.supersedeQuiet = 0
	}
	c.notify("vault unlocked")
	if !keep {
		return false, nil
	}
	if err := c.host.approve(c.v); err != nil {
		c.notify("could not keep this PC trusted (" + err.Error() + "); trust it again from the local page")
		return false, nil
	}
	c.notify("this PC stays trusted on the boot path it started with now")
	return true, nil
}

// checkCode checks a code-generator code against the seed in the open or
// pending vault (CH-4, O6): each 30 s step once, wrong codes counted
// toward the durable cap (CH-18). Caller holds mu and has c.v.
func (c *custody) checkCode(code string, now time.Time) error {
	if until, out := c.lockedOut(now); out {
		return errLockedOut(until)
	}
	sec, ok := c.v.Secret(SeedName)
	if !ok {
		return errNoCodeGenerator
	}
	seed := []byte(sec.Reveal())
	step, ok := owner.MatchTOTP(seed, code, now, c.st.LastStep)
	var skew int64
	near := false
	if !ok {
		skew, near = c.nearMatch(seed, code, now)
	}
	clear(seed)
	if ok {
		next := c.st
		next.LastStep = step
		if err := c.persist(next); err != nil {
			return errInternal
		}
		return nil
	}
	if near {
		return errClockSkew(skew)
	}
	next := c.st
	next.Wrong = append(c.recent(now), now.Unix())
	if err := c.persist(next); err != nil {
		return errInternal
	}
	if until, out := c.lockedOut(now); out {
		return errLockedOut(until)
	}
	return errWrongCode(MaxWrongCodes - len(c.st.Wrong))
}

// serve opens the model route over v. Caller holds mu.
func (c *custody) serve(v *vault.Vault) error {
	p, err := c.build(v)
	if err != nil {
		return errInternal
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	v.OnWarn(c.notify)
	c.ph, c.v, c.proxy, c.expires, c.ticket, c.needPIN = open, v, p, time.Time{}, "", false
	c.bootChanged, c.bootUpdated, c.bootSecure = false, false, false
	return nil
}

// nearMatch finds a code for a step just outside the accepted window, which
// means the box clock and the phone disagree. It returns the difference in
// seconds (positive: the phone is ahead). Caller holds mu.
func (c *custody) nearMatch(seed []byte, code string, now time.Time) (int64, bool) {
	cur := now.Unix() / 30
	for _, s := range []int64{cur + 1, cur + 2, cur - 2, cur - 3} {
		if s <= c.st.LastStep {
			continue
		}
		// With after = s-1 only step s itself can match.
		if _, ok := owner.MatchTOTP(seed, code, time.Unix(s*30, 0), s-1); ok {
			return (s - cur) * 30, true
		}
	}
	return 0, false
}

// persist writes next to the state file, fsynced, and makes it current
// only once it is on disk. Caller holds mu.
func (c *custody) persist(next unlockState) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(c.statePath, raw); err != nil {
		return err
	}
	c.st = next
	return nil
}

// verify checks a code-generator code for the broker's owner channel (CH-4,
// K7), so the seed never leaves this process. It accepts the current step
// or the one before, after both the broker's last step and the durable
// last step the unlock also uses, and spends a step that matches: the step
// is on disk before the answer, so a restart cannot reset it. Only an open
// vault verifies. counted picks the bucket a wrong code is charged to.
func (c *custody) verify(code string, after int64, counted bool) (int64, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return 0, false, errLocked
	}
	now := c.now()
	bucket, limit := &c.wrongSilent, MaxWrongSilent
	if counted {
		bucket, limit = &c.wrongCounted, MaxWrongCounted
	}
	*bucket = since(*bucket, now.Add(-VerifyWindow))
	if len(*bucket) >= limit {
		return 0, false, &pausedError{until: (*bucket)[0].Add(VerifyWindow)}
	}
	if t, isProof := strings.CutPrefix(code, owner.UnlockProofPrefix); isProof {
		sum := sha256.Sum256([]byte(t))
		if now.Before(c.proofUntil) && c.proofStep > after && subtle.ConstantTimeCompare(sum[:], c.proof[:]) == 1 {
			c.proof, c.proofUntil = [32]byte{}, time.Time{} // once
			return c.proofStep, true, nil
		}
		*bucket = append(*bucket, now)
		return 0, false, nil
	}
	seed, ok := c.v.Secret(SeedName)
	if !ok {
		return 0, false, errInternal
	}
	step, ok := owner.MatchTOTP([]byte(seed.Reveal()), code, now, max(after, c.st.LastStep))
	if !ok {
		*bucket = append(*bucket, now)
		return 0, false, nil
	}
	next := c.st
	next.LastStep = step
	if err := c.persist(next); err != nil {
		return 0, false, errInternal
	}
	return step, true, nil
}

// since keeps the times after cut, in place.
func since(ts []time.Time, cut time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	return kept
}

// recent returns the wrong codes inside WrongWindow. Caller holds mu.
func (c *custody) recent(now time.Time) []int64 {
	cut := now.Add(-WrongWindow).Unix()
	var out []int64
	for _, t := range c.st.Wrong {
		if t > cut {
			out = append(out, t)
		}
	}
	return out
}

// lockedOut reports whether the cap is reached, and until when. Caller
// holds mu.
func (c *custody) lockedOut(now time.Time) (time.Time, bool) {
	r := c.recent(now)
	if len(r) < MaxWrongCodes {
		return time.Time{}, false
	}
	oldest := r[len(r)-MaxWrongCodes]
	return time.Unix(oldest, 0).Add(WrongWindow), true
}

// lock discards the key and cancels an unlock in flight. A derivation
// still running keeps the phase at opening until it returns.
func (c *custody) lock() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	if c.ph != opening {
		c.discard()
	}
}

// expire discards a pending unlock whose code did not arrive in time.
func (c *custody) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph == pending && !c.now().Before(c.expires) {
		c.discard()
		c.notify("vault unlock expired without a code; key discarded")
	}
}

// discard closes the vault and returns to locked. Caller holds mu.
func (c *custody) discard() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.v != nil {
		c.v.Close()
	}
	c.v, c.proxy, c.ph, c.expires, c.ticket = nil, nil, locked, time.Time{}, ""
	// The sign-in proof is for this unlock only (#65 security R2).
	c.proof, c.proofUntil = [32]byte{}, time.Time{}
}

// model returns the proxy while the vault is open, else nil.
func (c *custody) model() *egress.Proxy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proxy
}

// put stores a provider API key while the vault is open. Only a built-in
// adapter's credential name is writable, and never over an entry of
// another kind, so the seed and the recovery entries (backup key, restore
// state, Owner Card) cannot be replaced from the local UI.
func (c *custody) put(name string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if !adapterCredential(name) || hasOtherKind(c.v, name, vault.KindAPIKey) {
		return errBadCredential
	}
	if err := c.v.Put(name, vault.KindAPIKey, value); err != nil {
		if errors.Is(err, vault.ErrRolledBack) {
			c.notify(noteRolledBack)
			return errRolledBack
		}
		return errBadCredential
	}
	return nil
}

func adapterCredential(name string) bool {
	for _, a := range adapters() {
		if name != "" && a.Credential == name {
			return true
		}
	}
	return false
}

// hasOtherKind reports whether name exists with a kind other than kind.
func hasOtherKind(v *vault.Vault, name, kind string) bool {
	for _, e := range v.List() {
		if e.Name == name {
			return e.Kind != kind
		}
	}
	return false
}

func hasKind(v *vault.Vault, name, kind string) bool {
	for _, e := range v.List() {
		if e.Name == name {
			return e.Kind == kind
		}
	}
	return false
}

// apiKeysOnly is the vault as the proxy sees it: only provider API keys are
// injectable, so no adapter declaration can send the code-generator seed or
// any other kind upstream. The redactor still covers every value (CRED-7).
type apiKeysOnly struct{ v *vault.Vault }

func (a apiKeysOnly) Secret(name string) (vault.Secret, bool) {
	if !hasKind(a.v, name, vault.KindAPIKey) {
		return vault.Secret{}, false
	}
	return a.v.Secret(name)
}

func (a apiKeysOnly) Redactor() (*vault.Redactor, error) { return a.v.Redactor() }

// writeFileAtomic replaces path with raw, mode 0600, fsynced, so a crash
// leaves the old file or the new one.
func writeFileAtomic(path string, raw []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	serr := d.Sync()
	if err := d.Close(); serr == nil {
		serr = err
	}
	return serr
}

// bootTrusted tries this PC's trusted-host slot once at start, so a
// trusted PC restarts unattended (CRED-8). Anything else leaves the vault
// locked for the unknown-host flow, and the owner is told why.
func (c *custody) bootTrusted() {
	if c.host == nil {
		c.notify("no TPM on this PC: unknown host; unlock with the vault passphrase and a code")
		return
	}
	c.mu.Lock()
	if c.ph != locked {
		c.mu.Unlock()
		return
	}
	c.ph = opening
	gen := c.gen
	c.mu.Unlock()

	v, err := c.host.open("")

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ph = locked
	if c.gen != gen {
		if v != nil {
			v.Close()
		}
		return
	}
	switch {
	case err == nil:
		if err := c.serve(v); err != nil {
			v.Close()
			c.notify("vault opened on this trusted host but the model route failed to start")
			return
		}
		c.notify("vault unlocked on this trusted host")
	case errors.Is(err, tpmseal.ErrNeedPIN):
		c.needPIN = true
		c.notify("trusted host with a boot PIN: enter the PIN on the local page")
	case errors.Is(err, vault.ErrRolledBack):
		c.notify(noteRolledBack)
	case errors.Is(err, vault.ErrCounterMissing):
		c.noteCounterResetLocked()
	case errors.Is(err, errRollbackCheck):
		log.Printf("trusted-host unlock: %v", err)
		c.notify(noteTPMSilent)
	case errors.Is(err, vault.ErrNoSlotOpens):
		c.notify("unknown host: unlock with the vault passphrase and a code")
	case errors.Is(err, tpmseal.ErrNoPolicy), errors.Is(err, tpmseal.ErrPolicy):
		// HW-5a: on a trusted PC this is either an update the box did
		// not approve or a tampered drive; the owner decides.
		c.markBootChanged()
	default:
		log.Printf("trusted-host unlock: %v", err)
		c.notify("This PC couldn't unlock the box by itself. Unlock with your passphrase and a code.")
	}
}

// noteCounterReset tells the owner, once, that this PC's rollback counter
// is gone. noteCounterResetLocked is the same with mu held.
func (c *custody) noteCounterReset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.noteCounterResetLocked()
}

func (c *custody) noteCounterResetLocked() {
	if !c.counterReset {
		c.counterReset = true
		c.notify(noteCounterReset)
	}
}

// markBootChanged notes that this trusted PC booted a path the box never
// approved, and tells the owner which case it most likely is. The release
// comparison reads the drive, which an attacker could edit, so it only
// picks the wording; both cases need the same full unlock. Caller holds mu.
func (c *custody) markBootChanged() {
	c.bootChanged, c.bootUpdated = true, c.host.updated()
	c.bootSecure = c.host.secureBootChanged()
	if c.bootSecure {
		c.notify("Secure Boot settings on this PC changed. If you updated firmware, unlock with your card to keep this PC trusted.")
		return
	}
	if c.bootUpdated {
		c.notify("Box updated. Unlock once with your passphrase and a code; this PC stays trusted after that.")
		return
	}
	c.notify("This PC started the box in a way it hasn't before. If you didn't change anything, the drive may have been tampered with. Unlock only if you're sure.")
}

// bootChange reports, while the vault is not open, whether this trusted
// PC booted an unapproved path, whether that looks like an update, and
// whether only its Secure Boot state changed.
func (c *custody) bootChange() (changed, updated, secureBoot bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph == open {
		return false, false, false
	}
	return c.bootChanged, c.bootUpdated, c.bootSecure
}

// pinWanted reports whether this trusted PC waits for its boot PIN.
func (c *custody) pinWanted() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.needPIN && c.ph == locked
}

// unlockPIN opens the vault through this PC's slot with the boot PIN. The
// TPM counts wrong PINs toward its own lockout; tries are also spaced like
// passphrase tries.
func (c *custody) unlockPIN(pin string) error {
	c.mu.Lock()
	if c.ph != locked {
		c.mu.Unlock()
		return errBusy
	}
	if c.host == nil {
		c.mu.Unlock()
		return errNoTPM
	}
	now := c.now()
	if !c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < MinAttemptGap {
		c.mu.Unlock()
		return errTooSoon
	}
	c.lastAttempt = now
	c.ph = opening
	gen := c.gen
	c.mu.Unlock()

	v, err := c.host.open(pin)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ph = locked
	if c.gen != gen {
		if v != nil {
			v.Close()
		}
		return errUnlockCancelled
	}
	switch {
	case err == nil:
	case errors.Is(err, tpmseal.ErrPIN), errors.Is(err, tpmseal.ErrNeedPIN):
		c.notify("wrong boot PIN on this trusted host")
		return errWrongPIN
	case errors.Is(err, tpmseal.ErrLockout):
		c.notify("this PC's TPM locked out after wrong boot PINs")
		return errPINLockout
	case errors.Is(err, vault.ErrNoSlotOpens):
		return errNotTrusted
	case errors.Is(err, tpmseal.ErrNoPolicy), errors.Is(err, tpmseal.ErrPolicy):
		c.markBootChanged()
		return errBootChanged
	case errors.Is(err, vault.ErrRolledBack):
		c.notify(noteRolledBack)
		return errRolledBack
	case errors.Is(err, vault.ErrCounterMissing):
		c.noteCounterResetLocked()
		return errNotTrusted
	case errors.Is(err, errRollbackCheck):
		log.Printf("trusted-host unlock: %v", err)
		c.notify(noteTPMSilent)
		return errInternal
	default:
		return errInternal
	}
	if err := c.serve(v); err != nil {
		v.Close()
		return err
	}
	c.notify("vault unlocked on this trusted host with its boot PIN")
	return nil
}

// tier4 checks the approval for a trusted-host change (CRED-9, CH-3: an
// approval code plus local confirmation, which is this request arriving
// on the local UI's socket) and returns the open vault.
func (c *custody) tier4(code string) (*vault.Vault, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return nil, errLocked
	}
	if c.host == nil {
		return nil, errNoTPM
	}
	if err := c.checkCode(code, c.now()); err != nil {
		if strings.HasPrefix(err.Error(), "wrong code") {
			c.notify("wrong code for a trusted-host change")
		}
		return nil, err
	}
	return c.v, nil
}

// MinPINLen is the shortest boot PIN, in characters (arbitrator, #42).
const MinPINLen = 6

// trust makes this PC a trusted host (CRED-9): its TPM slot opens the
// vault on this boot path from now on, with the boot PIN if pin is set.
func (c *custody) trust(code, pin string) (string, error) {
	if n := utf8.RuneCountInString(pin); pin != "" && (n < MinPINLen || n > 64) {
		return "", errBadPIN
	}
	v, err := c.tier4(code)
	if err != nil {
		return "", err
	}
	// The counter first: a PC is never trusted without it (V6). A PC
	// whose counter went (ErrCounterMissing) gets a new one here.
	if err := c.host.anchor(v); err != nil {
		if errors.Is(err, vault.ErrRolledBack) {
			return "", errRolledBack
		}
		return "", errHostNotSaved
	}
	c.mu.Lock()
	c.counterReset = false
	c.mu.Unlock()
	name, err := c.host.enroll(v, pin)
	if errors.Is(err, tpmseal.ErrLockoutOwned) {
		return "", errLockoutOwned
	}
	if err != nil {
		return "", errHostNotSaved
	}
	if pin != "" {
		c.notify("this PC is now a trusted host, with a boot PIN: " + name)
	} else {
		c.notify("this PC is now a trusted host: " + name)
	}
	return name, nil
}

// untrust removes the trusted host with the given id (CRED-9).
func (c *custody) untrust(code, id string) (int, error) {
	v, err := c.tier4(code)
	if err != nil {
		return 0, err
	}
	n, err := c.host.remove(v, id)
	if err != nil {
		return 0, errNoSuchHost
	}
	if n == 0 {
		return 0, errNoSuchHost
	}
	c.notify("a trusted host was removed")
	return n, nil
}

// reencrypt moves the open vault to a fresh data key (vault.Reencrypt,
// recovery R10a) and, on a PC with a TPM, to a new policy key with a fresh
// slot for this PC (with pin if it has one) and for every other trusted PC
// that can be sealed while away (trustedHost.reencrypt). owner must prove
// every passphrase and recovery slot. PCs that could not be resealed are
// counted, and the owner is told to trust them again (CRED-9). The caller
// has already checked the tier-4 approval the rotation needs; P2-8's
// lost-card and removed-host commits call this (arbitrator ruling on #45).
func (c *custody) reencrypt(pin string, owner ...vault.Factor) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return 0, errLocked
	}
	var n int
	var err error
	if c.host != nil {
		n, err = c.host.reencrypt(c.v, pin, owner)
	} else {
		n, err = c.v.Reencrypt(owner...)
	}
	switch {
	case err == nil:
	case errors.Is(err, vault.ErrRolledBack):
		c.notify(noteRolledBack)
		return 0, errRolledBack
	case errors.Is(err, errWrongPINReencrypt):
		return 0, errWrongPIN
	default:
		return n, err
	}
	if n > 0 {
		c.notify(fmt.Sprintf("the vault has a new key; %d other trusted PC(s) must be trusted again", n))
	}
	return n, nil
}

// hosts lists the trusted PCs. It needs no approval: names and flags only.
func (c *custody) hosts() ([]hostInfo, error) {
	if c.host == nil {
		return []hostInfo{}, nil
	}
	h, err := c.host.list()
	if err != nil {
		return nil, errInternal
	}
	return h, nil
}
