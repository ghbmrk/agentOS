package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/owner"
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
)

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
	// wrongPassAt is when the owner was last told of a wrong passphrase;
	// wrongPassQuiet counts those since, untold (WrongPassNoteEvery).
	wrongPassAt    time.Time
	wrongPassQuiet int
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

// unlock checks the passphrase and, if it opens the vault, returns the
// ticket its confirm must carry. A passphrase alone never opens the model
// route. One derivation runs at a time: the phase stays opening until it
// returns, even if lock cancels it meanwhile.
// WrongPassNoteEvery bounds how often the owner is told of wrong vault
// passphrases. They are not counted toward any lockout (nobody without the
// card can lock the owner out), but repeated ones may be someone on the
// box's Wi-Fi starving the owner's unlock, so the owner hears of them.
const WrongPassNoteEvery = 10 * time.Minute

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

func (c *custody) unlock(passphrase string) (string, error) {
	c.mu.Lock()
	if c.ph != locked {
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
	c.ph = opening
	gen := c.gen
	c.mu.Unlock()

	v, err := c.open(passphrase)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.ph = locked
	if c.gen != gen {
		if v != nil {
			v.Close()
		}
		return "", errUnlockCancelled
	}
	if err != nil {
		if errors.Is(err, vault.ErrNoSlotOpens) {
			c.noteWrongPassLocked(now)
			return "", errWrongPassphrase
		}
		return "", errInternal
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
	c.ph, c.v, c.ticket = pending, v, hex.EncodeToString(b)
	c.expires = now.Add(c.ttl)
	c.timer = time.AfterFunc(c.ttl, c.expire)
	if c.wrongPassQuiet > 0 {
		// A burst that stopped still reports its total.
		c.notify(fmt.Sprintf("%d more wrong vault passphrases were tried on the box's Wi-Fi since the last notice", c.wrongPassQuiet))
		c.wrongPassQuiet = 0
	}
	c.notify("vault passphrase accepted; waiting for a code-generator code")
	return c.ticket, nil
}

// confirm checks a code-generator code against the seed inside the vault.
// A wrong code counts toward the durable cap and leaves the unlock pending
// until its expiry, unless the cap is reached; then the key is discarded.
func (c *custody) confirm(ticket, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != pending || subtle.ConstantTimeCompare([]byte(ticket), []byte(c.ticket)) != 1 {
		return errNotPending
	}
	now := c.now()
	if !now.Before(c.expires) {
		c.discard()
		c.notify("vault unlock expired without a code; key discarded")
		return errExpired
	}
	sec, _ := c.v.Secret(SeedName)
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
			c.discard()
			return errInternal
		}
		p, err := c.build(c.v)
		if err != nil {
			c.discard()
			return errInternal
		}
		c.timer.Stop()
		c.ph, c.proxy, c.expires, c.ticket = open, p, time.Time{}, ""
		c.notify("vault unlocked")
		return nil
	}
	if near {
		return errClockSkew(skew)
	}
	next := c.st
	next.Wrong = append(c.recent(now), now.Unix())
	if err := c.persist(next); err != nil {
		c.discard()
		return errInternal
	}
	if until, out := c.lockedOut(now); out {
		c.discard()
		c.notify("too many wrong codes for a vault unlock; key discarded")
		return errLockedOut(until)
	}
	c.notify("wrong code for a vault unlock")
	return errWrongCode(MaxWrongCodes - len(c.st.Wrong))
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
