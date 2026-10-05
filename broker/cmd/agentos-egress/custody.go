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
	"strings"
	"sync"
	"time"

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
	errBadPIN       = uerr(http.StatusBadRequest, "a boot PIN has 4 to 64 characters")
	errWrongPIN     = uerr(http.StatusForbidden, "wrong PIN; this PC's TPM limits how many tries it allows")
	errPINLockout   = uerr(http.StatusTooManyRequests, "this PC's TPM is locked after wrong PINs; unlock with the vault passphrase and a code instead")
	errNotTrusted   = uerr(http.StatusConflict, "this PC is not a trusted host; unlock with the vault passphrase and a code")
	errBootChanged  = uerr(http.StatusConflict, "this PC's boot path changed since it was trusted; unlock with the vault passphrase and a code")
	errNoSuchHost   = uerr(http.StatusNotFound, "no trusted host with that id")
	errHostNotSaved = uerr(http.StatusInternalServerError, "could not make this PC trusted; nothing was changed")
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
	if err := c.checkCode(code, now); err != nil {
		var ue *unlockErr
		switch {
		case !errors.As(err, &ue) || ue == errInternal:
			c.discard()
			return errInternal
		case ue.status == http.StatusTooManyRequests:
			c.discard()
			c.notify("too many wrong codes for a vault unlock; key discarded")
		case strings.HasPrefix(ue.msg, "wrong code"):
			c.notify("wrong code for a vault unlock")
		}
		return err
	}
	if err := c.serve(c.v); err != nil {
		c.discard()
		return err
	}
	c.notify("vault unlocked")
	return nil
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
	c.ph, c.v, c.proxy, c.expires, c.ticket, c.needPIN = open, v, p, time.Time{}, "", false
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

// put stores a provider API key while the vault is open. The seed, the
// policy key, and other kinds are not writable here.
func (c *custody) put(name string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if name == "" || name == SeedName || name == PolicyKeyName || len(name) > 64 {
		return errBadCredential
	}
	for _, e := range c.v.List() {
		if e.Name == name && e.Kind != vault.KindAPIKey {
			return errBadCredential
		}
	}
	if err := c.v.Put(name, vault.KindAPIKey, value); err != nil {
		return errBadCredential
	}
	return nil
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
	case errors.Is(err, vault.ErrNoSlotOpens):
		c.notify("unknown host: unlock with the vault passphrase and a code")
	case errors.Is(err, tpmseal.ErrNoPolicy), errors.Is(err, tpmseal.ErrPolicy):
		// HW-5a: on a trusted PC this is either an update the box did
		// not approve or a tampered drive; the owner decides.
		c.notify("this trusted PC's boot path changed, so the vault stayed locked. If you did not just update the box, the drive may have been tampered with. Unlock with the vault passphrase and a code.")
	default:
		c.notify("trusted-host unlock failed (" + err.Error() + "); unlock with the vault passphrase and a code")
	}
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
		return errBootChanged
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

// trust makes this PC a trusted host (CRED-9): its TPM slot opens the
// vault on this boot path from now on, with the boot PIN if pin is set.
func (c *custody) trust(code, pin string) (string, error) {
	if pin != "" && (len(pin) < 4 || len(pin) > 64) {
		return "", errBadPIN
	}
	v, err := c.tier4(code)
	if err != nil {
		return "", err
	}
	name, err := c.host.enroll(v, pin)
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
