package main

import (
	"errors"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/owner"
	"github.com/ghbmrk/agentos/broker/vault"
)

// SeedName is the vault entry holding the owner's code-generator seed.
const SeedName = "owner-totp-seed"

// MaxWrongCodes wrong unlock codes within WrongWindow refuse further
// unlocks until the oldest ages out. Each try costs the passphrase and an
// Argon2id run, and every pending unlock is reported to the owner.
const (
	MaxWrongCodes = 3
	WrongWindow   = 24 * time.Hour
)

// MaxWrongVerifies wrong codes from the broker within VerifyWindow refuse
// further verifies until the oldest ages out (K7). The channel counts and
// locks on its own; this bound holds even if agentosd is taken over, and
// stays above what the channel lets through for the owner (5 wrong codes
// lock it, and challenge mode allows one attempt per texted token).
const (
	MaxWrongVerifies = 10
	VerifyWindow     = 10 * time.Minute
)

// Fixed errors, safe to show on the unlock socket.
var (
	errBusy            = errors.New("an unlock is already in progress or the vault is open")
	errWrongPassphrase = errors.New("the passphrase does not open this vault")
	errNoCodeGenerator = errors.New("no code generator is enrolled in this vault")
	errNotPending      = errors.New("no unlock is waiting for a code")
	errWrongCode       = errors.New("wrong or expired code; the unlocked key was discarded")
	errTooManyWrong    = errors.New("too many wrong codes; unlock is refused for now")
	errLocked          = errors.New("the vault is locked")
	errUnlockCancelled = errors.New("the unlock was cancelled")
	errBadCredential   = errors.New("credential name or value refused")
	errInternal        = errors.New("internal error")
)

type phase int

const (
	locked  phase = iota
	opening       // the passphrase is being checked (Argon2id)
	pending       // decrypted, waiting for the approval code
	open          // serving the model route
)

func (p phase) String() string { return [...]string{"locked", "opening", "pending", "open"}[p] }

// custody is the unknown-host unlock (CRED-8): the vault passphrase
// decrypts the vault, and an approval code from the owner's code generator,
// checked against the seed inside the vault, authorizes it. Until the code
// arrives the vault is held but nothing is served; a wrong code, or none
// within ttl, discards the key. Only an open vault serves the model route.
type custody struct {
	// open decrypts the vault with a passphrase (vault.OpenSealed).
	open func(passphrase string) (*vault.Vault, error)
	// build makes the egress proxy over an open vault.
	build func(*vault.Vault) (*egress.Proxy, error)
	ttl   time.Duration
	now   func() time.Time
	// notify reports unlock events for the owner (CRED-8 visibility).
	notify func(string)

	mu      sync.Mutex
	ph      phase
	gen     int // bumped by lock, so an unlock in flight is cancelled
	v       *vault.Vault
	proxy   *egress.Proxy
	expires time.Time
	timer   *time.Timer
	// lastStep is the last code-generator step accepted, by confirm or
	// verify, so a code works once across both (O6, K7).
	lastStep    int64
	wrong       []time.Time
	wrongVerify []time.Time
}

// status reports the phase and, while pending, when the code is due.
func (c *custody) status() (phase, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ph, c.expires
}

// unlock checks the passphrase and, if it opens the vault, waits for the
// code. A passphrase alone never opens the model route.
func (c *custody) unlock(passphrase string) error {
	c.mu.Lock()
	if c.ph != locked {
		c.mu.Unlock()
		return errBusy
	}
	if c.recentWrong() >= MaxWrongCodes {
		c.mu.Unlock()
		return errTooManyWrong
	}
	c.ph = opening
	gen := c.gen
	c.mu.Unlock()

	v, err := c.open(passphrase)

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		if v != nil {
			v.Close()
		}
		return errUnlockCancelled
	}
	if err != nil {
		c.ph = locked
		if errors.Is(err, vault.ErrNoSlotOpens) {
			return errWrongPassphrase
		}
		return errInternal
	}
	if _, ok := v.Secret(SeedName); !ok || !hasKind(v, SeedName, vault.KindTOTPSeed) {
		v.Close()
		c.ph = locked
		return errNoCodeGenerator
	}
	c.ph, c.v = pending, v
	c.expires = c.now().Add(c.ttl)
	c.timer = time.AfterFunc(c.ttl, c.expire)
	c.notify("vault passphrase accepted; waiting for an approval code")
	return nil
}

// confirm checks the approval code against the seed inside the vault. Any
// failure discards the key; the next try needs the passphrase again.
func (c *custody) confirm(code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != pending {
		return errNotPending
	}
	now := c.now()
	if !now.Before(c.expires) {
		c.discard()
		c.notify("vault unlock expired without a code; key discarded")
		return errWrongCode
	}
	seed, _ := c.v.Secret(SeedName)
	step, ok := owner.MatchTOTP([]byte(seed.Reveal()), code, now, c.lastStep)
	if !ok {
		c.wrong = append(c.wrong, now)
		c.discard()
		c.notify("wrong approval code for a vault unlock; key discarded")
		return errWrongCode
	}
	p, err := c.build(c.v)
	if err != nil {
		c.discard()
		return errInternal
	}
	c.lastStep = step
	c.timer.Stop()
	c.ph, c.proxy, c.expires = open, p, time.Time{}
	c.notify("vault unlocked")
	return nil
}

// verify checks a code-generator code for the broker's owner channel (CH-4,
// K7), so the seed never leaves this process. It accepts the current step
// or the one before, after both the broker's last step and this process's
// own, and spends a step that matches. Only an open vault verifies.
func (c *custody) verify(code string, after int64) (int64, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return 0, false, errLocked
	}
	now := c.now()
	c.wrongVerify = since(c.wrongVerify, now.Add(-VerifyWindow))
	if len(c.wrongVerify) >= MaxWrongVerifies {
		return 0, false, errTooManyWrong
	}
	seed, _ := c.v.Secret(SeedName)
	step, ok := owner.MatchTOTP([]byte(seed.Reveal()), code, now, max(after, c.lastStep))
	if !ok {
		c.wrongVerify = append(c.wrongVerify, now)
		return 0, false, nil
	}
	c.lastStep = step
	return step, true, nil
}

// lock discards the key in any phase and cancels an unlock in flight.
func (c *custody) lock() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gen++
	c.discard()
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
	c.v, c.proxy, c.ph, c.expires = nil, nil, locked, time.Time{}
}

// model returns the proxy while the vault is open, else nil.
func (c *custody) model() *egress.Proxy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.proxy
}

// put stores a provider API key while the vault is open. The seed and other
// kinds are not writable here.
func (c *custody) put(name string, value []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ph != open {
		return errLocked
	}
	if name == "" || name == SeedName || len(name) > 64 {
		return errBadCredential
	}
	if err := c.v.Put(name, vault.KindAPIKey, value); err != nil {
		return errBadCredential
	}
	return nil
}

// recentWrong counts wrong codes inside WrongWindow and forgets older ones.
// Caller holds mu.
func (c *custody) recentWrong() int {
	c.wrong = since(c.wrong, c.now().Add(-WrongWindow))
	return len(c.wrong)
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
