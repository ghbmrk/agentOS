package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/egress"
	"github.com/ghbmrk/agentos/broker/vault"
)

// REQ: CRED-8, CRED-1, CH-4

// totp computes the owner's code-generator code at t (RFC 6238, SHA-1,
// 30 s, 6 digits), as the owner's phone does.
func totp(seed []byte, t time.Time) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(t.Unix()/30))
	m := hmac.New(sha1.New, seed)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

func synthetic(t *testing.T, prefix string) string {
	t.Helper()
	b := make([]byte, 16)
	rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fastRig stands the Argon2id slot in with a raw-key open, so the unlock
// rules run without paying 256 MiB per try. server_test.go runs the real
// slot end to end.
type fastRig struct {
	c     *custody
	clk   *clock
	seed  []byte
	notes []string
	opens int
}

const goodPass = "the right passphrase"

func newFastRig(t *testing.T, withSeed bool) *fastRig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault")
	key := make([]byte, vault.KeySize)
	rand.Read(key)
	v, err := vault.Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	r := &fastRig{clk: &clock{t: time.Unix(1_800_000_000, 0)}, seed: []byte(synthetic(t, "seed-"))}
	if withSeed {
		if err := v.Put(SeedName, vault.KindTOTPSeed, r.seed); err != nil {
			t.Fatal(err)
		}
	}
	v.Put("openai", vault.KindAPIKey, []byte(synthetic(t, "sk-canary-")))
	v.Close()
	r.c = &custody{
		open: func(p string) (*vault.Vault, error) {
			r.opens++
			if p != goodPass {
				return nil, vault.ErrNoSlotOpens
			}
			return vault.Open(path, key)
		},
		build: func(v *vault.Vault) (*egress.Proxy, error) {
			return newProxy(v, map[string][]string{"agent": {"openai"}}, nil)
		},
		ttl:    15 * time.Minute,
		now:    r.clk.now,
		notify: func(s string) { r.notes = append(r.notes, s) },
	}
	t.Cleanup(r.c.lock)
	return r
}

func (r *fastRig) code() string { return totp(r.seed, r.clk.now()) }

func (r *fastRig) phase() phase { p, _ := r.c.status(); return p }

// CRED-8, A8: a running box refuses unlock by passphrase alone. The
// passphrase decrypts, but nothing is served until the code arrives, and
// the owner is told an unlock is pending.
func TestPassphraseAloneDoesNotOpenTheModelRoute(t *testing.T) {
	r := newFastRig(t, true)
	if err := r.c.unlock(goodPass); err != nil {
		t.Fatal(err)
	}
	if r.phase() != pending || r.c.model() != nil {
		t.Fatalf("after passphrase: %v, proxy %v", r.phase(), r.c.model())
	}
	if len(r.notes) != 1 {
		t.Fatalf("owner not told: %v", r.notes)
	}
	if err := r.c.confirm(r.code()); err != nil {
		t.Fatal(err)
	}
	if r.phase() != open || r.c.model() == nil {
		t.Fatalf("after code: %v", r.phase())
	}
}

// A8: the code alone does not unlock either.
func TestCodeAloneDoesNotUnlock(t *testing.T) {
	r := newFastRig(t, true)
	if err := r.c.confirm(r.code()); err != errNotPending {
		t.Fatalf("code with no passphrase: %v", err)
	}
	if r.phase() != locked {
		t.Fatal(r.phase())
	}
}

// CRED-8: a wrong code discards the unlocked key; the next try needs the
// passphrase again, and a right code then is too late.
func TestWrongCodeDiscardsTheKey(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	if err := r.c.confirm("000000"); err != errWrongCode {
		t.Fatalf("wrong code: %v", err)
	}
	if r.phase() != locked || r.c.v != nil {
		t.Fatalf("key kept after a wrong code: %v", r.phase())
	}
	if err := r.c.confirm(r.code()); err != errNotPending {
		t.Fatalf("right code after discard: %v", err)
	}
}

// CRED-8: no code within the request's expiry discards the key, whether
// the timer fires or a late code arrives first.
func TestNoCodeWithinExpiryDiscardsTheKey(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	r.clk.add(15 * time.Minute)
	if err := r.c.confirm(r.code()); err != errWrongCode || r.phase() != locked {
		t.Fatalf("late code: %v, %v", err, r.phase())
	}

	r.c.unlock(goodPass)
	r.clk.add(15 * time.Minute)
	r.c.expire()
	if r.phase() != locked || r.c.v != nil {
		t.Fatalf("expiry kept the key: %v", r.phase())
	}
}

// CH-18 for the unlock path: wrong codes are bounded. After MaxWrongCodes
// in the window the passphrase is not even tried; the window ages out.
// Wrong passphrases are not counted, so no one without the card can lock
// the owner out.
func TestWrongCodesAreBounded(t *testing.T) {
	r := newFastRig(t, true)
	for i := 0; i < 5; i++ {
		if err := r.c.unlock("not it"); err != errWrongPassphrase {
			t.Fatalf("wrong passphrase: %v", err)
		}
	}
	for i := 0; i < MaxWrongCodes; i++ {
		if err := r.c.unlock(goodPass); err != nil {
			t.Fatal(err)
		}
		r.c.confirm("000000")
	}
	before := r.opens
	if err := r.c.unlock(goodPass); err != errTooManyWrong {
		t.Fatalf("after %d wrong codes: %v", MaxWrongCodes, err)
	}
	if r.opens != before {
		t.Fatal("passphrase tried while refused")
	}
	r.clk.add(WrongWindow)
	if err := r.c.unlock(goodPass); err != nil {
		t.Fatalf("after the window: %v", err)
	}
}

// O6 for the unlock path: each code works once.
func TestCodeWorksOnce(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	code := r.code()
	if err := r.c.confirm(code); err != nil {
		t.Fatal(err)
	}
	r.c.lock()
	r.c.unlock(goodPass)
	if err := r.c.confirm(code); err != errWrongCode {
		t.Fatalf("replayed code: %v", err)
	}
}

// Fail closed: a vault with no code-generator seed cannot be unlocked by
// passphrase (the code is what makes an unexpected unlock visible).
func TestVaultWithoutSeedIsRefused(t *testing.T) {
	r := newFastRig(t, false)
	if err := r.c.unlock(goodPass); err != errNoCodeGenerator || r.phase() != locked {
		t.Fatalf("no seed: %v, %v", err, r.phase())
	}
}

// Lock discards an open vault, and cancels an unlock whose passphrase is
// still being checked.
func TestLockDiscardsAndCancels(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	r.c.confirm(r.code())
	r.c.lock()
	if r.phase() != locked || r.c.model() != nil {
		t.Fatal("lock kept the vault open")
	}

	release := make(chan struct{})
	inner := r.c.open
	r.c.open = func(p string) (*vault.Vault, error) { <-release; return inner(p) }
	done := make(chan error)
	go func() { done <- r.c.unlock(goodPass) }()
	for r.phase() != opening {
		time.Sleep(time.Millisecond)
	}
	if err := r.c.unlock(goodPass); err != errBusy {
		t.Fatalf("second unlock while opening: %v", err)
	}
	r.c.lock()
	close(release)
	if err := <-done; err != errUnlockCancelled || r.phase() != locked {
		t.Fatalf("cancelled unlock: %v, %v", err, r.phase())
	}
}

// Only provider API keys are injectable: no adapter can send the seed.
func TestProxySeesOnlyAPIKeys(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	a := apiKeysOnly{r.c.v}
	if _, ok := a.Secret(SeedName); ok {
		t.Fatal("seed injectable")
	}
	if _, ok := a.Secret("openai"); !ok {
		t.Fatal("api key not injectable")
	}
	if err := r.c.put("x-key", []byte(synthetic(t, "sk-"))); err != errLocked {
		t.Fatalf("put while pending: %v", err)
	}
	r.c.confirm(r.code())
	if err := r.c.put(SeedName, []byte(synthetic(t, "sk-"))); err != errBadCredential {
		t.Fatalf("seed overwritten: %v", err)
	}
	if err := r.c.put("anthropic", []byte(synthetic(t, "sk-ant-"))); err != nil {
		t.Fatal(err)
	}
}

// K7: the broker's high-tier check runs here, against the seed in the
// vault, and only while the vault is open. A pending vault holds the seed
// but serves nothing, verify included.
func TestVerifyNeedsAnOpenVault(t *testing.T) {
	r := newFastRig(t, true)
	if _, _, err := r.c.verify(r.code(), 0); err != errLocked {
		t.Fatalf("locked: %v", err)
	}
	r.c.unlock(goodPass)
	if _, _, err := r.c.verify(r.code(), 0); err != errLocked {
		t.Fatalf("pending: %v", err)
	}
	if r.phase() != pending {
		t.Fatalf("verify changed the unlock: %v", r.phase())
	}
}

// K7, O6: the unlock and the broker share one last step, so the code that
// unlocked the vault is not accepted again for the channel, and each code
// the channel uses works once whatever after the broker sends.
func TestVerifySharesTheLastStepWithUnlock(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	used := r.code()
	if err := r.c.confirm(used); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := r.c.verify(used, 0); ok || err != nil {
		t.Fatalf("unlock code accepted for the channel: %v %v", ok, err)
	}
	r.clk.add(30 * time.Second)
	code := r.code()
	step, ok, err := r.c.verify(code, 0)
	if !ok || err != nil || step != r.clk.now().Unix()/30 {
		t.Fatalf("fresh code: %d %v %v", step, ok, err)
	}
	if _, ok, _ := r.c.verify(code, 0); ok {
		t.Fatal("code accepted twice")
	}
	r.clk.add(30 * time.Second)
	if _, ok, _ := r.c.verify(r.code(), r.clk.now().Unix()/30); ok {
		t.Fatal("code at or before the broker's last step accepted")
	}
}

// A broker that has been taken over cannot grind codes: wrong verifies are
// bounded here, independently of the channel's own counting, and the bound
// ages out.
func TestWrongVerifiesAreBounded(t *testing.T) {
	r := newFastRig(t, true)
	r.c.unlock(goodPass)
	r.c.confirm(r.code())
	r.clk.add(30 * time.Second)
	for i := 0; i < MaxWrongVerifies; i++ {
		if _, ok, err := r.c.verify("000000", 0); ok || err != nil {
			t.Fatalf("wrong verify %d: %v %v", i, ok, err)
		}
	}
	if _, _, err := r.c.verify(r.code(), 0); err != errTooManyWrong {
		t.Fatalf("after %d wrong: %v", MaxWrongVerifies, err)
	}
	r.clk.add(VerifyWindow)
	if _, ok, err := r.c.verify(r.code(), 0); !ok || err != nil {
		t.Fatalf("after the window: %v %v", ok, err)
	}
	if r.phase() != open {
		t.Fatal("wrong verifies changed the vault")
	}
}
