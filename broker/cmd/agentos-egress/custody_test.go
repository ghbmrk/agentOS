package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	path  string
	key   []byte
	state string
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
	r := &fastRig{clk: &clock{t: time.Unix(1_800_000_000, 0)}, seed: []byte(synthetic(t, "seed-")), path: path, key: key}
	if withSeed {
		if err := v.Put(SeedName, vault.KindTOTPSeed, r.seed); err != nil {
			t.Fatal(err)
		}
	}
	v.Put("openai", vault.KindAPIKey, []byte(synthetic(t, "sk-canary-")))
	v.Close()
	r.state = filepath.Join(filepath.Dir(path), "unlock.json")
	r.build(t)
	return r
}

// build makes (or, after a restart, remakes) the custody over the same
// vault and state file.
func (r *fastRig) build(t *testing.T) {
	t.Helper()
	path := r.path
	key := r.key
	c, err := newCustody(&custody{
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
		ttl:       15 * time.Minute,
		now:       r.clk.now,
		notify:    func(s string) { r.notes = append(r.notes, s) },
		statePath: r.state,
	})
	if err != nil {
		t.Fatal(err)
	}
	r.c = c
	t.Cleanup(c.lock)
}

func (r *fastRig) code() string { return totp(r.seed, r.clk.now()) }

func (r *fastRig) phase() phase { p, _ := r.c.status(); return p }

// unlock waits out the attempt gap first, as a person would.
func (r *fastRig) unlock(t *testing.T) string {
	t.Helper()
	r.clk.add(MinAttemptGap)
	tk, err := r.c.unlock(goodPass)
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func msg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// CRED-8, A8: a running box refuses unlock by passphrase alone. The
// passphrase decrypts, but nothing is served until the code arrives, and
// the owner is told an unlock is pending.
func TestPassphraseAloneDoesNotOpenTheModelRoute(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	if r.phase() != pending || r.c.model() != nil || tk == "" {
		t.Fatalf("after passphrase: %v", r.phase())
	}
	if len(r.notes) != 1 {
		t.Fatalf("owner not told: %v", r.notes)
	}
	if err := r.c.confirm(tk, r.code()); err != nil {
		t.Fatal(err)
	}
	if r.phase() != open || r.c.model() == nil {
		t.Fatalf("after code: %v", r.phase())
	}
}

// A8: the code alone does not unlock either, and a confirm must carry the
// ticket of the unlock it answers.
func TestCodeAloneDoesNotUnlock(t *testing.T) {
	r := newFastRig(t, true)
	if err := r.c.confirm("", r.code()); err != errNotPending {
		t.Fatalf("code with no passphrase: %v", err)
	}
	r.unlock(t)
	if err := r.c.confirm("someone-elses-ticket", r.code()); err != errNotPending {
		t.Fatalf("wrong ticket: %v", err)
	}
	if r.phase() != pending || len(r.c.st.Wrong) != 0 {
		t.Fatal("a wrong ticket changed the unlock")
	}
}

// K5: a wrong code counts, durably, but keeps the unlock pending so the
// owner can retype it; the right code then opens the vault.
func TestWrongCodeCountsButKeepsTheUnlockPending(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	if err := r.c.confirm(tk, "000000"); msg(err) != "wrong code; 2 tries left" {
		t.Fatalf("wrong code: %v", err)
	}
	if r.phase() != pending {
		t.Fatalf("pending dropped after a wrong code: %v", r.phase())
	}
	st, _ := loadState(r.state)
	if len(st.Wrong) != 1 {
		t.Fatalf("wrong code not on disk: %+v", st)
	}
	if err := r.c.confirm(tk, r.code()); err != nil || r.phase() != open {
		t.Fatalf("right code after a wrong one: %v %v", err, r.phase())
	}
}

// CRED-8: no code within the request's expiry discards the key, whether
// the timer fires or a late code arrives first.
func TestNoCodeWithinExpiryDiscardsTheKey(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	r.clk.add(15 * time.Minute)
	if err := r.c.confirm(tk, r.code()); err != errExpired || r.phase() != locked {
		t.Fatalf("late code: %v, %v", err, r.phase())
	}

	r.unlock(t)
	r.clk.add(15 * time.Minute)
	r.c.expire()
	if r.phase() != locked || r.c.v != nil {
		t.Fatalf("expiry kept the key: %v", r.phase())
	}
}

// CH-18 for the unlock path: wrong codes are capped, the cap survives a
// restart, the refusal says when unlocking works again, and the passphrase
// is not even tried meanwhile. Wrong passphrases are not counted, so no
// one without the card can lock the owner out.
func TestWrongCodesAreCappedAcrossRestarts(t *testing.T) {
	r := newFastRig(t, true)
	for i := 0; i < 5; i++ {
		r.clk.add(MinAttemptGap)
		if _, err := r.c.unlock("not it"); err != errWrongPassphrase {
			t.Fatalf("wrong passphrase: %v", err)
		}
	}
	tk := r.unlock(t)
	r.c.confirm(tk, "000000")
	r.c.confirm(tk, "000000")

	r.c.lock()
	r.build(t) // a crash or restart
	tk = r.unlock(t)
	err := r.c.confirm(tk, "000000")
	until := time.Unix(1_800_000_000, 0).Add(5*MinAttemptGap + MinAttemptGap + WrongWindow)
	want := "Too many wrong codes. Unlock again after " + until.Local().Format("Mon 15:04") + "."
	if msg(err) != want || r.phase() != locked {
		t.Fatalf("third wrong code: %q, %v; want %q", msg(err), r.phase(), want)
	}
	r.build(t)
	before := r.opens
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); msg(err) != want {
		t.Fatalf("after restart: %v", err)
	}
	if r.opens != before {
		t.Fatal("passphrase tried while locked out")
	}
	r.clk.add(WrongWindow)
	r.unlock(t)
}

// O6 for the unlock path: each code works once, across restarts too.
func TestCodeWorksOnceAcrossRestarts(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	code := r.code()
	if err := r.c.confirm(tk, code); err != nil {
		t.Fatal(err)
	}
	r.c.lock()
	r.build(t)
	tk = r.unlock(t)
	if err := r.c.confirm(tk, code); err == nil || r.phase() == open {
		t.Fatalf("replayed code accepted: %v", err)
	}
}

// A code one or two steps outside the window means the clocks disagree:
// it is refused, says so, and does not count.
func TestClockSkewIsReportedNotCounted(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	ahead := totp(r.seed, r.clk.now().Add(60*time.Second))
	err := r.c.confirm(tk, ahead)
	if err == nil || !strings.Contains(msg(err), "differ by about") || len(r.c.st.Wrong) != 0 || r.phase() != pending {
		t.Fatalf("skewed code: %v, %d wrong, %v", err, len(r.c.st.Wrong), r.phase())
	}
}

// One Argon2id derivation at a time: a lock during the derivation cancels
// the unlock but keeps the phase at opening until the derivation returns,
// so a second unlock is busy rather than a second 256 MiB derivation.
// Attempts are also spaced, without counting as wrong.
func TestOneDerivationAtATime(t *testing.T) {
	r := newFastRig(t, true)
	release := make(chan struct{})
	var running, peak int32
	var mu sync.Mutex
	inner := r.c.open
	r.c.open = func(p string) (*vault.Vault, error) {
		mu.Lock()
		running++
		if running > peak {
			peak = running
		}
		mu.Unlock()
		<-release
		mu.Lock()
		running--
		mu.Unlock()
		return inner(p)
	}
	done := make(chan error)
	r.clk.add(MinAttemptGap)
	go func() { _, err := r.c.unlock(goodPass); done <- err }()
	for r.phase() != opening {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		r.c.lock()
		r.clk.add(MinAttemptGap)
		if _, err := r.c.unlock(goodPass); err != errBusy {
			t.Fatalf("unlock during a cancelled derivation: %v", err)
		}
	}
	if r.phase() != opening {
		t.Fatalf("lock left the derivation: %v", r.phase())
	}
	close(release)
	if err := <-done; err != errUnlockCancelled || r.phase() != locked {
		t.Fatalf("cancelled unlock: %v, %v", err, r.phase())
	}
	if peak != 1 {
		t.Fatalf("%d derivations at once", peak)
	}
	r.c.open = inner
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock("not it"); err != errWrongPassphrase {
		t.Fatal(err)
	}
	if _, err := r.c.unlock(goodPass); err != errTooSoon {
		t.Fatalf("attempt inside the gap: %v", err)
	}
	if len(r.c.st.Wrong) != 0 {
		t.Fatal("spaced attempts counted as wrong")
	}
}

// Fail closed: a vault with no code-generator seed cannot be unlocked by
// passphrase (the code is what makes an unexpected unlock visible), and an
// unreadable state file stops the process from starting.
func TestFailsClosed(t *testing.T) {
	r := newFastRig(t, false)
	r.clk.add(MinAttemptGap)
	if _, err := r.c.unlock(goodPass); err != errNoCodeGenerator || r.phase() != locked {
		t.Fatalf("no seed: %v, %v", err, r.phase())
	}
	os.WriteFile(r.state, []byte("{not json"), 0o600)
	if _, err := newCustody(&custody{statePath: r.state}); err == nil {
		t.Fatal("unreadable state accepted")
	}
}

// Lock discards an open vault.
func TestLockDiscards(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
	r.c.confirm(tk, r.code())
	r.c.lock()
	if r.phase() != locked || r.c.model() != nil {
		t.Fatal("lock kept the vault open")
	}
}

// Only provider API keys are injectable: no adapter can send the seed.
func TestProxySeesOnlyAPIKeys(t *testing.T) {
	r := newFastRig(t, true)
	tk := r.unlock(t)
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
	r.c.confirm(tk, r.code())
	if err := r.c.put(SeedName, []byte(synthetic(t, "sk-"))); err != errBadCredential {
		t.Fatalf("seed overwritten: %v", err)
	}
	if err := r.c.put("anthropic", []byte(synthetic(t, "sk-ant-"))); err != nil {
		t.Fatal(err)
	}
}
