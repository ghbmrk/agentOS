// Package loopstest is a spare envelope over an in-memory kernel, for tests
// of the loop scheduler and its callers. It does not import loops, so the
// scheduler's own tests can use it: a test builds its loops.Spare from
// State, Envelope, Holder, Widen, Revoke and OutPerM.
package loopstest

import (
	"crypto/ed25519"
	"math/rand/v2"
	"strconv"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// OutPerM is the test route's output price: one minor unit per 100 tokens,
// so one spare call (loops.TokensPerCall) costs 100.
const OutPerM = 10_000

// core.txt grants this package kernel.* because only tests link it. The
// guard holds that wherever the files are reached from (a symlink, a
// vendored copy, a build tag): a binary go test did not build stops here
// (core/ASSUMPTIONS.md, CORE-fixture-imports-a).
func init() {
	if !testing.Testing() {
		panic("loopstest is a test fixture: linked into a binary go test did not build")
	}
}

// EnvelopeCap is the day cap the owner grants the envelope: the no-budget
// cap, loops.SpareCap(loops.NoSpareBudget, OutPerM), which every lower
// budget narrows.
const EnvelopeCap = 150_000

// Kernel is a kernel over an in-memory log, a spare envelope granted by the
// owner on it, and the passkeys that granted it.
type Kernel struct {
	K        *kernel.Kernel
	Envelope key.Key
	Holder   ed25519.PrivateKey
	// Widened counts the owner's widenings (Widen).
	Widened int

	t      testing.TB
	now    func() time.Time
	owner  ed25519.PrivateKey
	second ed25519.PrivateKey
	root   key.Key
	n      int
}

func gen(seed byte) ed25519.PrivateKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	return ed25519.NewKeyFromSeed(s)
}

// New boots a kernel and grants the spare envelope, live from now. Raising
// the cap past EnvelopeCap goes through the owner's passkey (Widen).
func New(t testing.TB, now func() time.Time) *Kernel {
	t.Helper()
	k := &Kernel{t: t, now: now, owner: gen(1), second: gen(12), Holder: gen(2)}
	head := gen(3)
	anchors := []ed25519.PublicKey{k.pub(k.owner), k.pub(k.second)}
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{},
		Pub: k.pub(head), Sign: head, Rand: rand.NewChaCha8([32]byte{1})})
	k.must(err)
	at := k.ms()
	k.K, err = kernel.Boot(l, anchors, map[string]kernel.Clerk{}, at)
	k.must(err)
	k.root = key.Issue(k.owner, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "spare"})
	k.Envelope = k.grant(at-kernel.GrantHold, EnvelopeCap, k.root)
	return k
}

// State is the kernel's state, for loops.Spare.State.
func (k *Kernel) State() *kernel.State { return k.K.State() }

// Widen is the owner's passkey granting a fresh envelope with day cap n, for
// loops.Spare.Widen. Like any grant it is live after the hold.
func (k *Kernel) Widen(n int64) (key.Key, error) {
	k.Widened++
	return k.grant(k.ms(), n), nil
}

// Revoke is the owner's revocation of id, for loops.Spare.Revoke.
func (k *Kernel) Revoke(id key.ID) error { return k.K.Revoke(k.ms(), id) }

func (k *Kernel) pub(p ed25519.PrivateKey) ed25519.PublicKey { return p.Public().(ed25519.PublicKey) }

func (k *Kernel) ms() int64 { return k.now().UnixMilli() }

func (k *Kernel) must(err error) {
	k.t.Helper()
	if err != nil {
		k.t.Fatal(err)
	}
}

// grant issues a clerk key off the root with day cap n at at, co-signed by
// both passkeys, with any keys issued alongside it.
func (k *Kernel) grant(at, n int64, with ...key.Key) key.Key {
	k.t.Helper()
	ck, err := key.ClerkKey(k.root, k.owner, k.pub(k.Holder), at, n)
	k.must(err)
	keys := append(with, ck)
	h := kernel.BatchHash(keys...)
	k.must(k.K.Issue(at, []key.Cosign{key.Approve(k.owner, h), key.Approve(k.second, h)}, keys...))
	return ck
}

// Call is one model call charged to ck, a key under the spare envelope: a
// plan citing it, admitted for amount minor units and metered at that
// (LOG-7). It returns the kernel's refusal, if any.
func (k *Kernel) Call(ck key.Key, amount int64) *key.Refusal {
	k.t.Helper()
	return k.Spend(k.Plan(ck), amount)
}

// Plan submits a plan citing ck for one model call and returns its ID.
func (k *Kernel) Plan(ck key.Key) string {
	k.t.Helper()
	k.n++
	id := "loop-" + strconv.Itoa(k.n)
	p := kernel.SignPlan(kernel.Plan{ID: id, Key: ck, Steps: []kernel.PlanStep{
		{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}}}, k.Holder)
	k.must(k.K.Submit(k.ms(), p))
	return id
}

// Spend is a model call under plan id, admitted for amount minor units and
// metered at that. It returns the kernel's refusal, if any.
func (k *Kernel) Spend(id string, amount int64) *key.Refusal {
	k.t.Helper()
	at := k.ms()
	a, rf := k.K.AdmitSpend(at, id, amount)
	if rf != nil {
		return rf
	}
	k.must(k.K.Meter(at, a, "spare", amount, "provider"))
	return nil
}
