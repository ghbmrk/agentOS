package model_test

// REQ: LOG-7, RES-5, KEY-2, KEY-4, CLK-7

import (
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

type fake struct {
	calls int
	u     model.Usage
	err   error
}

func (f *fake) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	return strings.Repeat("x", 400), f.u, f.err
}

func seed(b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

// rig boots a kernel and a model key capped at 100 per task.
func rig(t *testing.T, p *fake) (*model.Clerk, *kernel.Kernel, key.Key) {
	t.Helper()
	opub, opriv := seed(1)
	hpub, hpriv := seed(2)
	gpub, gpriv := seed(3)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: gpub, Sign: gpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, opub, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(opriv, key.Root{Holder: hpub, Clerk: model.Name, Verbs: []key.Verb{key.Read}, Serial: "m"})
	if err := k.Issue(0, root); err != nil {
		t.Fatal(err)
	}
	ky, err := key.Derive(root, hpriv, hpub, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	c := &model.Clerk{Routes: map[string]model.Price{"api": {InPerM: 1_000_000, OutPerM: 1_000_000}}, Provider: p, Ledger: k}
	return c, k, ky
}

func TestProviderFigureIsMeteredAndCapsHold(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, _, ky := rig(t, f)
	if _, err := c.Call(1, ky, "t", "api", "hi", 50); err != nil {
		t.Fatal(err)
	}
	// 70 used; worst case of the next call is 1+50 = 51 > 30 left.
	if _, err := c.Call(2, ky, "t", "api", "hi", 50); err == nil || f.calls != 1 {
		t.Fatalf("over-cap call reached the provider: %v calls=%d", err, f.calls)
	}
}

func TestExhaustedTaskIsHeldAndOwnerExtends(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, k, ky := rig(t, f)
	if _, err := c.Call(1, ky, "t", "api", "hi", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(2, ky, "t", "api", "hi", 50); err == nil {
		t.Fatal("over-cap call must be refused")
	}
	if h, ok := k.State().SpendHeld["t"]; !ok || h.Code != key.RSpendTask {
		t.Fatalf("task not held: %+v", h)
	}
	if _, err := c.Call(3, ky, "t", "api", "hi", 1); err == nil || f.calls != 1 {
		t.Fatalf("a held task makes no call, however small: %v calls=%d", err, f.calls)
	}
	// the owner's envelope, and an extension derived from it
	opub, opriv := seed(1)
	hpub, hpriv := seed(2)
	_ = opub
	root := key.Issue(opriv, key.Root{Holder: hpub, Clerk: model.Name, Verbs: []key.Verb{key.Read}, Serial: "env"})
	if err := k.Issue(3, root); err != nil {
		t.Fatal(err)
	}
	env, err := key.Derive(root, hpriv, hpub, key.LimitSpendTask(500), key.LimitSpendDay(500))
	if err != nil {
		t.Fatal(err)
	}
	ext, err := key.Derive(env, hpriv, hpub, key.LimitSpendTask(200))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Extend(4, ext, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(5, ext, "t", "api", "hi", 50); err != nil {
		t.Fatalf("extended task runs: %v", err)
	}
}

func poolRig(t *testing.T, f *fake) (*model.Clerk, *kernel.Kernel, key.Key) {
	c, k, ky := rig(t, f)
	c.Routes["plan"] = model.Price{Pool: "codex-5h"}
	return c, k, ky
}

func TestPoolRouteReadsUtilizationAndStopsAtTheReserve(t *testing.T) {
	f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 950, ResetAt: 10_000}}}
	c, k, ky := poolRig(t, f)
	if err := k.Reserve(0, "codex-5h", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(1, ky, "t", "plan", "hi", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(2, ky, "t", "plan", "hi", 10); err == nil || f.calls != 1 {
		t.Fatalf("a pool at the reserve admits nothing: %v calls=%d", err, f.calls)
	}
	if _, err := c.Call(2, ky, "t", "api", "hi", 10); err != nil {
		t.Fatalf("other routes are unaffected: %v", err)
	}
	if _, err := c.Call(10_000, ky, "t", "plan", "hi", 10); err != nil {
		t.Fatalf("the reset time is the cooldown: %v", err)
	}
}

func TestClerkCountsWhenProviderReportsNone(t *testing.T) {
	f := &fake{}
	c, k, ky := rig(t, f)
	if _, err := c.Call(1, ky, "big", "api", strings.Repeat("p", 40), 100); err == nil {
		t.Fatal("worst case 110 must not fit 100")
	}
	if _, err := c.Call(1, ky, "t", "api", strings.Repeat("p", 40), 90); err != nil {
		t.Fatal(err)
	}
	// 40 bytes in = 10 tokens, 400 bytes out = 100 tokens, source "clerk".
	last := k.Log().Entries()[len(k.Log().Entries())-1]
	if last.Type != kernel.TModelUsed || !strings.Contains(string(last.Body), `"amount":110`) || !strings.Contains(string(last.Body), `"source":"clerk"`) {
		t.Fatalf("entry: %s %s", last.Type, last.Body)
	}
}

func TestFailedCallAndUnknownRouteMeterNothing(t *testing.T) {
	f := &fake{err: errors.New("down")}
	c, k, ky := rig(t, f)
	n := len(k.Log().Entries())
	if _, err := c.Call(1, ky, "t", "api", "hi", 10); err == nil {
		t.Fatal("provider error must surface")
	}
	if _, err := c.Call(1, ky, "t", "nope", "hi", 10); err == nil {
		t.Fatal("unknown route")
	}
	if len(k.Log().Entries()) != n {
		t.Fatal("nothing happened, nothing metered")
	}
}
