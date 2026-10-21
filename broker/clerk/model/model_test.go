package model_test

// REQ: LOG-7, RES-5, KEY-2, KEY-4, CLK-7

import (
	"crypto/ed25519"
	"errors"
	"math"
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

// flaky is a ledger whose log can stop recording usage.
type flaky struct {
	model.Ledger
	fail bool
}

func (f *flaky) Meter(now int64, plan, route string, amount int64, source string) error {
	if f.fail {
		return errors.New("log down")
	}
	return f.Ledger.Meter(now, plan, route, amount, source)
}

// rig boots a kernel and submits active plans "t" and "big" citing a model key
// capped at 100 per task.
func rig(t *testing.T, p *fake) (*model.Clerk, *kernel.Kernel, *flaky) {
	t.Helper()
	opub, opriv := seed(1)
	hpub, hpriv := seed(2)
	gpub, gpriv := seed(3)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: gpub, Sign: gpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	k, err := kernel.Boot(l, []ed25519.PublicKey{opub}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(opriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, opriv, hpub, 0, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Issue(-kernel.GrantHold, root, ky); err != nil {
		t.Fatal(err)
	}
	step := kernel.PlanStep{Verb: key.Read, Clerk: "model", Args: map[string]string{"query": "q"}}
	for _, id := range []string{"t", "big"} {
		if err := k.Submit(0, kernel.SignPlan(kernel.Plan{ID: id, Key: ky, Steps: []kernel.PlanStep{step}}, hpriv)); err != nil {
			t.Fatal(err)
		}
	}
	lg := &flaky{Ledger: k}
	routes := map[string]model.Price{
		"api":  {InPerM: 1_000_000, OutPerM: 1_000_000},
		"plan": {Pool: "codex-5h"},
		"tiny": {InPerM: 1, OutPerM: 1},
	}
	return &model.Clerk{Routes: routes, Provider: p, Ledger: lg}, k, lg
}

func lastEntry(k *kernel.Kernel) kernel.Entry {
	es := k.Log().Entries()
	return es[len(es)-1]
}

func TestProviderFigureIsMeteredAndCapsHold(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, _, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 50); err != nil {
		t.Fatal(err)
	}
	// 70 used; worst case of the next call is 1+50 = 51 > 30 left.
	if _, err := c.Call(2, "t", "api", "hi", 50); err == nil || f.calls != 1 {
		t.Fatalf("over-cap call reached the provider: %v calls=%d", err, f.calls)
	}
}

func TestExhaustedPlanIsHeldAndOwnerExtends(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(2, "t", "api", "hi", 50); err == nil {
		t.Fatal("over-cap call must be refused")
	}
	if h, ok := k.State().SpendHeld["t"]; !ok || h.Code != key.RSpendTask {
		t.Fatalf("plan not held: %+v", h)
	}
	if _, err := c.Call(3, "t", "api", "hi", 1); err == nil || f.calls != 1 {
		t.Fatalf("a held plan makes no call, however small: %v calls=%d", err, f.calls)
	}
	// the owner's envelope (another root), and an extension derived from it
	_, opriv := seed(1)
	hpub, hpriv := seed(2)
	root := key.Issue(opriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "env"})
	env, err := key.ClerkKey(root, opriv, hpub, 0, 500, key.LimitSpendTask(500))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Issue(3-kernel.GrantHold, root, env); err != nil { // granted at setup
		t.Fatal(err)
	}
	ext, err := key.Derive(env, hpriv, hpub, key.LimitSpendTask(200))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Extend(4, ext, "t"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(5, "t", "api", "hi", 50); err != nil {
		t.Fatalf("extended plan runs: %v", err)
	}
}

func TestPoolRouteReadsUtilizationAndStopsAtTheReserve(t *testing.T) {
	f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 950, ResetAt: 10_000}}}
	c, k, _ := rig(t, f)
	if err := k.Reserve(0, "codex-5h", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(1, "t", "plan", "hi", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(2, "t", "plan", "hi", 10); err == nil || f.calls != 1 {
		t.Fatalf("a pool at the reserve admits nothing: %v calls=%d", err, f.calls)
	}
	if _, err := c.Call(2, "t", "api", "hi", 10); err != nil {
		t.Fatalf("other routes are unaffected: %v", err)
	}
	if _, err := c.Call(10_000, "t", "plan", "hi", 10); err != nil {
		t.Fatalf("the reset time is the cooldown: %v", err)
	}
}

func TestClerkCountsWhenProviderReportsNone(t *testing.T) {
	f := &fake{}
	c, k, _ := rig(t, f)
	// worst case 10+100 = 110 does not fit 100; the refusal holds only "big"
	if _, err := c.Call(1, "big", "api", strings.Repeat("p", 40), 100); err == nil {
		t.Fatal("worst case 110 must not fit 100")
	}
	if _, err := c.Call(1, "t", "api", strings.Repeat("p", 40), 90); err != nil {
		t.Fatal(err)
	}
	// 40 bytes in = 10 tokens, 400 bytes out = 100 tokens, source "clerk".
	last := lastEntry(k)
	if last.Type != kernel.TModelUsed || !strings.Contains(string(last.Body), `"amount":110`) || !strings.Contains(string(last.Body), `"source":"clerk"`) {
		t.Fatalf("entry: %s %s", last.Type, last.Body)
	}
}

func TestProviderErrorMetersTheAdmittedWorstCase(t *testing.T) {
	f := &fake{err: errors.New("down")}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 10); err == nil {
		t.Fatal("provider error must surface")
	}
	// 1 token in + 10 out: a failed call may still have spent, so it costs 11
	last := lastEntry(k)
	if last.Type != kernel.TModelUsed || !strings.Contains(string(last.Body), `"amount":11`) || !strings.Contains(string(last.Body), `"source":"admitted"`) {
		t.Fatalf("entry: %s %s", last.Type, last.Body)
	}
}

func TestRefusedCallsMakeNoCallAndMeterNothing(t *testing.T) {
	f := &fake{}
	c, k, _ := rig(t, f)
	n := len(k.Log().Entries())
	for name, call := range map[string]func() error{
		"unknown route": func() error { _, e := c.Call(1, "t", "nope", "hi", 10); return e },
		"zero maxOut":   func() error { _, e := c.Call(1, "t", "api", "hi", 0); return e },
		"negative":      func() error { _, e := c.Call(1, "t", "api", "hi", -5); return e },
		"overflow":      func() error { _, e := c.Call(1, "t", "api", "hi", math.MaxInt64); return e },
		"unknown plan":  func() error { _, e := c.Call(1, "nope", "api", "hi", 10); return e },
	} {
		if call() == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	if err := k.Cancel(1, "t"); err != nil {
		t.Fatal(err)
	}
	n = len(k.Log().Entries())
	if _, err := c.Call(2, "t", "api", "hi", 10); err == nil {
		t.Fatal("a cancelled plan makes no call")
	}
	if f.calls != 0 || len(k.Log().Entries()) != n {
		t.Fatalf("refusals reached the provider or the log: calls=%d", f.calls)
	}
}

func TestCostRoundsUpAndNeverBelowThePrice(t *testing.T) {
	f := &fake{u: model.Usage{In: 1, Reported: true}}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "tiny", "hi", 10); err != nil {
		t.Fatal(err)
	}
	if last := lastEntry(k); !strings.Contains(string(last.Body), `"amount":1`) {
		t.Fatalf("one token at a positive price costs at least 1: %s", last.Body)
	}
}

func TestNegativeReportedUsageMetersTheWorstCase(t *testing.T) {
	f := &fake{u: model.Usage{In: -50, Out: 10, Reported: true}}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 10); err != nil {
		t.Fatal(err)
	}
	last := lastEntry(k)
	if !strings.Contains(string(last.Body), `"amount":11`) || !strings.Contains(string(last.Body), `"source":"admitted"`) {
		t.Fatalf("a negative figure is not a refund: %s", last.Body)
	}
}

func TestUnrecordedSpendShutsTheClerkUntilTheLogRecords(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, k, lg := rig(t, f)
	lg.fail = true
	if reply, err := c.Call(1, "t", "api", "hi", 50); err == nil || reply != "" {
		t.Fatalf("the reply is withheld when its usage cannot be recorded: %q %v", reply, err)
	}
	if _, err := c.Call(2, "big", "api", "hi", 1); err == nil || f.calls != 1 {
		t.Fatalf("no call while spend is unrecorded: %v calls=%d", err, f.calls)
	}
	lg.fail = false
	if _, err := c.Call(3, "big", "api", "hi", 1); err != nil {
		t.Fatalf("calls resume once the log records: %v", err)
	}
	es := k.Log().Entries()
	var used []string
	for _, e := range es {
		if e.Type == kernel.TModelUsed {
			used = append(used, string(e.Body))
		}
	}
	if len(used) != 2 || !strings.Contains(used[0], `"amount":70`) {
		t.Fatalf("the owed usage is recorded first: %v", used)
	}
}

func TestRequestThatNeverLeftMetersNothing(t *testing.T) {
	f := &fake{err: model.ErrNotSent}
	c, k, _ := rig(t, f)
	n := len(k.Log().Entries())
	if _, err := c.Call(1, "t", "api", "hi", 10); !errors.Is(err, model.ErrNotSent) {
		t.Fatalf("the error surfaces: %v", err)
	}
	if len(k.Log().Entries()) != n {
		t.Fatal("a request that never left costs nothing and leaves no entry")
	}
}

func TestUsageReturnedWithAnErrorIsMetered(t *testing.T) {
	f := &fake{u: model.Usage{In: 3, Out: 4, Reported: true}, err: errors.New("cut off")}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 10); err == nil {
		t.Fatal("provider error must surface")
	}
	last := lastEntry(k)
	if !strings.Contains(string(last.Body), `"amount":7`) || !strings.Contains(string(last.Body), `"source":"provider"`) {
		t.Fatalf("reported usage is what it cost: %s", last.Body)
	}
}

func TestPoolReadingIsAppliedOnAProviderError(t *testing.T) {
	f := &fake{u: model.Usage{Pool: &model.PoolReading{Used: 950, ResetAt: 10_000}}, err: errors.New("cut off")}
	c, k, _ := rig(t, f)
	if err := k.Reserve(0, "codex-5h", 100); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(1, "t", "plan", "hi", 10); err == nil {
		t.Fatal("provider error must surface")
	}
	if r := k.AdmitPool(2, "codex-5h"); r == nil {
		t.Fatal("the reading that came with the error closes the pool")
	}
}

// Prices and sizes that wrap or go negative are refused before the provider.
func TestCostArithmeticIsRefusedBeforeTheProvider(t *testing.T) {
	for name, tc := range map[string]struct {
		p      model.Price
		maxOut int64
	}{
		"negative price":   {model.Price{InPerM: 1, OutPerM: -1}, 10},
		"product wraps":    {model.Price{OutPerM: 2}, math.MaxInt64/2 + 1},
		"sum wraps":        {model.Price{InPerM: math.MaxInt64, OutPerM: 1}, 2},
		"no round-up room": {model.Price{InPerM: math.MaxInt64 - 500_000}, 1},
	} {
		f := &fake{}
		c, k, _ := rig(t, f)
		c.Routes["bad"] = tc.p
		n := len(k.Log().Entries())
		if _, err := c.Call(1, "t", "bad", "hi", tc.maxOut); err == nil {
			t.Fatalf("%s must be refused", name)
		}
		if f.calls != 0 || len(k.Log().Entries()) != n {
			t.Fatalf("%s reached the provider or the log", name)
		}
	}
}

// Each guard in the cost arithmetic is pinned by a price it alone refuses, or,
// for the add guard, by a provider figure it alone keeps from wrapping.
func TestEachCostGuardIsPinnedByItsOwnCase(t *testing.T) {
	prompt := strings.Repeat("x", 400)
	for name, tc := range map[string]struct {
		p      model.Price
		maxOut int64
	}{
		// 100 in at -1M/M plus 150 out at 1M/M sums to a positive 50: only the sign check refuses it
		"negative in-price": {model.Price{InPerM: -1_000_000, OutPerM: 1_000_000}, 150},
		// (2^44+1) * 2^20 wraps to 2^20: only the multiply check refuses it
		"product wraps": {model.Price{OutPerM: 1 << 20}, 1<<44 + 1},
	} {
		f := &fake{}
		c, k, _ := rig(t, f)
		c.Routes["bad"] = tc.p
		n := len(k.Log().Entries())
		if _, err := c.Call(1, "t", "bad", prompt, tc.maxOut); err == nil {
			t.Fatalf("%s must be refused", name)
		}
		if f.calls != 0 || len(k.Log().Entries()) != n {
			t.Fatalf("%s reached the provider or the log", name)
		}
	}
	// a reported sum that wraps is metered at the admitted worst case, never at 0 or less
	f := &fake{u: model.Usage{In: math.MaxInt64 / 1_000_000, Out: math.MaxInt64 / 1_000_000, Reported: true}}
	c, k, _ := rig(t, f)
	c.Routes["big"] = model.Price{InPerM: 1_000_000, OutPerM: 1_000_000}
	if _, err := c.Call(1, "t", "big", "hi", 10); err != nil {
		t.Fatal(err)
	}
	last := lastEntry(k)
	if !strings.Contains(string(last.Body), `"amount":11`) || !strings.Contains(string(last.Body), `"source":"admitted"`) {
		t.Fatalf("a wrapping figure is metered at the admitted cost: %s", last.Body)
	}
}

// A plan under a mail key with a spend cap makes a capped model call: the
// funding key's caveat authorizes, not the clerk it was issued for.
func TestPlanUnderAMailKeyMakesACappedCall(t *testing.T) {
	f := &fake{u: model.Usage{In: 30, Out: 40, Reported: true}}
	c, k, _ := rig(t, f)
	_, opriv := seed(1)
	hpub, hpriv := seed(2)
	root := key.Issue(opriv, key.Root{Clerk: "mail", Verbs: []key.Verb{key.Trash}, Serial: "mail"})
	ky, err := key.ClerkKey(root, opriv, hpub, 0, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Issue(-kernel.GrantHold, root, ky); err != nil {
		t.Fatal(err)
	}
	step := kernel.PlanStep{Verb: key.Trash, Clerk: "mail", Args: map[string]string{"target": "m1"}}
	if err := k.Submit(0, kernel.SignPlan(kernel.Plan{ID: "mailplan", Key: ky, Steps: []kernel.PlanStep{step}}, hpriv)); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call(1, "mailplan", "api", "hi", 50); err != nil {
		t.Fatalf("a mail key's spend cap funds a model call: %v", err)
	}
	if _, err := c.Call(2, "mailplan", "api", "hi", 50); err == nil || f.calls != 1 {
		t.Fatalf("its cap holds: %v calls=%d", err, f.calls)
	}
}
