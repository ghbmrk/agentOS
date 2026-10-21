package model_test

// REQ: LOG-7, RES-5, KEY-2, KEY-4, CLK-7

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/model"
	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

type fake struct {
	calls  int
	u      model.Usage
	err    error
	during func() // runs while the request is out
}

func (f *fake) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	f.calls++
	if f.during != nil {
		f.during()
	}
	return strings.Repeat("x", 400), f.u, f.err
}

// cosigned is the owner's and the second hardware key's co-signatures over a
// grant batch.
func cosigned(keys ...key.Key) []key.Cosign {
	_, o := seed(1)
	_, b := seed(12)
	return []key.Cosign{key.Approve(o, kernel.BatchHash(keys...)), key.Approve(b, kernel.BatchHash(keys...))}
}

func seed(b byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	s := make([]byte, ed25519.SeedSize)
	s[0] = b
	p := ed25519.NewKeyFromSeed(s)
	return p.Public().(ed25519.PublicKey), p
}

// flaky is a ledger whose log can stop recording usage or pool readings.
type flaky struct {
	model.Ledger
	fail, failPool bool
}

func (f *flaky) ReadPool(now int64, pool string, used, resetAt int64) error {
	if f.failPool {
		return errors.New("log down")
	}
	return f.Ledger.ReadPool(now, pool, used, resetAt)
}

func (f *flaky) Meter(now int64, a kernel.Admitted, route string, amount int64, source string) error {
	if f.fail {
		return errors.New("log down")
	}
	return f.Ledger.Meter(now, a, route, amount, source)
}

// rig boots a kernel and submits active plans "t" and "big" citing a model key
// capped at 100 per task.
func rig(t *testing.T, p model.Provider) (*model.Clerk, *kernel.Kernel, *flaky) {
	t.Helper()
	opub, opriv := seed(1)
	hpub, hpriv := seed(2)
	gpub, gpriv := seed(3)
	l, err := kernel.Open(kernel.Config{Store: &kernel.MemStore{}, Anchor: &kernel.MemAnchor{}, Pub: gpub, Sign: gpriv, Rand: rand.NewChaCha8([32]byte{1})})
	if err != nil {
		t.Fatal(err)
	}
	bpub, _ := seed(12) // the second hardware key, which co-signs new power (D-146)
	k, err := kernel.Boot(l, []ed25519.PublicKey{opub, bpub}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := key.Issue(opriv, key.Root{Clerk: "model", Verbs: []key.Verb{key.Read}, Serial: "m"})
	ky, err := key.ClerkKey(root, opriv, hpub, 0, 1<<40, key.LimitSpendTask(100))
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Issue(-kernel.GrantHold, cosigned(root, ky), root, ky); err != nil {
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
	if err := k.Issue(3-kernel.GrantHold, cosigned(root, env), root, env); err != nil { // granted at setup
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
	if _, err := c.Call(1, "t", "api", "hi", 10); !errors.Is(err, model.ErrNotSent) {
		t.Fatalf("the error surfaces: %v", err)
	}
	if e := lastEntry(k); e.Type != kernel.TModelUsed || !strings.Contains(string(e.Body), `"amount":0`) {
		t.Fatalf("its admission is settled at nothing: %s %s", e.Type, e.Body)
	}
	f.err = nil
	if _, err := c.Call(2, "t", "api", "hi", 99); err != nil {
		t.Fatalf("the whole budget is left: %v", err)
	}
}

// Calls run at once: the provider is called without the clerk's lock, and
// the kernel's reservations keep them inside the caps together (#2613 item 1).
func TestConcurrentCallsShareNoBudget(t *testing.T) {
	f := &gate{in: make(chan struct{}), release: make(chan struct{})}
	c, _, _ := rig(t, f)
	done := make(chan error, 1)
	go func() { _, err := c.Call(1, "t", "api", "hi", 59); done <- err }() // worst case 60
	<-f.in
	if _, err := c.Call(1, "t", "api", "hi", 40); err == nil {
		t.Fatal("a second call shared the first one's budget")
	}
	if _, err := c.Call(1, "t", "api", "hi", 39); err != nil {
		t.Fatalf("the rest of the budget: %v", err)
	}
	close(f.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// gate is a provider whose first call waits to be released.
type gate struct {
	in, release chan struct{}
	n           atomic.Int32
}

func (g *gate) Call(route, prompt string, maxOut int64) (string, model.Usage, error) {
	if g.n.Add(1) == 1 {
		g.in <- struct{}{}
		<-g.release
	}
	return "ok", model.Usage{In: 1, Out: 1, Reported: true}, nil
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
	if err := k.Issue(-kernel.GrantHold, cosigned(root, ky), root, ky); err != nil {
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

// A provider that sends a figure is metered by it even when it says the request
// never left: ErrNotSent alone is not a reason to drop reported usage.
func TestReportedUsageIsMeteredEvenWithErrNotSent(t *testing.T) {
	f := &fake{u: model.Usage{In: 3, Out: 4, Reported: true}, err: model.ErrNotSent}
	c, k, _ := rig(t, f)
	if _, err := c.Call(1, "t", "api", "hi", 10); !errors.Is(err, model.ErrNotSent) {
		t.Fatalf("the error surfaces: %v", err)
	}
	last := lastEntry(k)
	if last.Type != kernel.TModelUsed || !strings.Contains(string(last.Body), `"amount":7`) || !strings.Contains(string(last.Body), `"source":"provider"`) {
		t.Fatalf("the reported figure is metered: %s %s", last.Type, last.Body)
	}
}

// poolRead returns the last pool.read entry's body.
func poolRead(t *testing.T, k *kernel.Kernel) string {
	t.Helper()
	es := k.Log().Entries()
	for i := len(es) - 1; i >= 0; i-- {
		if es[i].Type == kernel.TPoolRead {
			return string(es[i].Body)
		}
	}
	t.Fatal("no pool reading recorded")
	return ""
}

// A paid, metered reply is kept when the log refuses its pool reading, and the
// pool is recorded as full, since a reading can only narrow.
func TestPaidReplyIsKeptWhenItsPoolReadingIsRefused(t *testing.T) {
	for name, tc := range map[string]struct {
		before, used int64
		during       func(k *kernel.Kernel) error
	}{
		// a figure outside 0..1000
		"bad figure": {used: 1500},
		// at 900 used, the owner raises the reserve mid-call, so the closed pool refuses a lower reading
		"reserve raised": {before: 900, used: 500, during: func(k *kernel.Kernel) error { return k.Reserve(1, "codex-5h", 200) }},
	} {
		f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: tc.used, ResetAt: 10_000}}}
		c, k, _ := rig(t, f)
		if err := k.ReadPool(0, "codex-5h", tc.before, 10_000); err != nil {
			t.Fatal(err)
		}
		if tc.during != nil {
			f.during = func() {
				if err := tc.during(k); err != nil {
					t.Fatal(err)
				}
			}
		}
		reply, err := c.Call(1, "t", "plan", "hi", 10)
		if err != nil || reply == "" {
			t.Fatalf("%s: the paid reply is kept: %q %v", name, reply, err)
		}
		if b := poolRead(t, k); !strings.Contains(b, `"used":1000`) || !strings.Contains(b, `"reset_at":10000`) {
			t.Fatalf("%s: the refused reading is recorded as a full pool: %s", name, b)
		}
		if r := k.AdmitPool(2, "codex-5h"); r == nil {
			t.Fatalf("%s: the pool is closed", name)
		}
	}
}

// When the log cannot write the pool reading at all, the reply is still kept,
// and the reading is owed before any further call. Once written it is the
// provider's own figure, not a full pool.
func TestUnrecordedPoolReadingShutsTheClerkUntilTheLogRecords(t *testing.T) {
	f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 300, ResetAt: 10_000}}}
	c, k, lg := rig(t, f)
	lg.failPool = true
	if reply, err := c.Call(1, "t", "plan", "hi", 10); err != nil || reply == "" {
		t.Fatalf("the paid reply is kept: %q %v", reply, err)
	}
	if _, err := c.Call(2, "t", "api", "hi", 10); err == nil || f.calls != 1 {
		t.Fatalf("no call while a pool reading is unrecorded: %v calls=%d", err, f.calls)
	}
	lg.failPool = false
	if _, err := c.Call(3, "t", "api", "hi", 10); err != nil {
		t.Fatalf("calls resume once the log records: %v", err)
	}
	if b := poolRead(t, k); !strings.Contains(b, `"used":300`) || !strings.Contains(b, `"reset_at":10000`) {
		t.Fatalf("the owed reading is the provider's figure: %s", b)
	}
	if _, err := c.Call(4, "t", "plan", "hi", 10); err != nil {
		t.Fatalf("a pool at 300 stays open: %v", err)
	}
}

// An owed reading whose reset time has passed by the time the log recovers is
// dropped: the provider's reset time is the cooldown, so the pool does not
// close for a fresh window after it has already reset.
func TestOwedReadingPastItsResetIsDropped(t *testing.T) {
	for name, tc := range map[string]struct{ resetAt, recover int64 }{
		"provider reset": {resetAt: 10_000, recover: 20_000},
		// no reset time: the declared window from the call is the cooldown
		"no reset time": {resetAt: 0, recover: 1 + kernel.PoolWindowMS},
	} {
		f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 1000, ResetAt: tc.resetAt}}}
		c, k, lg := rig(t, f)
		lg.failPool = true
		if _, err := c.Call(1, "t", "plan", "hi", 10); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := c.Call(2, "t", "api", "hi", 10); err == nil {
			t.Fatalf("%s: the reading is owed until its reset time", name)
		}
		lg.failPool = false
		f.u.Pool = nil // the next call carries no reading of its own
		if _, err := c.Call(tc.recover, "t", "plan", "hi", 10); err != nil {
			t.Fatalf("%s: the pool reset before the log recovered, so it is open: %v", name, err)
		}
		for _, e := range k.Log().Entries() {
			if e.Type == kernel.TPoolRead {
				t.Fatalf("%s: a stale reading was recorded: %s", name, e.Body)
			}
		}
	}
}

// A failed meter still applies the call's pool reading, so the pool is not
// left open once the log records the owed spend.
func TestPoolReadingIsAppliedWhenTheMeterFails(t *testing.T) {
	f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 950, ResetAt: 10_000}}}
	c, k, lg := rig(t, f)
	if err := k.Reserve(0, "codex-5h", 100); err != nil {
		t.Fatal(err)
	}
	lg.fail = true
	if reply, err := c.Call(1, "t", "plan", "hi", 10); err == nil || reply != "" {
		t.Fatalf("the reply is withheld when its spend cannot be recorded: %q %v", reply, err)
	}
	lg.fail = false
	if _, err := c.Call(2, "t", "plan", "hi", 10); err == nil || f.calls != 1 {
		t.Fatalf("the reading closed the pool: %v calls=%d", err, f.calls)
	}
}

// A reading with no reset time is owed with the declared window from the call,
// not from when the log recovers, so an outage never lengthens the cooldown.
func TestOwedReadingKeepsTheWindowFromTheCall(t *testing.T) {
	f := &fake{u: model.Usage{Reported: true, Pool: &model.PoolReading{Used: 1000}}}
	c, k, lg := rig(t, f)
	lg.failPool = true
	if _, err := c.Call(1, "t", "plan", "hi", 10); err != nil {
		t.Fatal(err)
	}
	lg.failPool = false
	f.u.Pool = nil // the next calls carry no reading of their own
	if _, err := c.Call(100, "t", "api", "hi", 10); err != nil {
		t.Fatalf("calls resume once the log records: %v", err)
	}
	if b := poolRead(t, k); !strings.Contains(b, fmt.Sprintf(`"reset_at":%d`, 1+kernel.PoolWindowMS)) {
		t.Fatalf("the cooldown runs from the call: %s", b)
	}
	if _, err := c.Call(1+kernel.PoolWindowMS, "t", "plan", "hi", 10); err != nil {
		t.Fatalf("the pool reopens one window after the call: %v", err)
	}
}
