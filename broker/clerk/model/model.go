// Package model is the clerk for model calls: the only exit for them (CLK-7).
// It admits a call against the plan's key's spend caps, makes it, and meters
// what it used into the log (LOG-7).
package model

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// ErrNotSent is what a Provider returns when the request provably never left
// (it failed before sending), so the call cost nothing.
var ErrNotSent = errors.New("model: request not sent")

// Usage is a call's token count. Reported is true when the provider's
// connection carried the figure; otherwise the clerk counts its own. Pool is
// the pool's utilization the provider's response carried, if it did (RES-5).
type Usage struct {
	In, Out  int64
	Reported bool
	Pool     *PoolReading
}

// PoolReading is the provider's figure for a usage pool: per mille used, and
// when it resets (unix ms).
type PoolReading struct{ Used, ResetAt int64 }

// Provider makes the call. It holds the credential; nothing else does. On an
// error it still returns any usage it knows, and the clerk meters a Reported
// figure whatever the error. It returns ErrNotSent only when no byte of the
// request was written (a refused connection, a failed lookup), and an error
// the provider does not bill (an overload or server error it reports as
// unbilled) with a Reported zero. Any other error is charged the admitted worst
// case. The clerk calls it from several calls at once, outside its lock, so it
// must be safe for concurrent use.
type Provider interface {
	Call(route, prompt string, maxOut int64) (reply string, u Usage, err error)
}

// Price is minor units per million tokens on one route. Pool names the usage
// pool a plan route draws on ("" for a metered API route). A route draws on one
// pool, because a provider meters one subscription per credential; a route
// that spans two is two routes.
type Price struct {
	InPerM, OutPerM int64
	Pool            string
}

// Ledger is the part of the kernel the clerk needs: the check and the record.
// Calls name the plan; the kernel finds its key and task (LOG-7).
type Ledger interface {
	AdmitSpend(now int64, plan string, amount int64) (kernel.Admitted, *key.Refusal)
	Meter(now int64, a kernel.Admitted, route string, amount int64, source string) error
	Hold(now int64, plan string, rf *key.Refusal) error
	AdmitPool(now int64, pool string) *key.Refusal
	ReadPool(now int64, pool string, used, resetAt int64) error
}

// Clerk is the model clerk. Once a log write it owes fails (spend that
// happened, or a pool reading) it makes no further call until the log has
// recorded it, so no spend goes unmetered and no pool stays open on a reading
// the log missed.
type Clerk struct {
	Routes   map[string]Price
	Provider Provider
	Ledger   Ledger

	mu   sync.Mutex
	owed []func(now int64) error
}

// tokens is the clerk's own count: four bytes a token, rounded up.
func tokens(s string) int64 { return Count(int64(len(s))) }

// Count is the clerk's own token count of n bytes: four bytes a token,
// rounded up.
func Count(n int64) int64 { return n/4 + min(n%4, 1) }

var errOverflow = errors.New("model: cost out of range")

// mul is a*b for non-negative a and b, or an error if it overflows.
func mul(a, b int64) (int64, error) {
	if a < 0 || b < 0 || (a != 0 && b > math.MaxInt64/a) {
		return 0, errOverflow
	}
	return a * b, nil
}

// cost rounds up, so metered spend never falls below the price. Negative
// tokens or prices and arithmetic that wraps are refused, so a call is never
// admitted at, or metered as, less than it spent.
func (p Price) cost(in, out int64) (int64, error) {
	a, err := mul(in, p.InPerM)
	if err != nil {
		return 0, err
	}
	b, err := mul(out, p.OutPerM)
	if err != nil {
		return 0, err
	}
	if a > math.MaxInt64-b || a+b > math.MaxInt64-999_999 {
		return 0, errOverflow
	}
	return (a + b + 999_999) / 1_000_000, nil
}

// owe makes a log write. A failure is kept and retried before the next call
// (flush), so the call whose write failed is the last.
func (c *Clerk) owe(now int64, write func(now int64) error) error {
	if err := write(now); err != nil {
		c.owed = append(c.owed, func(now int64) error {
			// A retry of a settlement whose answer was lost after it landed:
			// the kernel settles an admission once, so it is recorded.
			if err := write(now); !errors.Is(err, kernel.ErrNotAdmitted) {
				return err
			}
			return nil
		})
		return err
	}
	return nil
}

func (c *Clerk) flush(now int64) error {
	for len(c.owed) > 0 {
		if err := c.owed[0](now); err != nil {
			return fmt.Errorf("model: unrecorded usage, no calls until the log records it: %w", err)
		}
		c.owed = c.owed[1:]
	}
	return nil
}

// Call runs one model call for plan: the key, the task and every cap come from
// the plan, never from the caller. A pool route must be open (below the
// owner's reserve) and the worst case (the prompt plus maxOut tokens) must fit
// the caps before the provider is called; a spend cap that is used up holds
// the plan until the owner extends it. A provider error costs the usage it
// reported, nothing if the request never left, else the admitted worst case.
// The reply is withheld if the spend cannot be recorded. A paid reply is kept
// when only its pool reading fails: a reading the log refuses is recorded as a
// full pool instead, since a reading can only narrow, and one the log cannot
// write is owed until its reset time.
func (c *Clerk) Call(now int64, plan, route, prompt string, maxOut int64) (string, error) {
	adm, err := c.Admit(now, plan, route, tokens(prompt), maxOut)
	if err != nil {
		return "", err
	}
	// The provider is called without the lock: the kernel's reservation, not
	// the clerk, keeps calls admitted at once inside the caps.
	reply, u, callErr := c.Provider.Call(route, prompt, maxOut)
	if merr := adm.Settle(now, u, tokens(reply), callErr); merr != nil {
		return "", errors.Join(callErr, merr)
	}
	if callErr != nil {
		return "", callErr
	}
	return reply, nil
}

// Admission is one admitted call, settled once by Settle. Call makes its
// own; a call the clerk does not make through its Provider (a CLI guest's
// request that the plan login clerk forwards, MIG-4-plan-login-b) is
// admitted by Admit and settled when it ends.
type Admission struct {
	c         *Clerk
	route     string
	p         Price
	in, worst int64
	a         kernel.Admitted
	once      sync.Once
	err       error
}

// Admit admits a call of in input tokens (the clerk's count) and at most
// maxOut output tokens, as Call does before it calls the provider.
func (c *Clerk) Admit(now int64, plan, route string, in, maxOut int64) (*Admission, error) {
	p, worst, a, err := c.admit(now, plan, route, in, maxOut)
	if err != nil {
		return nil, err
	}
	return &Admission{c: c, route: route, p: p, in: in, worst: worst, a: a}, nil
}

// Settle meters how the call ended, as Call does: the usage the provider
// reported, nothing if callErr is ErrNotSent, the clerk's own count (the
// admitted input and out output tokens) if callErr is nil, and else the
// admitted worst case; and the pool reading, if any. A second Settle
// records nothing and returns the first one's answer. An error is spend
// the log has not recorded: no further call is made until it has.
func (s *Admission) Settle(now int64, u Usage, out int64, callErr error) error {
	s.once.Do(func() { s.err = s.c.settle(now, s, u, out, callErr) })
	return s.err
}

func (c *Clerk) settle(now int64, s *Admission, u Usage, out int64, callErr error) error {
	p, a, route := s.p, s.a, s.route
	amount, src := s.worst, "admitted"
	var cerr error
	switch {
	case u.Reported:
		amount, cerr = p.cost(u.In, u.Out)
		src = "provider"
	case errors.Is(callErr, ErrNotSent):
		amount, src = 0, "clerk" // the request never left
	case callErr == nil:
		amount, cerr = p.cost(s.in, out)
		src = "clerk"
	}
	if cerr != nil {
		amount, src = s.worst, "admitted"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	merr := c.owe(now, func(now int64) error { return c.Ledger.Meter(now, a, route, amount, src) })
	if p.Pool != "" && u.Pool != nil {
		used, reset := u.Pool.Used, u.Pool.ResetAt
		if reset <= now {
			reset = now + kernel.PoolWindowMS
		}
		_ = c.owe(now, func(now int64) error {
			if now >= reset {
				return nil // the pool has reset since the reading
			}
			if c.Ledger.ReadPool(now, p.Pool, used, reset) == nil {
				return nil
			}
			return c.Ledger.ReadPool(now, p.Pool, kernel.PoolFull, reset)
		})
	}
	return merr
}

// admit checks the route and admits the call's worst case, under the lock.
func (c *Clerk) admit(now int64, plan, route string, in, maxOut int64) (Price, int64, kernel.Admitted, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var none kernel.Admitted
	if err := c.flush(now); err != nil {
		return Price{}, 0, none, err
	}
	p, ok := c.Routes[route]
	if !ok {
		return Price{}, 0, none, fmt.Errorf("model: no route %q", route)
	}
	if maxOut <= 0 {
		return Price{}, 0, none, errors.New("model: maxOut must be positive")
	}
	worst, err := p.cost(in, maxOut)
	if err != nil {
		return Price{}, 0, none, err
	}
	if p.Pool != "" {
		if r := c.Ledger.AdmitPool(now, p.Pool); r != nil {
			return Price{}, 0, none, r
		}
	}
	a, r := c.Ledger.AdmitSpend(now, plan, worst)
	if r != nil {
		if r.Code == key.RSpendTask || r.Code == key.RSpendDay {
			if err := c.Ledger.Hold(now, plan, r); err != nil {
				return Price{}, 0, none, err
			}
		}
		return Price{}, 0, none, r
	}
	return p, worst, a, nil
}
