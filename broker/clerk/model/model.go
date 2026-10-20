// Package model is the clerk for model calls: the only exit for them (CLK-7).
// It admits a call against the plan's key's spend caps, makes it, and meters
// what it used into the log (LOG-7).
package model

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Name is the clerk name a key must be issued for.
const Name = "model"

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

// Provider makes the call. It holds the credential; nothing else does.
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
	AdmitSpend(now int64, plan, clerk string, amount int64) *key.Refusal
	Meter(now int64, plan, route string, amount int64, source string) error
	Hold(now int64, plan string, rf *key.Refusal) error
	AdmitPool(now int64, pool string) *key.Refusal
	ReadPool(now int64, pool string, used, resetAt int64) error
}

// unmetered is spend that happened but the log has not recorded.
type unmetered struct {
	plan, route, source string
	amount              int64
}

// Clerk is the model clerk. Once a Meter fails it makes no further call until
// the log has recorded what it owes, so no spend goes unmetered.
type Clerk struct {
	Routes   map[string]Price
	Provider Provider
	Ledger   Ledger

	mu      sync.Mutex
	pending []unmetered
}

// tokens is the clerk's own count: four bytes a token, rounded up.
func tokens(s string) int64 { return int64(len(s)+3) / 4 }

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

// record meters what a call used. A failure is kept and retried before the
// next call (flush), so the call that failed to record is the last.
func (c *Clerk) record(now int64, u unmetered) error {
	if err := c.Ledger.Meter(now, u.plan, u.route, u.amount, u.source); err != nil {
		c.pending = append(c.pending, u)
		return err
	}
	return nil
}

func (c *Clerk) flush(now int64) error {
	for len(c.pending) > 0 {
		u := c.pending[0]
		if err := c.Ledger.Meter(now, u.plan, u.route, u.amount, u.source); err != nil {
			return fmt.Errorf("model: unmetered spend, no calls until the log records it: %w", err)
		}
		c.pending = c.pending[1:]
	}
	return nil
}

// Call runs one model call for plan: the key, the task and every cap come from
// the plan, never from the caller. A pool route must be open (below the
// owner's reserve) and the worst case (the prompt plus maxOut tokens) must fit
// the caps before the provider is called; a spend cap that is used up holds
// the plan until the owner extends it. A provider error costs the admitted
// worst case. The reply is withheld if the usage cannot be recorded.
func (c *Clerk) Call(now int64, plan, route, prompt string, maxOut int64) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.flush(now); err != nil {
		return "", err
	}
	p, ok := c.Routes[route]
	if !ok {
		return "", fmt.Errorf("model: no route %q", route)
	}
	if maxOut <= 0 {
		return "", errors.New("model: maxOut must be positive")
	}
	in := tokens(prompt)
	worst, err := p.cost(in, maxOut)
	if err != nil {
		return "", err
	}
	if p.Pool != "" {
		if r := c.Ledger.AdmitPool(now, p.Pool); r != nil {
			return "", r
		}
	}
	if r := c.Ledger.AdmitSpend(now, plan, Name, worst); r != nil {
		if r.Code == key.RSpendTask || r.Code == key.RSpendDay {
			if err := c.Ledger.Hold(now, plan, r); err != nil {
				return "", err
			}
		}
		return "", r
	}
	reply, u, err := c.Provider.Call(route, prompt, maxOut)
	if err != nil {
		if merr := c.record(now, unmetered{plan, route, "admitted", worst}); merr != nil {
			return "", errors.Join(err, merr)
		}
		return "", err
	}
	amount, src := int64(0), "provider"
	if u.Reported {
		amount, err = p.cost(u.In, u.Out)
	} else {
		amount, err = p.cost(in, tokens(reply))
		src = "clerk"
	}
	if err != nil {
		amount, src = worst, "admitted"
	}
	if err := c.record(now, unmetered{plan, route, src, amount}); err != nil {
		return "", err
	}
	if p.Pool != "" && u.Pool != nil {
		if err := c.Ledger.ReadPool(now, p.Pool, u.Pool.Used, u.Pool.ResetAt); err != nil {
			return "", err
		}
	}
	return reply, nil
}
