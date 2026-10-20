// Package model is the clerk for model calls: the only exit for them (CLK-7).
// It admits a call against the cited key's spend caps, makes it, and meters
// what it used into the log (LOG-7).
package model

import (
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// Name is the clerk name a key must be issued for.
const Name = "model"

// Usage is a call's token count. Reported is true when the provider's
// connection carried the figure; otherwise the clerk counts its own.
type Usage struct {
	In, Out  int64
	Reported bool
}

// Provider makes the call. It holds the credential; nothing else does.
type Provider interface {
	Call(route, prompt string, maxOut int64) (reply string, u Usage, err error)
}

// Price is minor units per million tokens on one route.
type Price struct{ InPerM, OutPerM int64 }

// Ledger is the part of the kernel the clerk needs: the check and the record.
type Ledger interface {
	AdmitSpend(now int64, k key.Key, clerk, task string, amount int64) *key.Refusal
	Meter(now int64, k key.Key, task, route string, amount int64, source string) error
}

// Clerk is the model clerk.
type Clerk struct {
	Routes   map[string]Price
	Provider Provider
	Ledger   Ledger
}

// tokens is the clerk's own count: four bytes a token, rounded up.
func tokens(s string) int64 { return int64(len(s)+3) / 4 }

// cost rounds up, so metered spend never falls below the price.
func (p Price) cost(in, out int64) int64 {
	return (in*p.InPerM + out*p.OutPerM + 999_999) / 1_000_000
}

// Call runs one model call under key k for task. The worst case (the prompt
// plus maxOut tokens) must fit the caps before the provider is called; the
// reply is withheld if the usage cannot be recorded.
func (c *Clerk) Call(now int64, k key.Key, task, route, prompt string, maxOut int64) (string, error) {
	p, ok := c.Routes[route]
	if !ok {
		return "", fmt.Errorf("model: no route %q", route)
	}
	if maxOut <= 0 {
		return "", errors.New("model: maxOut must be positive")
	}
	if r := c.Ledger.AdmitSpend(now, k, Name, task, p.cost(tokens(prompt), maxOut)); r != nil {
		return "", r
	}
	reply, u, err := c.Provider.Call(route, prompt, maxOut)
	if err != nil {
		return "", err
	}
	src := "provider"
	if !u.Reported {
		u, src = Usage{In: tokens(prompt), Out: tokens(reply)}, "clerk"
	}
	if err := c.Ledger.Meter(now, k, task, route, p.cost(u.In, u.Out), src); err != nil {
		return "", err
	}
	return reply, nil
}
