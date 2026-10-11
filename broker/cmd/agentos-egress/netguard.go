package main

import (
	"context"
	"log"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// netWatchEvery is the Watch interval: how soon a changed home network
// replaces the learned one (DEV-2).
const netWatchEvery = 10 * time.Second

// netGuard builds the process's one address policy (DEV-2): it learns the
// home network from src now and again every every until ctx ends, resolves
// names only through the learned resolver, journals each refusal, and
// carries no pin (a backup target or private hosted route is entered from
// owner settings, which this process does not read yet). A failed first read
// is logged, not fatal: the registries still apply and the next tick
// retries.
func netGuard(ctx context.Context, src *netguard.Sources, every time.Duration) (*netguard.Policy, error) {
	p := netguard.New(netguard.Config{
		Source: src.Read,
		OnDeny: func(e netguard.DenyEvent) {
			// Addresses and a reason only: no name, URL or credential.
			log.Printf("netguard: refused %v port %d purpose %d: %s", e.Addr, e.Port, e.Purpose, e.Reason)
		},
	})
	if err := p.SetPins(nil); err != nil {
		return nil, err
	}
	if err := p.Refresh(); err != nil {
		log.Printf("netguard: first read of the home network failed: %v", err)
	}
	go p.WatchEvery(ctx, every)
	return p, nil
}
