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

// netEvents opens the kernel change feed; tests replace it.
var netEvents = netguard.WatchNetlink

// netGuard builds the process's one address policy (DEV-2): it learns the
// home network from src now, on each kernel change event and again every
// every until ctx ends, resolves
// names only through the learned resolver, journals each refusal, and
// carries no pin (a backup target or private hosted route is entered from
// owner settings, which this process does not read yet). A failed first read
// is logged, not fatal: the registries still apply and the next tick
// retries.
func netGuard(ctx context.Context, src *netguard.Sources, every time.Duration) (*netguard.Policy, error) {
	p := netguard.New(netguard.Config{
		Source: src.Read,
		Quick:  src.ReadLocal,
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
	// The poll stays as the backstop; a kernel address or route event adds
	// an immediate refresh (a new prefix is refused within the event). Both
	// feed one worker, so full reads never overlap (#1439).
	ev, err := netEvents(ctx)
	if err != nil {
		log.Printf("netguard: netlink unavailable, polling only: %v", err)
		ev = nil
	}
	go p.WatchEventsEvery(ctx, ev, every)
	return p, nil
}
