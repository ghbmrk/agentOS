package main

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// The process's one address policy (MIG-4-untrusted-exit-b2b, DEV-2), built as
// cmd/agentos-egress's netGuard is; copied, since this process links no
// other command (D-154 rule 4).

// netWatchEvery is the Watch interval: how soon a changed home network
// replaces the learned one (DEV-2).
const netWatchEvery = 10 * time.Second

// netEvents opens the kernel change feed; tests replace it.
var netEvents = netguard.WatchNetlink

// netConnect, when set, replaces the policy's final connect; a test seam,
// nil in the process.
var netConnect func(ctx context.Context, network, addr string) (net.Conn, error)

// netGuard builds the process's policy: it learns the home network from src
// now, on each kernel change event and again every every until ctx ends,
// resolves names only through the learned resolver, logs each refusal by
// address and reason only, and carries no pin. A failed first read is
// logged, not fatal: until a read succeeds nothing resolves, so nothing is
// dialled, and the next tick retries.
func netGuard(ctx context.Context, src *netguard.Sources, every time.Duration) (*netguard.Policy, error) {
	p := netguard.New(netguard.Config{
		Source: src.Read,
		Quick:  src.ReadLocal,
		OnDeny: func(e netguard.DenyEvent) {
			// Addresses and a reason only: no name, URL or credential.
			log.Printf("netguard: refused %v port %d purpose %d: %s", e.Addr, e.Port, e.Purpose, e.Reason)
		},
		Connect: netConnect,
	})
	if err := p.SetPins(nil); err != nil {
		return nil, err
	}
	if err := p.Refresh(); err != nil {
		log.Printf("netguard: first read of the home network failed: %v", err)
	}
	ev, err := netEvents(ctx)
	if err != nil {
		log.Printf("netguard: netlink unavailable, polling only: %v", err)
		ev = nil
	}
	go p.WatchEventsEvery(ctx, ev, every)
	return p, nil
}
