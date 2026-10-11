package netguard

import (
	"context"
	"net"
	"net/netip"
	"time"
)

// Resolver returns a resolver that asks only the learned resolver (DEV-2:
// names resolve only through the broker). It is the pure-Go resolver with
// its dial replaced: whatever server resolv.conf names, the connection is
// made to the learned resolver on port 53, under PurposeDNS, and checked
// like any other dial. Nothing is learned yet means nothing resolves.
func (p *Policy) Resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: p.dnsDial}
}

func (p *Policy) dnsDial(ctx context.Context, network, _ string) (net.Conn, error) {
	ctx = WithPurpose(ctx, PurposeDNS)
	p.mu.RLock()
	rs := p.net.Resolver
	p.mu.RUnlock()
	proto := protoOf(network)
	if proto != "tcp" && proto != "udp" {
		return nil, p.deny(ctx, netip.Addr{}, 53, proto, "dns over a non-IP network")
	}
	if !rs.IsValid() {
		return nil, p.deny(ctx, netip.Addr{}, 53, proto, "no resolver learned")
	}
	if err := p.Check(ctx, rs, 53, proto); err != nil {
		return nil, err
	}
	return p.connect(ctx, network, net.JoinHostPort(rs.String(), "53"))
}

// deny refuses a dial that has no address to check, and journals it.
func (p *Policy) deny(ctx context.Context, a netip.Addr, port uint16, proto, why string) error {
	if p.onDeny != nil {
		p.onDeny(DenyEvent{Addr: a, Port: port, Purpose: requestOf(ctx).purpose, Reason: why})
	}
	return &DeniedError{a, why}
}

// WatchEvery refreshes the learned network every d until ctx ends: the
// Watch interval. A changed network replaces the old set at the next tick.
func (p *Policy) WatchEvery(ctx context.Context, d time.Duration) {
	ev := make(chan struct{}, 1)
	go p.Watch(ctx, ev)
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			select {
			case ev <- struct{}{}:
			default:
			}
		}
	}
}
