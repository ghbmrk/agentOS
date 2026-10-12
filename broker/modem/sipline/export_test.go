package sipline

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

var loopback sync.Map // *netguard.Policy -> true

func init() {
	dialer, check := guardDialer, guardCheck
	guardDialer = func(g *netguard.Policy) *net.Dialer {
		d := dialer(g)
		if _, ok := loopback.Load(g); ok {
			inner := d.ControlContext
			d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
				if ap, err := netip.ParseAddrPort(address); err == nil && ap.Addr().Unmap().IsLoopback() {
					return nil
				}
				return inner(ctx, network, address, c)
			}
		}
		return d
	}
	guardCheck = func(g *netguard.Policy, ctx context.Context, a netip.Addr, port uint16, proto string) error {
		if _, ok := loopback.Load(g); ok && a.Unmap().IsLoopback() {
			return nil
		}
		return check(g, ctx, a, port, proto)
	}
}

// ReachLoopback lets a line using g reach loopback, where the simulated
// provider listens; every other address still goes through g.
func ReachLoopback(g *netguard.Policy) *netguard.Policy {
	loopback.Store(g, true)
	return g
}

// ParseAnswer exposes parseAnswer's verdict to the external tests.
func ParseAnswer(body []byte, private bool) error {
	_, err := parseAnswer(body, private)
	return err
}

// ParseOffer exposes parseOffer's verdict and the tag to echo.
func ParseOffer(body []byte, private bool) (string, error) {
	a, err := parseOffer(body, private)
	return a.tag, err
}

// SetInbound shortens the waits for a call to the line and sets the clock
// the clip limits read, until the returned restore is called.
// SetPollEvery sets how often the line polls its texting account.
func SetPollEvery(d time.Duration) (restore func()) {
	p := pollEvery
	pollEvery = d
	return func() { pollEvery = p }
}

func SetInbound(ack, latch time.Duration, clock func() time.Time) (restore func()) {
	a, l, n := ackWait, latchWait, now
	ackWait, latchWait, now = ack, latch, clock
	return func() { ackWait, latchWait, now = a, l, n }
}
