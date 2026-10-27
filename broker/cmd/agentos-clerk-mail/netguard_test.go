package main

// REQ: DEV-2, D-154

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// The main's policy learns the home network from its sources: before any
// learn a lookup through its resolver is refused with nothing dialled, and
// after a learn only the learned resolver's address is dialled (DEV-2).
func TestTheMailClerkLearnsItsNetwork(t *testing.T) {
	var mu sync.Mutex
	up := false
	var dialled []string
	src := &netguard.Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case !up:
				return nil, errors.New("absent")
			case p == "/proc/net/route":
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"), nil
			case p == "/etc/resolv.conf":
				return []byte("nameserver 192.168.1.53\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) { return netip.MustParseAddr("8.8.8.8"), nil },
	}
	prevEv, prevConn := netEvents, netConnect
	netEvents = func(context.Context) (<-chan struct{}, error) { return nil, errors.New("no netlink here") }
	netConnect = func(_ context.Context, _, addr string) (net.Conn, error) {
		mu.Lock()
		dialled = append(dialled, addr)
		mu.Unlock()
		return nil, errors.New("test: no server")
	}
	defer func() { netEvents, netConnect = prevEv, prevConn }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := netGuard(ctx, src, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func() {
		lctx, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		_, _ = g.Resolver().LookupTXT(lctx, "s1._domainkey.shop.test.")
	}
	lookup()
	mu.Lock()
	if len(dialled) != 0 {
		t.Fatalf("before any learn, %q was dialled", dialled)
	}
	up = true
	mu.Unlock()
	if err := g.Refresh(); err != nil {
		t.Fatalf("the policy has no working source: %v", err)
	}
	lookup()
	mu.Lock()
	defer mu.Unlock()
	if len(dialled) == 0 {
		t.Fatal("after a learn, the lookup dialled nothing")
	}
	for _, a := range dialled {
		if a != "192.168.1.53:53" {
			t.Fatalf("dialled %q; want only the learned resolver", a)
		}
	}
}
