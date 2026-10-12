package main

// REQ: DEV-2, REV-5, ARC-6

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/netguard"
)

type fakeNet struct {
	mu    sync.Mutex
	route string
	ext   netip.Addr
}

func (f *fakeNet) set(route string, ext string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.route, f.ext = route, netip.MustParseAddr(ext)
}

func (f *fakeNet) sources() *netguard.Sources {
	return &netguard.Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			switch p {
			case "/proc/net/route":
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" + f.route), nil
			case "/etc/resolv.conf":
				return []byte("nameserver 192.168.1.53\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.ext, nil
		},
	}
}

const gw1 = "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"

// The egress process builds one policy that has learned the home network
// at start: the uplink prefix, the gateway and the router's external
// address are refused, and the refusal is journaled without a name.
func TestEgressProcessGuardRefusesTheLearnedNetwork(t *testing.T) {
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)
	f := &fakeNet{}
	f.set(gw1, "8.8.8.8")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := netGuard(ctx, f.sources(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.168.1.20", "192.168.1.1", "8.8.8.8", "::ffff:192.168.1.20"} {
		if err := g.Check(context.Background(), netip.MustParseAddr(a), 443, "tcp"); !errors.Is(err, netguard.ErrDenied) {
			t.Fatalf("%s: %v", a, err)
		}
	}
	if err := g.Check(context.Background(), netip.MustParseAddr("1.1.1.1"), 443, "tcp"); err != nil {
		t.Fatalf("a public address was refused: %v", err)
	}
	_, _ = g.DialContext(context.Background(), "tcp", "192.168.1.20:22")
	if !strings.Contains(buf.String(), "netguard: refused 192.168.1.20") {
		t.Fatalf("refusal not journaled: %q", buf.String())
	}
}

// A new gateway or external address replaces the old one within one tick.
func TestEgressProcessGuardFollowsTheNetwork(t *testing.T) {
	f := &fakeNet{}
	f.set(gw1, "8.8.8.8")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := netGuard(ctx, f.sources(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	f.set(gw1, "9.9.9.9")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(g.Check(context.Background(), netip.MustParseAddr("9.9.9.9"), 443, "tcp"), netguard.ErrDenied) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the new external address was not learned within the interval")
}

// A kernel address or route event applies the new network within the event,
// with the poll interval far away (DEV-2).
func TestEgressProcessGuardFollowsNetlinkEvents(t *testing.T) {
	f := &fakeNet{}
	f.set(gw1, "8.8.8.8")
	ev := make(chan struct{}, 1)
	prev := netEvents
	netEvents = func(context.Context) (<-chan struct{}, error) { return ev, nil }
	defer func() { netEvents = prev }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := netGuard(ctx, f.sources(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.set(gw1, "9.9.9.9")
	ev <- struct{}{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(g.Check(context.Background(), netip.MustParseAddr("9.9.9.9"), 443, "tcp"), netguard.ErrDenied) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the event did not apply the new network")
}

// Where netlink cannot be opened the poll still applies and the failure is
// logged.
func TestEgressProcessGuardKeepsPollWithoutNetlink(t *testing.T) {
	var buf bytes.Buffer
	prevLog := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevLog)
	prev := netEvents
	netEvents = func(context.Context) (<-chan struct{}, error) { return nil, errors.New("no socket") }
	defer func() { netEvents = prev }()
	f := &fakeNet{}
	f.set(gw1, "8.8.8.8")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g, err := netGuard(ctx, f.sources(), 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	f.set(gw1, "9.9.9.9")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(g.Check(context.Background(), netip.MustParseAddr("9.9.9.9"), 443, "tcp"), netguard.ErrDenied) {
			if !strings.Contains(buf.String(), "netlink") {
				t.Fatalf("the netlink failure was not logged: %q", buf.String())
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the poll did not apply the new network")
}
