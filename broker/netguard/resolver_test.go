package netguard

// REQ: DEV-2, REV-5, ARC-6

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type dialed struct {
	mu    sync.Mutex
	addrs []string
}

func (d *dialed) add(a string) {
	d.mu.Lock()
	d.addrs = append(d.addrs, a)
	d.mu.Unlock()
}
func (d *dialed) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.addrs...)
}

type events struct {
	mu sync.Mutex
	n  int
}

func (e *events) add() { e.mu.Lock(); e.n++; e.mu.Unlock() }
func (e *events) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.n
}

func learnedPolicy(t *testing.T, d *dialed, ev *events) *Policy {
	t.Helper()
	p := New(Config{
		Connect: func(_ context.Context, _, addr string) (net.Conn, error) {
			d.add(addr)
			return nil, errors.New("synthetic: not connected")
		},
		OnDeny: func(DenyEvent) { ev.add() },
	})
	p.Learn(Network{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Gateway:  netip.MustParseAddr("192.168.1.1"),
		Resolver: netip.MustParseAddr("192.168.1.53"),
	})
	return p
}

// Names resolve only through the learned resolver, on port 53, whatever
// server resolv.conf would name.
func TestResolverAsksOnlyTheLearnedResolver(t *testing.T) {
	var d dialed
	var ev events
	p := learnedPolicy(t, &d, &ev)
	_, _ = p.Resolver().LookupNetIP(context.Background(), "ip", "name.example")
	got := d.all()
	if len(got) == 0 {
		t.Fatal("the resolver never dialed the learned resolver")
	}
	for _, a := range got {
		if a != "192.168.1.53:53" {
			t.Fatalf("resolver dialed %q", a)
		}
	}
}

// Nothing learned means nothing resolves: no dial, and the refusal is journaled.
func TestResolverFailsClosedUntilLearned(t *testing.T) {
	var d dialed
	var ev events
	p := New(Config{
		Connect: func(_ context.Context, _, addr string) (net.Conn, error) { d.add(addr); return nil, errors.New("no") },
		OnDeny:  func(DenyEvent) { ev.add() },
	})
	if _, err := p.Resolver().LookupNetIP(context.Background(), "ip", "name.example"); err == nil {
		t.Fatal("resolved with no learned resolver")
	}
	if len(d.all()) != 0 {
		t.Fatalf("dialed %v", d.all())
	}
	if ev.count() == 0 {
		t.Fatal("refusal not journaled")
	}
}

// PurposeDNS reaches the learned resolver on port 53 and nothing else.
func TestDNSPurposeIsStrict(t *testing.T) {
	var d dialed
	var ev events
	p := learnedPolicy(t, &d, &ev)
	ctx := WithPurpose(context.Background(), PurposeDNS)
	for _, addr := range []string{"192.168.1.53:853", "192.168.1.1:53", "8.8.8.8:53", "192.168.1.53:80"} {
		if _, err := p.DialContext(ctx, "tcp", addr); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	if len(d.all()) != 0 {
		t.Fatalf("dialed %v", d.all())
	}
	if _, err := p.DialContext(ctx, "tcp", "192.168.1.53:53"); errors.Is(err, ErrDenied) {
		t.Fatalf("the learned resolver on 53 was refused: %v", err)
	}
}

// A changed network replaces the learned one within one Watch interval.
func TestWatchEveryReplacesLearnedNetwork(t *testing.T) {
	var n atomic.Value
	n.Store(Network{})
	p := New(Config{Source: func() (Network, error) { return n.Load().(Network), nil }})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("8.8.8.8"), 443, "tcp"); err != nil {
		t.Fatalf("before the change: %v", err)
	}
	n.Store(Network{External: netip.MustParseAddr("8.8.8.8")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.WatchEvery(ctx, 10*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(p.Check(context.Background(), netip.MustParseAddr("8.8.8.8"), 443, "tcp"), ErrDenied) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the new external address was not learned within the interval")
}
