package netguard

// REQ: DEV-2, REV-5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func nlmsg(typ uint16) []byte {
	b := make([]byte, syscall.NLMSG_HDRLEN+4)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	return b
}

// neighmsg is one RTM_NEWNEIGH/RTM_DELNEIGH message for dst (an ndmsg of
// family fam, then an NDA_LLADDR and an NDA_DST attribute).
func neighmsg(typ uint16, fam byte, dst []byte) []byte {
	nd := make([]byte, 12)
	nd[0] = fam
	attr := func(t uint16, v []byte) []byte {
		a := make([]byte, (4+len(v)+3)&^3)
		binary.NativeEndian.PutUint16(a[0:], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(a[2:], t)
		copy(a[4:], v)
		return a
	}
	body := append(append(nd, attr(2, []byte{2, 0, 0, 0, 0, 0x0b})...), attr(1, dst)...)
	b := make([]byte, syscall.NLMSG_HDRLEN, syscall.NLMSG_HDRLEN+len(body))
	b = append(b, body...)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	return b
}

// Address, route and link changes are events, and so is a change to the
// IPv4 default gateway's neighbour entry (a router swapped behind the same
// address with no link event at the box, #1536); the rest of what the
// kernel sends on the groups is not, and another host's neighbour entry
// does not even read the route table.
func TestNetlinkEventsAreAddressRouteLinkAndGatewayNeighbourChanges(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	asked := 0
	gateway := func() netip.Addr { asked++; return gw }
	for _, typ := range []uint16{syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK} {
		if !netlinkChange(nlmsg(typ), gateway) {
			t.Fatalf("type %d is a network change", typ)
		}
	}
	for _, typ := range []uint16{syscall.NLMSG_DONE, syscall.NLMSG_NOOP, syscall.RTM_NEWNEIGH, syscall.RTM_GETNEIGH} {
		if netlinkChange(nlmsg(typ), gateway) {
			t.Fatalf("type %d is not a network change", typ)
		}
	}
	if netlinkChange([]byte{1, 2, 3}, gateway) {
		t.Fatal("a truncated message is not a change")
	}
	if asked != 0 {
		t.Fatalf("the gateway was read %d times for messages with no neighbour address", asked)
	}
	for _, typ := range []uint16{syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH} {
		if !netlinkChange(neighmsg(typ, syscall.AF_INET, []byte{192, 168, 1, 1}), gateway) {
			t.Fatalf("type %d on the gateway's entry is a network change", typ)
		}
		if netlinkChange(neighmsg(typ, syscall.AF_INET, []byte{192, 168, 1, 9}), gateway) {
			t.Fatalf("type %d on another host's entry is not a network change", typ)
		}
	}
	v6 := netip.MustParseAddr("fe80::1").As16()
	if netlinkChange(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET6, v6[:]), gateway) {
		t.Fatal("an IPv6 neighbour entry is not a network change")
	}
	two := append(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 9}), neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 8})...)
	asked = 0
	if netlinkChange(two, gateway) || asked != 1 {
		t.Fatalf("one read of other hosts' entries asked the gateway %d times", asked)
	}
	if netlinkChange(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 1}), func() netip.Addr { return netip.Addr{} }) {
		t.Fatal("a neighbour entry with no default gateway is not a network change")
	}
}

// A new prefix is refused within one event, not one poll: the event learns
// the prefix from the quick local read at once, while the full refresh
// (which may wait on the router) is still running.
func TestWatchEventLearnsNewPrefixBeforeSlowRefresh(t *testing.T) {
	release := make(chan struct{})
	old := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	next := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("8.8.8.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	var slow atomic.Bool
	p := New(Config{
		Source: func() (Network, error) {
			if slow.Load() {
				<-release // the slow external lookup
				return next, nil
			}
			return old, nil
		},
		Quick: func() (Network, error) { return next, nil },
	})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	probe := netip.MustParseAddr("8.8.8.9")
	if err := p.Check(context.Background(), probe, 443, "tcp"); err != nil {
		t.Fatalf("before the event: %v", err)
	}
	slow.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	ev := make(chan struct{}, 1)
	watched := make(chan struct{})
	go func() { p.Watch(ctx, ev); close(watched) }()
	// End the slow read before the next test runs: it writes refreshGapHook.
	defer func() { close(release); cancel(); <-watched }()
	ev <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(p.Check(context.Background(), probe, 443, "tcp"), ErrDenied) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the new prefix was not refused after one event")
}

// A quick read keeps the router's external address while the gateway is
// unchanged; it is not dropped until the full refresh replaces it.
func TestQuickLearnKeepsExternalWhileGatewayUnchanged(t *testing.T) {
	gw := netip.MustParseAddr("192.168.1.1")
	ext := netip.MustParseAddr("8.8.8.8")
	p := New(Config{
		Source: func() (Network, error) { return Network{Gateway: gw, External: ext}, nil },
		Quick:  func() (Network, error) { return Network{Gateway: gw}, nil },
	})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	p.quickLearn()
	if err := p.Check(context.Background(), ext, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("the external address was forgotten: %v", err)
	}
}

// A second event is not queued behind the first event's slow full read: on
// an IPv6 RA the route event's quick read misses the address and the address
// event's quick read has it (DEV-2).
func TestWatchSecondEventIsNotQueuedBehindSlowRead(t *testing.T) {
	release := make(chan struct{})
	old := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	next := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("8.8.8.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	var slow atomic.Bool
	var quicks atomic.Int32
	p := New(Config{
		Source: func() (Network, error) {
			if slow.Load() {
				<-release
			}
			return old, nil
		},
		Quick: func() (Network, error) {
			if quicks.Add(1) == 1 {
				return old, nil // the route event: the address is not there yet
			}
			return next, nil
		},
	})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	slow.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	ev := make(chan struct{})
	watched := make(chan struct{})
	go func() { p.Watch(ctx, ev); close(watched) }()
	// End the slow read before the next test runs: it writes refreshGapHook.
	defer func() { close(release); cancel(); <-watched }()
	ev <- struct{}{}
	ev <- struct{}{}
	probe := netip.MustParseAddr("8.8.8.9")
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if errors.Is(p.Check(context.Background(), probe, 443, "tcp"), ErrDenied) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the second event waited behind the first event's slow read")
}

// A full read that began before the change never overwrites the newer quick
// learn when it returns late (a poll read racing a netlink event).
func TestStaleFullReadDoesNotOverwriteNewerLearn(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	old := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	next := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("8.8.8.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	var calls atomic.Int32
	p := New(Config{
		Source: func() (Network, error) {
			if calls.Add(1) == 1 {
				close(started)
				<-release // the poll read: local part already ran on the old network
			}
			return old, nil
		},
		Quick: func() (Network, error) { return next, nil },
	})
	done := make(chan struct{})
	go func() { _ = p.Refresh(); close(done) }()
	<-started
	p.quickLearn() // the netlink event
	probe := netip.MustParseAddr("8.8.8.9")
	if err := p.Check(context.Background(), probe, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("after the event: %v", err)
	}
	close(release)
	<-done
	if err := p.Check(context.Background(), probe, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("the stale poll read re-allowed the new prefix: %v", err)
	}
}

// A quick learn that lands after a full read's generation check but before
// its store still wins: the check and the store are one critical section.
func TestQuickLearnInRefreshGapIsNotOverwritten(t *testing.T) {
	old := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	next := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("8.8.8.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
	p := New(Config{
		Source: func() (Network, error) { return old, nil },
		Quick:  func() (Network, error) { return next, nil },
	})
	refreshGapHook = p.quickLearn // the netlink event, in the gap if there is one
	t.Cleanup(func() { refreshGapHook = nil })
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	probe := netip.MustParseAddr("8.8.8.9")
	if err := p.Check(context.Background(), probe, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("the stale poll read re-allowed the new prefix: %v", err)
	}
}

// A full read that stores a newer external address after a quick read
// returns, but before quickLearn merges and stores, is kept: the quick
// read's copy of the external address never replaces the learned one while
// the gateway is unchanged, and the merge and the store are one critical
// section under the write lock (#1492).
func TestRefreshInQuickGapKeepsNewerExternal(t *testing.T) {
	oldExt, newExt := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	ext := oldExt
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			if f == "/proc/net/route" {
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) { return ext, nil },
	}
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	quickGapHook = func() {
		ext = newExt // the router's WAN address changes
		if err := p.Refresh(); err != nil {
			t.Error(err)
		}
	}
	held := false
	quickLockedHook = func() {
		if p.mu.TryRLock() {
			p.mu.RUnlock()
			return
		}
		held = true
	}
	t.Cleanup(func() { quickGapHook, quickLockedHook = nil, nil })
	p.quickLearn()
	if !held {
		t.Fatal("quickLearn read what is learned without holding the write lock")
	}
	p.mu.RLock()
	got := p.net.External
	p.mu.RUnlock()
	if got != newExt {
		t.Fatalf("external after the quick learn = %v, want %v", got, newExt)
	}
	if err := p.Check(context.Background(), newExt, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("the router's new external address is dialable: %v", err)
	}
}

// A quick read that lands in a full read's gap, after the full read has
// asked the router and found a newer external address, does not stop that
// address from being learned: the quick read keeps the old learned address,
// and the stale full read then stores its own external address because the
// gateway is unchanged (#1492, the mirror of
// TestRefreshInQuickGapKeepsNewerExternal).
func TestQuickInRefreshGapKeepsNewerExternal(t *testing.T) {
	oldExt, newExt := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	ext := oldExt
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			if f == "/proc/net/route" {
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) { return ext, nil },
	}
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	ext = newExt // the router's WAN address changes
	refreshGapHook = p.quickLearn
	t.Cleanup(func() { refreshGapHook = nil })
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	p.mu.RLock()
	got := p.net.External
	p.mu.RUnlock()
	if got != newExt {
		t.Fatalf("external after the full read = %v, want %v", got, newExt)
	}
	if err := p.Check(context.Background(), newExt, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("the router's new external address is dialable: %v", err)
	}
}

// When the gateway changes, a quick read never carries the previous
// network's external address over: it takes its own (from Sources.ReadLocal,
// the last one read on that gateway). On a flip-back (G1, then G2, then G1
// again) G2's router address is not kept as G1's, and G1's own, learned on
// G1 earlier, is refused at once, before the full read lands (#1517).
func TestQuickLearnGatewayChangeDropsOldExternal(t *testing.T) {
	e1, e2 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	g1, g2 := netip.MustParseAddr("192.168.1.1"), netip.MustParseAddr("192.168.2.1")
	gw, ext := "0101A8C0", e1
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(16, 32)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			if f == "/proc/net/route" {
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t" + gw + "\t0003\t0\t0\t100\t00000000\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) { return ext, nil },
	}
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	learned := func() Network {
		p.mu.RLock()
		defer p.mu.RUnlock()
		return p.net
	}
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	gw, ext = "0102A8C0", e2 // to G2
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if n := learned(); n.Gateway != g2 || n.External != e2 {
		t.Fatalf("after the G2 read: gateway %v external %v, want %v %v", n.Gateway, n.External, g2, e2)
	}
	gw, ext = "0101A8C0", e1 // back to G1
	p.quickLearn()
	if n := learned(); n.Gateway != g1 || n.External != e1 {
		t.Fatalf("after the quick read back on G1: gateway %v external %v, want %v and %v (G2's address is not G1's)", n.Gateway, n.External, g1, e1)
	}
	if err := p.Check(context.Background(), e1, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("G1's router address is dialable right after the quick read back on G1: %v", err)
	}
	if err := p.Check(context.Background(), e2, 443, "tcp"); err != nil {
		t.Fatalf("G2's router address is still refused on G1: %v", err)
	}
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if err := p.Check(context.Background(), e1, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("G1's router address is dialable after the full read: %v", err)
	}
}

// gwSources is a real Sources whose default gateway and router answer the
// test moves. Each full read asks ext, or waits for one value from answer
// when ext is nil.
type gwSources struct {
	gw     atomic.Value // string, /proc/net/route hex
	mac    atomic.Value // string, the gateway's MAC in /proc/net/arp; unset or "" is no entry
	dev    atomic.Value // string, the default route's interface; unset is eth0
	down   atomic.Bool  // the interface addresses cannot be read
	answer chan netip.Addr
	ext    func(ctx context.Context) (netip.Addr, error)
}

func (g *gwSources) iface() string {
	if d, _ := g.dev.Load().(string); d != "" {
		return d
	}
	return "eth0"
}

func (g *gwSources) sources() *Sources {
	return &Sources{
		Addrs: func() ([]net.Addr, error) {
			if g.down.Load() {
				return nil, errors.New("interfaces unreadable")
			}
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(16, 32)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			switch f {
			case "/proc/net/route":
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" + g.iface() + "\t00000000\t" + g.gw.Load().(string) + "\t0003\t0\t0\t100\t00000000\n"), nil
			case "/etc/resolv.conf":
				return []byte("nameserver 192.168.1.53\n"), nil
			case "/proc/net/arp":
				if m, _ := g.mac.Load().(string); m != "" {
					return []byte(arpTable(g.gw.Load().(string), m, g.iface())), nil
				}
			}
			return nil, errors.New("absent")
		},
		External: func(ctx context.Context, _ netip.Addr) (netip.Addr, error) {
			if g.ext != nil {
				return g.ext(ctx)
			}
			select {
			case a := <-g.answer:
				return a, nil
			case <-ctx.Done():
				return netip.Addr{}, ctx.Err()
			}
		},
	}
}

// On a gateway never read before, the quick read has no external address,
// so public destinations wait for that gateway's full read (fail closed): a
// dial held in that window goes ahead once the full read stores, and the
// router's address the full read learned is refused (#1517).
func TestNeverSeenGatewayHoldsPublicUntilFullRead(t *testing.T) {
	e1, e3 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	public := netip.MustParseAddr("1.1.1.1")
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.answer <- e1
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	g.gw.Store("0103A8C0") // to G3, never read
	p.quickLearn()
	held := make(chan error, 2)
	go func() { held <- p.Check(context.Background(), e3, 443, "tcp") }()
	go func() { held <- p.Check(context.Background(), public, 443, "tcp") }()
	select {
	case err := <-held:
		t.Fatalf("a public destination was decided before G3's full read: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("192.168.1.9"), 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("a home address is not refused at once while held: %v", err)
	}
	g.answer <- e3
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	var denied, allowed int
	for i := 0; i < 2; i++ {
		select {
		case err := <-held:
			if errors.Is(err, ErrDenied) {
				denied++
			} else if err == nil {
				allowed++
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a held dial did not go ahead after the full read stored")
		}
	}
	if denied != 1 || allowed != 1 {
		t.Fatalf("after G3's full read: %d refused, %d allowed; want G3's router address refused and the public one allowed", denied, allowed)
	}
}

// The hold is bounded: if the gateway's full read never stores, a held
// public destination is refused when the bound or the caller's context ends,
// never allowed.
func TestNeverSeenGatewayHoldFailsClosed(t *testing.T) {
	old := externalHold
	externalHold = 50 * time.Millisecond
	t.Cleanup(func() { externalHold = old })
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.answer <- netip.MustParseAddr("8.8.8.8")
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	g.gw.Store("0103A8C0")
	p.quickLearn()
	public := netip.MustParseAddr("1.1.1.1")
	if err := p.Check(context.Background(), public, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("a public destination is allowed with no full read on the new gateway: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	externalHold = time.Hour
	if err := p.Check(ctx, public, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("a cancelled held check is not refused: %v", err)
	}
}

// A full read in flight when the gateway changes is stale. If it read the
// new gateway, its router answer ends the hold and is refused; a silent
// router ends it too, since that gateway has nothing more to learn.
func TestStaleFullReadOnNewGatewayEndsHold(t *testing.T) {
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.answer <- netip.MustParseAddr("8.8.8.8")
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	public := netip.MustParseAddr("1.1.1.1")
	for _, c := range []struct {
		gw  string
		ext netip.Addr
	}{{"0103A8C0", netip.MustParseAddr("9.9.9.9")}, {"0104A8C0", netip.Addr{}}} {
		g.gw.Store(c.gw)
		// The event lands while the full read waits on the new router.
		g.ext = func(context.Context) (netip.Addr, error) {
			p.quickLearn()
			p.mu.RLock()
			hold := p.hold
			p.mu.RUnlock()
			if hold == nil {
				t.Errorf("gateway %s: no hold after the quick read", c.gw)
			}
			if !c.ext.IsValid() {
				return netip.Addr{}, errors.New("no answer")
			}
			return c.ext, nil
		}
		if err := p.Refresh(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- p.Check(context.Background(), public, 443, "tcp") }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("gateway %s: public refused after the stale full read: %v", c.gw, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("gateway %s: the hold did not end on a stale full read of the new gateway", c.gw)
		}
		if c.ext.IsValid() {
			if err := p.Check(context.Background(), c.ext, 443, "tcp"); !errors.Is(err, ErrDenied) {
				t.Fatalf("gateway %s: the router's address is dialable: %v", c.gw, err)
			}
		}
	}
}

// externalHold must outlast one full read's two router requests (the first,
// and the one to the gateway it ended on), or the hold refuses on a healthy
// router.
func TestExternalHoldOutlastsTwoRouterReads(t *testing.T) {
	for _, d := range []time.Duration{externalReadTimeout, natpmpDeadline} {
		if externalHold <= 2*d {
			t.Fatalf("externalHold %v is not past two router reads of %v", externalHold, d)
		}
	}
}

// While a hold is on, names still resolve through the assigned resolver and
// pinned endpoints still connect: only unpinned public destinations wait.
func TestHoldSparesDNSAndPins(t *testing.T) {
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.answer <- netip.MustParseAddr("8.8.8.8")
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	pinned := netip.MustParseAddrPort("203.0.113.20:8443")
	if err := p.SetPins([]Pin{{Kind: PinCompute, Addr: pinned, Key: [32]byte{1}}}); err != nil {
		t.Fatal(err)
	}
	g.gw.Store("0103A8C0")
	p.quickLearn()
	p.mu.RLock()
	held := p.hold != nil
	p.mu.RUnlock()
	if !held {
		t.Fatal("no hold on a never-seen gateway")
	}
	done := make(chan error, 2)
	go func() {
		done <- p.Check(WithPurpose(context.Background(), PurposeDNS), netip.MustParseAddr("192.168.1.53"), 53, "udp")
	}()
	go func() {
		done <- p.Check(WithPurpose(context.Background(), PurposeModelCall), pinned.Addr(), pinned.Port(), "tcp")
	}()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("held or refused: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("DNS or a pinned endpoint waits on the hold")
		}
	}
}

// A policy with a quick read but no full-read source has nothing that could
// end a hold, so it never starts one.
func TestNoHoldWithoutFullReadSource(t *testing.T) {
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0103A8C0")
	s := g.sources()
	p := New(Config{Quick: s.ReadLocal})
	p.quickLearn()
	p.mu.RLock()
	held := p.hold != nil
	p.mu.RUnlock()
	if held {
		t.Fatal("a hold started with no Config.Source to end it")
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("1.1.1.1"), 443, "tcp"); err != nil {
		t.Fatalf("public destination: %v", err)
	}
}

// Through the egress process's own worker (WatchEventsEvery): an event on a
// never-seen gateway holds public destinations, and that worker's full read
// ends the hold and refuses the router's address it learned.
func TestHoldEndsThroughTheWatchWorker(t *testing.T) {
	g := &gwSources{answer: make(chan netip.Addr)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	ev := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.WatchEventsEvery(ctx, ev, time.Hour); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	e1, e3 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	ev <- struct{}{}
	g.answer <- e1
	waitDenied(t, p, e1)
	g.gw.Store("0103A8C0")
	ev <- struct{}{}
	for end := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		p.mu.RLock()
		on := p.hold != nil
		p.mu.RUnlock()
		if on {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the worker's quick read on G3 started no hold")
		}
	}
	held := make(chan error, 1)
	go func() { held <- p.Check(context.Background(), e3, 443, "tcp") }()
	select {
	case err := <-held:
		t.Fatalf("G3's router address was decided before G3's full read: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	g.answer <- e3
	select {
	case err := <-held:
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("G3's router address after the worker's full read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker's full read did not end the hold")
	}
}

// waitDenied waits for the worker to learn that a is refused.
func waitDenied(t *testing.T, p *Policy, a netip.Addr) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		p.mu.RLock()
		learned, held := p.net.External == a, p.hold != nil
		p.mu.RUnlock()
		if learned && !held {
			if err := p.Check(context.Background(), a, 443, "tcp"); !errors.Is(err, ErrDenied) {
				t.Fatalf("%v learned but not refused: %v", a, err)
			}
			return
		}
	}
	t.Fatalf("%v never refused as the router's address", a)
}

// arpTable is /proc/net/arp text with one complete entry on dev for the
// gateway (route-table hex) at mac.
func arpTable(gwHex, mac, dev string) string {
	v, _ := strconv.ParseUint(gwHex, 16, 32)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return "IP address       HW type     Flags       HW address            Mask     Device\n" +
		netip.AddrFrom4(b).String() + "      0x1         0x2         " + mac + "     *        " + dev + "\n"
}

// A different router behind the same gateway address is a new gateway: the
// quick read after the move (a new MAC in the neighbour table, or none yet
// after a link flap flushed it) does not carry the previous router's
// external address over, so public destinations wait for the new router's
// full read, and the new router's address it learns is refused (#1536).
func TestSameGatewayNewRouterHoldsPublicUntilFullRead(t *testing.T) {
	for _, tc := range []struct{ name, macB string }{
		{"new MAC", "02:00:00:00:00:0b"},
		{"neighbour entry flushed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eA, eB := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
			public := netip.MustParseAddr("1.1.1.1")
			g := &gwSources{answer: make(chan netip.Addr, 1)}
			g.gw.Store("0101A8C0")
			g.mac.Store("02:00:00:00:00:0a")
			s := g.sources()
			p := New(Config{Source: s.Read, Quick: s.ReadLocal})
			g.answer <- eA
			if err := p.Refresh(); err != nil {
				t.Fatal(err)
			}
			g.mac.Store(tc.macB) // router B, same gateway address
			p.quickLearn()
			held := make(chan error, 2)
			go func() { held <- p.Check(context.Background(), eB, 443, "tcp") }()
			go func() { held <- p.Check(context.Background(), public, 443, "tcp") }()
			select {
			case err := <-held:
				t.Fatalf("a public destination was decided before router B's full read: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			g.mac.Store("02:00:00:00:00:0b") // the NAT-PMP request resolves B
			g.answer <- eB
			if err := p.Refresh(); err != nil {
				t.Fatal(err)
			}
			var denied, allowed int
			for i := 0; i < 2; i++ {
				select {
				case err := <-held:
					if errors.Is(err, ErrDenied) {
						denied++
					} else if err == nil {
						allowed++
					}
				case <-time.After(5 * time.Second):
					t.Fatal("a held dial did not go ahead after the full read stored")
				}
			}
			if denied != 1 || allowed != 1 {
				t.Fatalf("after router B's full read: %d refused, %d allowed; want B's address refused and the public one allowed", denied, allowed)
			}
		})
	}
}

// holdOpen reports whether public destinations are held.
func holdOpen(p *Policy) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.hold != nil
}

// A full read the gateway changes under (another address, the same address
// with another router's MAC, or the entry flushed and then resolved to
// another router) asks the router it ended on, with or without a change
// event: public destinations stay held until that router answers, never on
// the first router's answer, and the router's address it learns is refused
// (#1536).
func TestFullReadAcrossGatewayChangeAsksTheEndRouter(t *testing.T) {
	for _, tc := range []struct{ name, gw, mac, resolved string }{
		{"new address", "0102A8C0", "02:00:00:00:00:0b", ""},
		{"same address, new MAC", "0101A8C0", "02:00:00:00:00:0b", ""},
		{"entry flushed", "0101A8C0", "", "02:00:00:00:00:0b"},
	} {
		for _, event := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, event %v", tc.name, event), func(t *testing.T) {
				eA, eB := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
				g := &gwSources{}
				g.gw.Store("0101A8C0")
				g.mac.Store("02:00:00:00:00:0a")
				s := g.sources()
				p := New(Config{Source: s.Read, Quick: s.ReadLocal})
				g.ext = func(context.Context) (netip.Addr, error) { return eA, nil }
				if err := p.Refresh(); err != nil {
					t.Fatal(err)
				}
				calls := 0
				held := make(chan error, 1)
				g.ext = func(context.Context) (netip.Addr, error) {
					calls++
					switch calls {
					case 1: // router A answers, then the gateway changes
						g.gw.Store(tc.gw)
						g.mac.Store(tc.mac)
						if event {
							p.quickLearn()
							if !holdOpen(p) {
								t.Error("no hold after the event")
							}
						}
						return eA, nil
					case 2: // the request to the end gateway
						if tc.resolved != "" {
							g.mac.Store(tc.resolved)
							if event {
								p.quickLearn()
							}
						}
						if event {
							if !holdOpen(p) {
								t.Error("the first router's answer ended the hold")
							}
							go func() { held <- p.Check(context.Background(), eB, 443, "tcp") }()
							select {
							case err := <-held:
								t.Errorf("router B's address was decided before B answered: %v", err)
							case <-time.After(100 * time.Millisecond):
							}
						} else {
							p.mu.RLock()
							n := p.net
							p.mu.RUnlock()
							if n.External != eA || n.GatewayMAC != "02:00:00:00:00:0a" {
								t.Errorf("router A's network changed with no event: %+v", n)
							}
						}
						return eB, nil
					}
					t.Errorf("router asked %d times", calls)
					return netip.Addr{}, errors.New("no answer")
				}
				if err := p.Refresh(); err != nil {
					t.Fatal(err)
				}
				if calls != 2 {
					t.Fatalf("router asked %d times, want 2", calls)
				}
				p.mu.RLock()
				n := p.net
				p.mu.RUnlock()
				if n.External != eB || holdOpen(p) {
					t.Fatalf("after the end router's answer: %+v, hold %v", n, holdOpen(p))
				}
				if event {
					select {
					case err := <-held:
						if !errors.Is(err, ErrDenied) {
							t.Fatalf("held check on router B's address: %v", err)
						}
					case <-time.After(2 * time.Second):
						t.Fatal("the held check was never decided")
					}
				}
				if err := p.Check(context.Background(), eB, 443, "tcp"); !errors.Is(err, ErrDenied) {
					t.Fatalf("router B's address is dialable: %v", err)
				}
			})
		}
	}
}

// A full read the gateway changes under twice returns ErrGatewayMoved with
// the network it ended on, and nothing is filed. With no event, the policy
// applies that network as a quick read would: a never-seen gateway holds
// public destinations, and the next full read ends the hold.
func TestFullReadMovedTwiceHoldsUntilNextRead(t *testing.T) {
	eA, e3 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.ext = func(context.Context) (netip.Addr, error) { return eA, nil }
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	gws := []string{"0102A8C0", "0103A8C0"}
	g.ext = func(context.Context) (netip.Addr, error) {
		g.gw.Store(gws[0])
		gws = gws[1:]
		return eA, nil
	}
	if err := p.Refresh(); !errors.Is(err, ErrGatewayMoved) {
		t.Fatalf("a read moved under twice: %v", err)
	}
	p.mu.RLock()
	n := p.net
	p.mu.RUnlock()
	if n.Gateway != netip.MustParseAddr("192.168.3.1") || n.External.IsValid() || !holdOpen(p) {
		t.Fatalf("after the double move: %+v, hold %v", n, holdOpen(p))
	}
	if ln, _ := s.ReadLocal(); ln.External.IsValid() {
		t.Fatalf("an answer was filed under the end gateway: %v", ln.External)
	}
	g.ext = func(context.Context) (netip.Addr, error) { return e3, nil }
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if holdOpen(p) {
		t.Fatal("the next full read did not end the hold")
	}
	if err := p.Check(context.Background(), e3, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("G3's router address is dialable: %v", err)
	}
}

// The worker follows a full read that returned ErrGatewayMoved with another
// at once, without waiting for an event or a poll.
func TestWatchRereadsAfterGatewayMoved(t *testing.T) {
	var calls atomic.Int32
	again := make(chan struct{}, 1)
	p := New(Config{Source: func() (Network, error) {
		n := Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, Gateway: netip.MustParseAddr("192.168.1.1")}
		if calls.Add(1) == 1 {
			return n, ErrGatewayMoved
		}
		select {
		case again <- struct{}{}:
		default:
		}
		return n, nil
	}})
	ev := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.WatchEventsEvery(ctx, ev, time.Hour); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	ev <- struct{}{}
	select {
	case <-again:
	case <-time.After(5 * time.Second):
		t.Fatalf("no full read after ErrGatewayMoved (%d reads)", calls.Load())
	}
}

// A full read that read router A's answer is stale if router B replaced A
// behind the same address before it stored: A's address is not given to B
// and B's hold stays open (#1536).
func TestStaleFullReadOfOldRouterKeepsNewRoutersHold(t *testing.T) {
	eA := netip.MustParseAddr("8.8.8.8")
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	g.mac.Store("02:00:00:00:00:0a")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	g.ext = func(context.Context) (netip.Addr, error) { return eA, nil }
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	refreshGapHook = func() {
		g.mac.Store("02:00:00:00:00:0b")
		p.quickLearn()
	}
	t.Cleanup(func() { refreshGapHook = nil })
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	p.mu.RLock()
	n := p.net
	p.mu.RUnlock()
	if n.External.IsValid() || !holdOpen(p) {
		t.Fatalf("router A's stale read applied to router B: %+v, hold %v", n, holdOpen(p))
	}
}

// The policy keys the gateway on its interface too: after an answer read on
// ppp0 with no neighbour entry, the same address on wlan0 with no entry is a
// new gateway. The quick read does not carry ppp0's router address over;
// public destinations are held until wlan0's full read, and the router
// address that read learns is refused (#1536).
func TestPolicyGatewayKeyedByInterface(t *testing.T) {
	eA, eB := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	g.dev.Store("ppp0")
	g.ext = func(context.Context) (netip.Addr, error) { return eA, nil }
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	g.dev.Store("wlan0")
	p.quickLearn()
	p.mu.RLock()
	n := p.net
	p.mu.RUnlock()
	if !holdOpen(p) || n.GatewayDev != "wlan0" || n.External.IsValid() {
		t.Fatalf("wlan0 at ppp0's gateway address with no entry: %+v, hold %v; want ppp0's %v dropped and a hold", n, holdOpen(p), eA)
	}
	held := make(chan error, 2)
	go func() { held <- p.Check(context.Background(), eA, 443, "tcp") }()
	go func() { held <- p.Check(context.Background(), eB, 443, "tcp") }()
	select {
	case err := <-held:
		t.Fatalf("a public destination was decided before wlan0's full read: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	g.ext = func(context.Context) (netip.Addr, error) { return eB, nil }
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-held:
		case <-time.After(5 * time.Second):
			t.Fatal("a held dial did not go ahead after the full read stored")
		}
	}
	if err := p.Check(context.Background(), eB, 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("wlan0's router address is dialable: %v", err)
	}
	if err := p.Check(context.Background(), eA, 443, "tcp"); err != nil {
		t.Fatalf("ppp0's router address on wlan0: %v, want an ordinary public destination", err)
	}
}

// A full read that returns ErrGatewayMoved after a newer quick read learned
// the network is stale: its end network does not replace the newer one.
func TestMovedFullReadDoesNotOverwriteNewerLearn(t *testing.T) {
	pfx := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	g1 := Network{Prefixes: pfx, Gateway: netip.MustParseAddr("192.168.1.1"), External: netip.MustParseAddr("8.8.8.8")}
	g3 := Network{Prefixes: pfx, Gateway: netip.MustParseAddr("192.168.3.1")}
	p := New(Config{
		Source: func() (Network, error) { return g3, ErrGatewayMoved },
		Quick:  func() (Network, error) { return g1, nil },
	})
	p.Learn(g1)
	refreshGapHook = func() { p.quickLearn() }
	t.Cleanup(func() { refreshGapHook = nil })
	if err := p.Refresh(); !errors.Is(err, ErrGatewayMoved) {
		t.Fatalf("refresh: %v", err)
	}
	p.mu.RLock()
	n := p.net
	p.mu.RUnlock()
	if n.Gateway != g1.Gateway || n.External != g1.External || holdOpen(p) {
		t.Fatalf("a stale moved read replaced the newer learn: %+v, hold %v", n, holdOpen(p))
	}
}

// On an IPv6-only uplink the router request to the link-local gateway fails
// at once, so a gateway change holds public destinations only until that
// failed full read, which ends the hold: they are then allowed, not refused.
func TestIPv6OnlyGatewayChangeHoldEndsAtFailedRead(t *testing.T) {
	z := "00000000000000000000000000000000"
	var gw atomic.Value
	gw.Store("fe800000000000000000000000000001")
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("2001:db8::77"), Mask: net.CIDRMask(64, 128)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			switch f {
			case "/proc/net/route":
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"), nil
			case "/proc/net/ipv6_route":
				return []byte(z + " 00 " + z + " 00 " + gw.Load().(string) + " 00000400 00000001 00000000 00000003 eth0\n"), nil
			}
			return nil, syscall.ENOENT
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) { return netip.Addr{}, syscall.EINVAL },
	}
	p := New(Config{Source: s.Read, Quick: s.ReadLocal})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	gw.Store("fe800000000000000000000000000002")
	p.quickLearn()
	if !holdOpen(p) {
		t.Fatal("no hold on the new IPv6 gateway")
	}
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	if holdOpen(p) {
		t.Fatal("the failed full read did not end the hold")
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("2001:4860::8888"), 443, "tcp"); err != nil {
		t.Fatalf("a public destination after the failed read: %v", err)
	}
}
