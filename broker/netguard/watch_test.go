package netguard

// REQ: DEV-2, REV-5

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
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

// Only address, route and link changes are events; the rest of what the
// kernel sends on the groups is not.
func TestNetlinkEventsAreAddressRouteAndLinkChanges(t *testing.T) {
	for _, typ := range []uint16{syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK} {
		if !netlinkChange(nlmsg(typ)) {
			t.Fatalf("type %d is a network change", typ)
		}
	}
	for _, typ := range []uint16{syscall.NLMSG_DONE, syscall.NLMSG_NOOP, syscall.RTM_NEWNEIGH} {
		if netlinkChange(nlmsg(typ)) {
			t.Fatalf("type %d is not a network change", typ)
		}
	}
	if netlinkChange([]byte{1, 2, 3}) {
		t.Fatal("a truncated message is not a change")
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
