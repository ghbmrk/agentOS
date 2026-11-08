//go:build linux

package netguard

// REQ: DEV-2

import (
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The socket WatchNetlink reads is bound, as the kernel reports it, to the
// address, route and link groups and to the neighbour group, so a router
// swapped behind the gateway's address is an event (#1536). Binding needs
// no privilege (rtnetlink allows any user to receive).
func TestNetlinkSocketSubscribesToNeighbourEvents(t *testing.T) {
	fd, err := openNetlink()
	if err != nil {
		t.Fatalf("no rtnetlink socket: %v", err)
	}
	defer unix.Close(fd)
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	nl, ok := sa.(*unix.SockaddrNetlink)
	if !ok {
		t.Fatalf("socket name %T", sa)
	}
	for _, g := range []struct {
		name string
		bit  uint32
	}{
		{"RTMGRP_LINK", unix.RTMGRP_LINK},
		{"RTMGRP_IPV4_IFADDR", unix.RTMGRP_IPV4_IFADDR},
		{"RTMGRP_IPV6_IFADDR", unix.RTMGRP_IPV6_IFADDR},
		{"RTMGRP_IPV4_ROUTE", unix.RTMGRP_IPV4_ROUTE},
		{"RTMGRP_IPV6_ROUTE", unix.RTMGRP_IPV6_ROUTE},
		{"RTMGRP_NEIGH", unix.RTMGRP_NEIGH},
	} {
		if nl.Groups&g.bit == 0 {
			t.Errorf("the socket is not subscribed to %s (groups %#x)", g.name, nl.Groups)
		}
	}
}

// One receive in WatchNetlink's loop (#5094): a read is a change only as
// neighWatch says; the receive timeout and an interrupt are none; an
// overflow is a change and forgets the gateway's entry, so the entry that
// next arrives counts even when it equals the one last seen (a swap A to B
// lost in the overflow, then back to A); any other error ends the feed.
func TestNetlinkReceiveOverflowForgetsTheGatewayEntry(t *testing.T) {
	gwA := []byte{192, 168, 1, 1}
	gateway := func() (netip.Addr, int32) { return netip.AddrFrom4([4]byte(gwA)), 2 }
	macA := []byte{2, 0, 0, 0, 0, 0x0a}
	buf := make([]byte, 1<<10)
	recv := func(w *neighWatch, msg []byte, err error) (bool, bool) {
		n := copy(buf, msg)
		if err != nil {
			n = -1
		}
		return w.onRecv(buf, n, err, gateway)
	}
	a := neighmsgOn(2, syscall.RTM_NEWNEIGH, gwA, 0x02, macA)
	var w neighWatch
	if c, end := recv(&w, a, nil); !c || end {
		t.Fatalf("router A's entry: change %v, end %v", c, end)
	}
	if c, end := recv(&w, a, nil); c || end {
		t.Fatalf("router A's entry again: change %v, end %v", c, end)
	}
	for _, e := range []error{unix.EAGAIN, unix.EINTR} {
		if c, end := recv(&w, nil, e); c || end {
			t.Fatalf("%v: change %v, end %v", e, c, end)
		}
	}
	if c, end := recv(&w, nil, unix.ENOBUFS); !c || end {
		t.Fatalf("an overflow: change %v, end %v", c, end)
	}
	if c, end := recv(&w, a, nil); !c || end {
		t.Fatalf("router A's entry after an overflow: change %v, end %v; the overflow may have hidden A to B and back", c, end)
	}
	if c, end := recv(&w, nil, unix.EBADF); c || !end {
		t.Fatalf("a socket error: change %v, end %v", c, end)
	}
}

// routeGateway reads the host's default gateway as Gateway4 does, with its
// route's interface index; an interface that cannot be looked up is 0.
func TestRouteGatewayCarriesTheRoutesInterface(t *testing.T) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		t.Skip("no /proc/net/route")
	}
	want, dev := gateway4(string(b))
	gw, idx := routeGateway()
	if gw != want {
		t.Fatalf("gateway %v, want %v", gw, want)
	}
	if want.IsValid() {
		ifi, err := net.InterfaceByName(dev)
		if err != nil || idx != int32(ifi.Index) {
			t.Fatalf("route interface %q: index %d, want %v (%v)", dev, idx, ifi, err)
		}
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skip("no lo")
	}
	if got := ifIndex("lo"); got != int32(lo.Index) || got == 0 {
		t.Fatalf("ifIndex(lo) = %d, want %d", got, lo.Index)
	}
	if got := ifIndex("agentos-none0"); got != 0 {
		t.Fatalf("ifIndex of a missing interface = %d, want 0", got)
	}
}
