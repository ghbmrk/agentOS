//go:build linux

package netguard

// REQ: DEV-2

import (
	"encoding/binary"
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

func nlmsg(typ uint16) []byte {
	b := make([]byte, syscall.NLMSG_HDRLEN+4)
	binary.NativeEndian.PutUint32(b[0:], uint32(len(b)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	return b
}

// neighmsg is one RTM_NEWNEIGH/RTM_DELNEIGH message for dst (an ndmsg of
// family fam on interface 2 in state REACHABLE, then an NDA_LLADDR and an
// NDA_DST attribute).
func neighmsg(typ uint16, fam byte, dst []byte) []byte {
	return neighmsgAt(typ, fam, dst, 0x02, []byte{2, 0, 0, 0, 0, 0x0b})
}

// neighmsgAt is neighmsg with the entry's NUD state and MAC.
func neighmsgAt(typ uint16, fam byte, dst []byte, state uint16, mac []byte) []byte {
	nd := make([]byte, 12)
	nd[0] = fam
	binary.NativeEndian.PutUint32(nd[4:], 2)
	binary.NativeEndian.PutUint16(nd[8:], state)
	attr := func(t uint16, v []byte) []byte {
		a := make([]byte, (4+len(v)+3)&^3)
		binary.NativeEndian.PutUint16(a[0:], uint16(4+len(v)))
		binary.NativeEndian.PutUint16(a[2:], t)
		copy(a[4:], v)
		return a
	}
	body := append(append(nd, attr(2, mac)...), attr(1, dst)...)
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
	gateway := func() (netip.Addr, int32) { asked++; return gw, 2 }
	var w neighWatch
	for _, typ := range []uint16{syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK} {
		if !w.change(nlmsg(typ), gateway) {
			t.Fatalf("type %d is a network change", typ)
		}
	}
	for _, typ := range []uint16{syscall.NLMSG_DONE, syscall.NLMSG_NOOP, syscall.RTM_NEWNEIGH, syscall.RTM_GETNEIGH} {
		if w.change(nlmsg(typ), gateway) {
			t.Fatalf("type %d is not a network change", typ)
		}
	}
	if w.change([]byte{1, 2, 3}, gateway) {
		t.Fatal("a truncated message is not a change")
	}
	if asked != 0 {
		t.Fatalf("the gateway was read %d times for messages with no neighbour address", asked)
	}
	for _, typ := range []uint16{syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH} {
		if !w.change(neighmsg(typ, syscall.AF_INET, []byte{192, 168, 1, 1}), gateway) {
			t.Fatalf("type %d on the gateway's entry is a network change", typ)
		}
		if w.change(neighmsg(typ, syscall.AF_INET, []byte{192, 168, 1, 9}), gateway) {
			t.Fatalf("type %d on another host's entry is not a network change", typ)
		}
	}
	v6 := netip.MustParseAddr("fe80::1").As16()
	if w.change(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET6, v6[:]), gateway) {
		t.Fatal("an IPv6 neighbour entry is not a network change")
	}
	two := append(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 9}), neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 8})...)
	asked = 0
	if w.change(two, gateway) || asked != 1 {
		t.Fatalf("one read of other hosts' entries asked the gateway %d times", asked)
	}
	var fresh neighWatch
	if fresh.change(neighmsg(syscall.RTM_NEWNEIGH, syscall.AF_INET, []byte{192, 168, 1, 1}), func() (netip.Addr, int32) { return netip.Addr{}, 0 }) {
		t.Fatal("a neighbour entry with no default gateway is not a network change")
	}
}

// Only a change to what the gateway's neighbour entry says about the router
// is an event: its MAC, its interface, or whether it is valid (#1578). The
// NUD transitions a full read's own router packet drives (REACHABLE, STALE,
// DELAY, PROBE, all with the same MAC) are not, so the reads do not feed
// each other; a swapped MAC, a failed or deleted entry, and a new gateway
// address still are.
func TestNetlinkGatewayNeighbourCountsOnlyMACOrValidityChanges(t *testing.T) {
	gwA, gwB := []byte{192, 168, 1, 1}, []byte{192, 168, 1, 2}
	cur := netip.AddrFrom4([4]byte(gwA))
	gateway := func() (netip.Addr, int32) { return cur, 0 }
	macA, macB := []byte{2, 0, 0, 0, 0, 0x0a}, []byte{2, 0, 0, 0, 0, 0x0b}
	const reachable, stale, delay, probe, failed, incomplete = 0x02, 0x04, 0x08, 0x10, 0x20, 0x01
	var w neighWatch
	steps := []struct {
		what string
		msg  []byte
		want bool
	}{
		{"first sight of the entry", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macA), true},
		{"REACHABLE to STALE", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, stale, macA), false},
		{"STALE to DELAY", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, delay, macA), false},
		{"DELAY to PROBE", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, probe, macA), false},
		{"PROBE to REACHABLE", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macA), false},
		{"a new router's MAC", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, stale, macB), true},
		{"the same router again", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macB), false},
		{"the entry failed", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, failed, macB), true},
		{"still unresolved", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, incomplete, nil), false},
		{"valid again", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macB), true},
		{"the entry deleted", neighmsgAt(syscall.RTM_DELNEIGH, syscall.AF_INET, gwA, reachable, macB), true},
		{"back with the same MAC", neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macB), true},
	}
	for _, s := range steps {
		if got := w.change(s.msg, gateway); got != s.want {
			t.Fatalf("%s: change %v, want %v", s.what, got, s.want)
		}
	}
	// The same router's MAC on another interface is a change: the gateway
	// key carries the interface (the route's interface unknown here, so no
	// message is filtered).
	other := neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwA, reachable, macB)
	binary.NativeEndian.PutUint32(other[syscall.NLMSG_HDRLEN+4:], 3)
	if !w.change(other, gateway) {
		t.Fatal("the gateway's MAC on another interface is not a change")
	}
	// A new default gateway's entry is a change even with the same MAC.
	cur = netip.AddrFrom4([4]byte(gwB))
	if !w.change(neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwB, reachable, macB), gateway) {
		t.Fatal("the first entry of a new gateway address is not a change")
	}
	// After an overflow the entry is not trusted: the next one counts.
	w.forget()
	if !w.change(neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwB, stale, macB), gateway) {
		t.Fatal("the first entry after a lost-message overflow is not a change")
	}
	// Two transitions in one read: a MAC change anywhere in it counts.
	two := append(neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwB, stale, macA), neighmsgAt(syscall.RTM_NEWNEIGH, syscall.AF_INET, gwB, reachable, macB)...)
	if !w.change(two, gateway) {
		t.Fatal("a read whose first message swaps the MAC and second swaps it back is not a change")
	}
}

// neighmsgOn is neighmsgAt on interface index ifindex.
func neighmsgOn(ifindex uint32, typ uint16, dst []byte, state uint16, mac []byte) []byte {
	b := neighmsgAt(typ, syscall.AF_INET, dst, state, mac)
	binary.NativeEndian.PutUint32(b[syscall.NLMSG_HDRLEN+4:], ifindex)
	return b
}

// The gateway's entry is the one on its route's interface, the entry
// ReadLocal reads (#5094): with one address on two links, the other link's
// entry changes nothing, so the two entries do not alternate keys and churn
// reads. When the route moves to the other link, that link's entry is the
// gateway's, and the same MAC there is a new key: the key carries the
// interface.
func TestNetlinkGatewayNeighbourOnlyOnTheRoutesInterface(t *testing.T) {
	gwA := []byte{192, 168, 1, 1}
	gw := netip.AddrFrom4([4]byte(gwA))
	dev := int32(2)
	gateway := func() (netip.Addr, int32) { return gw, dev }
	mac, macOther := []byte{2, 0, 0, 0, 0, 0x0a}, []byte{2, 0, 0, 0, 0, 0x0b}
	const reachable, stale = 0x02, 0x04
	var w neighWatch
	if !w.change(neighmsgOn(2, syscall.RTM_NEWNEIGH, gwA, reachable, mac), gateway) {
		t.Fatal("the first entry on the route's interface is not a change")
	}
	for i, m := range [][]byte{
		neighmsgOn(3, syscall.RTM_NEWNEIGH, gwA, reachable, macOther),
		neighmsgOn(2, syscall.RTM_NEWNEIGH, gwA, stale, mac),
		neighmsgOn(3, syscall.RTM_NEWNEIGH, gwA, stale, macOther),
		neighmsgOn(3, syscall.RTM_DELNEIGH, gwA, stale, macOther),
		neighmsgOn(2, syscall.RTM_NEWNEIGH, gwA, reachable, mac),
	} {
		if w.change(m, gateway) {
			t.Fatalf("message %d: the gateway address's entry on another link, or a NUD step on the route's, is a change", i)
		}
	}
	dev = 3 // the route moved to the other link
	if !w.change(neighmsgOn(3, syscall.RTM_NEWNEIGH, gwA, reachable, mac), gateway) {
		t.Fatal("the same MAC on the route's new interface is not a change")
	}
	if w.change(neighmsgOn(2, syscall.RTM_DELNEIGH, gwA, reachable, mac), gateway) {
		t.Fatal("the old link's entry is a change after the route moved off it")
	}
}
