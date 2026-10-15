//go:build linux

package netguard

// REQ: DEV-2

import (
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
