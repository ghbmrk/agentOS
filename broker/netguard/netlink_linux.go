//go:build linux

package netguard

import (
	"context"
	"log"
	"net/netip"

	"golang.org/x/sys/unix"
)

// WatchNetlink sends on the returned channel each time the kernel reports an
// address, route or link change (DEV-2: a new prefix is refused within the
// event, not at the next poll), or a change to the default gateway's
// neighbour entry's MAC or validity (a swapped router's new MAC is seen
// within the event; neighWatch). The channel holds one pending event; further
// changes while it is full coalesce into it. It ends with ctx. Where the
// socket cannot be opened the error is returned and the caller keeps the
// poll, which stays as the backstop either way.
func WatchNetlink(ctx context.Context) (<-chan struct{}, error) {
	fd, err := openNetlink()
	if err != nil {
		return nil, err
	}
	// A receive timeout lets the loop notice ctx without another thread.
	tv := unix.NsecToTimeval(500e6)
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	out := make(chan struct{}, 1)
	go func() {
		defer unix.Close(fd)
		defer close(out)
		buf := make([]byte, 1<<16)
		var nw neighWatch
		for ctx.Err() == nil {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			changed, end := nw.onRecv(buf, n, err, routeGateway)
			if end {
				if ctx.Err() == nil {
					log.Printf("netguard: netlink feed ended, polling only: %v", err)
				}
				return
			}
			if changed {
				notify(out)
			}
		}
	}()
	return out, nil
}

// onRecv applies one receive (n bytes of buf, or err) to w. It reports
// whether the receive is a network change, and whether the feed ends: on an
// error other than the receive timeout, an interrupt or an overflow. An
// overflow (ENOBUFS) lost messages, so it is a change, and w forgets the
// gateway's entry, so the entry that next arrives is one too: a swap A to B
// lost in the overflow, then back to A, is still seen (#5094).
func (w *neighWatch) onRecv(buf []byte, n int, err error, gateway func() (netip.Addr, int32)) (changed, end bool) {
	switch err {
	case nil:
		return w.change(buf[:n], gateway), false
	case unix.EAGAIN, unix.EINTR:
		return false, false
	case unix.ENOBUFS:
		w.forget()
		return true, false
	}
	return false, true
}

// openNetlink opens the rtnetlink socket WatchNetlink reads, bound to the
// address, route, link and neighbour groups.
func openNetlink() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return -1, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE | unix.RTMGRP_NEIGH)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func notify(out chan<- struct{}) {
	select {
	case out <- struct{}{}:
	default:
	}
}
