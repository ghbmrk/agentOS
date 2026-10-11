//go:build linux

package netguard

import (
	"context"

	"golang.org/x/sys/unix"
)

// WatchNetlink sends on the returned channel each time the kernel reports an
// address, route or link change (DEV-2: a new prefix is refused within the
// event, not at the next poll). The channel holds one pending event; further
// changes while it is full coalesce into it. It ends with ctx. Where the
// socket cannot be opened the error is returned and the caller keeps the
// poll, which stays as the backstop either way.
func WatchNetlink(ctx context.Context) (<-chan struct{}, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	groups := uint32(unix.RTMGRP_LINK | unix.RTMGRP_IPV4_IFADDR | unix.RTMGRP_IPV6_IFADDR | unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Groups: groups}); err != nil {
		unix.Close(fd)
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
		for ctx.Err() == nil {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if err == unix.EAGAIN || err == unix.EINTR {
					continue
				}
				if err == unix.ENOBUFS { // overflow: something changed
					notify(out)
					continue
				}
				return
			}
			if netlinkChange(buf[:n]) {
				notify(out)
			}
		}
	}()
	return out, nil
}

func notify(out chan<- struct{}) {
	select {
	case out <- struct{}{}:
	default:
	}
}
