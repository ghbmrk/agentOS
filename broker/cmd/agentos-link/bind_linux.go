package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenLink listens on TCP port on the link interface only: the socket is
// bound to iface with SO_BINDTODEVICE before it binds the port, so a
// connection arriving on any other interface never reaches it (HW-16). The
// interface's input rule (the image's) drops everything else on the link.
func listenLink(iface string, port int) (net.Listener, error) {
	if !ifaceName(iface) || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("agentos-link: %q port %d is not a link interface and port", iface, port)
	}
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(context.Background(), "tcp", net.JoinHostPort("", strconv.Itoa(port)))
}

// boundDevice is the interface ln's socket is bound to.
func boundDevice(ln net.Listener) (string, error) {
	tl, ok := ln.(*net.TCPListener)
	if !ok {
		return "", fmt.Errorf("agentos-link: not a TCP listener")
	}
	rc, err := tl.SyscallConn()
	if err != nil {
		return "", err
	}
	var name string
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		name, gerr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return "", err
	}
	return name, gerr
}
