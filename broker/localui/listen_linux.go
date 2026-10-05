package localui

import (
	"context"
	"net"
	"strconv"
	"syscall"
)

// Listen opens the local UI's listener on the access point only (CH-9):
// bound to the box's access point address and, with SO_BINDTODEVICE, to the
// access point interface, so a packet for that address arriving on any
// other interface (the home network, an agent machine's link) is never
// accepted, whatever the routing table says. The server also checks every
// request's source (Server.ServeHTTP) and the firewall drops it first
// (NftRules).
func Listen(ctx context.Context, c APConfig, port int) (net.Listener, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return listenOn(ctx, c.Iface, net.JoinHostPort(c.Addr.Addr().String(), strconv.Itoa(port)))
}

// listenOn listens on addr, bound to the interface iface.
func listenOn(ctx context.Context, iface, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return serr
	}}
	return lc.Listen(ctx, "tcp4", addr)
}
