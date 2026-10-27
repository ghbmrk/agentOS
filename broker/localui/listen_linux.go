package localui

import (
	"context"
	"net"
	"strconv"
	"syscall"
)

// Listen opens the page's listener on port 1 only (CH-9, D-178): bound to
// every address of p's interface and, with SO_BINDTODEVICE, to that
// interface alone, so a packet arriving on any other interface (port 2,
// the edge's cable, a USB tether) is never accepted, whatever the routing
// table says (HW-15). The core's address there comes from DHCP and may
// change, so no address is bound. The server also checks every request's
// source (homeSource) and the inbound table admits the page's ports only
// from private sources (netguard.InboundRules).
func Listen(ctx context.Context, p Page, port int) (net.Listener, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return listenOn(ctx, p.Iface, net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
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
