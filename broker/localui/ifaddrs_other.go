//go:build !(linux && (amd64 || arm64))

package localui

import (
	"net"
	"net/netip"
)

// boxAddrs lists the box's addresses (the page runs only on Linux; see
// ifaddrs_linux.go).
func boxAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(as))
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out, nil
}
