package netguard

import (
	"encoding/binary"
	"net/netip"
	"os"
	"syscall"
)

// netlinkChange reports whether a netlink read holds an address, route or
// link change, or a change to the IPv4 default gateway's neighbour entry
// (a router swapped behind the same address with no link event at the box;
// #1536). gateway is asked at most once, and only for a neighbour message,
// so other hosts' entries cause no churn. A truncated or unparsable read
// holds none.
func netlinkChange(b []byte, gateway func() netip.Addr) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	var gw netip.Addr
	asked := false
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			return true
		case syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH:
			a, ok := neighbourDst(m.Data)
			if !ok {
				continue
			}
			if !asked {
				gw, asked = gateway(), true
			}
			if gw.IsValid() && a == gw {
				return true
			}
		}
	}
	return false
}

// neighbourDst returns an IPv4 neighbour message's address (struct ndmsg,
// then its NDA_DST attribute).
func neighbourDst(d []byte) (netip.Addr, bool) {
	const ndmsgLen, ndaDst = 12, 1
	if len(d) < ndmsgLen || d[0] != syscall.AF_INET {
		return netip.Addr{}, false
	}
	for d = d[ndmsgLen:]; len(d) >= 4; {
		l := int(binary.NativeEndian.Uint16(d[0:]))
		if l < 4 || l > len(d) {
			return netip.Addr{}, false
		}
		if binary.NativeEndian.Uint16(d[2:]) == ndaDst && l == 8 {
			return netip.AddrFrom4([4]byte(d[4:8])), true
		}
		l = (l + 3) &^ 3
		if l > len(d) {
			break
		}
		d = d[l:]
	}
	return netip.Addr{}, false
}

// routeGateway is the IPv4 default gateway now, from /proc/net/route.
func routeGateway() netip.Addr {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}
	}
	return Gateway4(string(b))
}
