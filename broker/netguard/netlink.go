//go:build linux

package netguard

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
)

// neighWatch remembers the IPv4 default gateway's neighbour entry as the
// kernel last reported it: its interface and MAC while the entry is valid,
// else nothing. Only a change to that is a network change (#1578): a NUD
// transition that keeps the MAC (REACHABLE, STALE, DELAY, PROBE) changes no
// gateway key, and counting it made each full read's router packet start
// the next one.
type neighWatch struct {
	gw   netip.Addr
	seen bool
	key  string
}

// change reports whether a netlink read holds an address, route or link
// change, or a change to the IPv4 default gateway's neighbour entry (a
// router swapped behind the same address with no link event at the box, or
// its entry flushed; #1536). gateway returns the default gateway and its
// route's interface index, 0 where that is unknown; it is asked at most
// once, and only for a neighbour message, so other hosts' entries cause no
// churn. The gateway's entry is the one on the route's interface, the one
// ReadLocal reads: the same address on another link is another host, so one
// address on two links does not alternate keys. A truncated or unparsable
// read holds none.
func (w *neighWatch) change(b []byte, gateway func() (netip.Addr, int32)) bool {
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return false
	}
	var gw netip.Addr
	var dev int32
	asked, changed := false, false
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.RTM_NEWADDR, syscall.RTM_DELADDR, syscall.RTM_NEWROUTE, syscall.RTM_DELROUTE, syscall.RTM_NEWLINK, syscall.RTM_DELLINK:
			return true
		case syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH:
			nb, ok := parseNeighbour(m.Data)
			if !ok {
				continue
			}
			if !asked {
				gw, dev = gateway()
				asked = true
			}
			if !gw.IsValid() || nb.dst != gw || dev != 0 && nb.ifindex != dev {
				continue
			}
			key := ""
			if m.Header.Type == syscall.RTM_NEWNEIGH && nb.state&nudValid != 0 {
				key = fmt.Sprintf("%d %x", nb.ifindex, nb.lladdr)
			}
			if !w.seen || w.gw != gw || w.key != key {
				changed = true
			}
			w.gw, w.seen, w.key = gw, true, key
		}
	}
	return changed
}

// forget drops what w remembers, so the next gateway entry counts as a
// change: after a netlink overflow, messages were lost.
func (w *neighWatch) forget() { *w = neighWatch{} }

// nudValid is the kernel's NUD_VALID: the states in which /proc/net/arp
// marks the entry complete (ATF_COM), which is when NeighbourMAC reads it.
const nudValid = 0x02 | 0x04 | 0x08 | 0x10 | 0x40 | 0x80 // REACHABLE STALE DELAY PROBE NOARP PERMANENT

type neighbour struct {
	dst     netip.Addr
	ifindex int32
	state   uint16
	lladdr  []byte
}

// parseNeighbour reads an IPv4 neighbour message (struct ndmsg, then its
// NDA_DST and NDA_LLADDR attributes). It needs NDA_DST.
func parseNeighbour(d []byte) (neighbour, bool) {
	const ndmsgLen, ndaDst, ndaLLAddr = 12, 1, 2
	var nb neighbour
	if len(d) < ndmsgLen || d[0] != syscall.AF_INET {
		return nb, false
	}
	nb.ifindex = int32(binary.NativeEndian.Uint32(d[4:]))
	nb.state = binary.NativeEndian.Uint16(d[8:])
	for d = d[ndmsgLen:]; len(d) >= 4; {
		l := int(binary.NativeEndian.Uint16(d[0:]))
		if l < 4 || l > len(d) {
			return neighbour{}, false
		}
		switch binary.NativeEndian.Uint16(d[2:]) {
		case ndaDst:
			if l == 8 {
				nb.dst = netip.AddrFrom4([4]byte(d[4:8]))
			}
		case ndaLLAddr:
			nb.lladdr = append([]byte(nil), d[4:l]...)
		}
		l = (l + 3) &^ 3
		if l > len(d) {
			break
		}
		d = d[l:]
	}
	return nb, nb.dst.IsValid()
}

// routeGateway is the IPv4 default gateway now, from /proc/net/route, and
// its route's interface index (ifIndex).
func routeGateway() (netip.Addr, int32) {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, 0
	}
	gw, dev := gateway4(string(b))
	return gw, ifIndex(dev)
}

// ifIndex is dev's interface index, or 0 where it cannot be looked up (the
// interface just went): 0 filters no neighbour message, so a failed lookup
// fails toward more reads, never fewer.
func ifIndex(dev string) int32 {
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		return 0
	}
	return int32(ifi.Index)
}
