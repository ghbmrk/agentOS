// Package mdns is the enforcer's mDNS pair relay (SPEC NET-3 Casting;
// briefs/ENF.md slice f, decision 5). There is no general reflector: a
// device's mDNS records are passed only across a pair the owner signed,
// so an infected device cannot advertise onto the Owner network.
//
// The relay works on the same paths the ruleset opens (nft.Paths). On a
// path from a person's network (Owner or Household, one network each) to a
// device, queries pass from the network to the device and the device's
// responses pass back; nothing else does, so a device's own queries and
// the network's own announcements stay where they are. Between two paired
// devices, both pass both ways. A packet's side is the interface it came
// in on, never its addresses or its records.
//
// It is enforcer code: it imports the standard library and the enforcer's
// nft package only (broker/daemon/arc2_test.go). Its assumptions are in
// ASSUMPTIONS.md.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
)

var ErrRelay = errors.New("mdns: relay refused")

// Group and Group6 are mDNS's IPv4 and IPv6 groups and port (RFC 6762).
var (
	Group  = netip.AddrPortFrom(netip.MustParseAddr(nft.MDNSGroup), nft.MDNSPort)
	Group6 = netip.AddrPortFrom(netip.MustParseAddr(nft.MDNSGroup6), nft.MDNSPort)
)

// Plan is where each kind of packet goes from each interface.
type Plan struct {
	queries, responses map[string][]string
}

// NewPlan is the plan for paths.
func NewPlan(paths []nft.Path) Plan {
	p := Plan{queries: map[string][]string{}, responses: map[string][]string{}}
	add := func(m map[string][]string, from, to string) {
		if !slices.Contains(m[from], to) {
			m[from] = append(m[from], to)
			slices.Sort(m[from])
		}
	}
	for _, path := range paths {
		add(p.queries, path.From, path.To)
		add(p.responses, path.To, path.From)
		if path.Both {
			add(p.queries, path.To, path.From)
			add(p.responses, path.From, path.To)
		}
	}
	return p
}

// Ifaces is every interface the plan listens on or sends to.
func (p Plan) Ifaces() []string {
	var out []string
	for _, m := range []map[string][]string{p.queries, p.responses} {
		for from, tos := range m {
			for _, i := range append([]string{from}, tos...) {
				if !slices.Contains(out, i) {
					out = append(out, i)
				}
			}
		}
	}
	slices.Sort(out)
	return out
}

// Route is the interfaces a packet that came in on iface goes out on:
// none for a packet that is not a well-formed mDNS message from port 5353,
// or that no pair carries.
func (p Plan) Route(iface string, srcPort uint16, pkt []byte) []string {
	// A DNS header is 12 bytes; mDNS uses opcode 0 (QUERY) only, and its
	// responses come from port 5353 (RFC 6762 §6, §18.3). Legacy one-shot
	// queries from other ports want a unicast answer the relay could not
	// return, so they are not passed either.
	if len(pkt) < 12 || srcPort != nft.MDNSPort || pkt[2]&0x78 != 0 {
		return nil
	}
	if pkt[2]&0x80 != 0 {
		return p.responses[iface]
	}
	return p.queries[iface]
}

// Rate limits per interface, over both families: a device that floods
// gets its packets dropped, not multiplied onto a network.
const (
	burst  = 40
	perSec = 20
)

// maxPacket is the largest packet relayed; a larger one is dropped, never
// truncated (RFC 6762 §17 allows 9000 bytes).
const maxPacket = 9000

// Linux's IP_MULTICAST_ALL and IPV6_MULTICAST_ALL, which the syscall
// package does not name. Off, a socket hears only the groups it joined
// itself.
const (
	ipMulticastAll   = 49
	ipv6MulticastAll = 29
)

// bucket is one interface's rate limit.
type bucket struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*perSec)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Serve relays along plan until ctx ends. Each interface gets one socket
// per family, bound to that interface (SO_BINDTODEVICE) and to the group,
// so a packet is heard only on the interface it came in on; the relay
// hears none of its own sends. A packet leaves on the other interfaces in
// its own family, as Filter rebuilds it.
func Serve(ctx context.Context, plan Plan) error {
	ifaces := plan.Ifaces()
	if len(ifaces) == 0 {
		<-ctx.Done()
		return nil
	}
	type side struct {
		name string
		v6   bool
	}
	conns := map[side]*net.UDPConn{}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	families := []bool{false}
	if hasIPv6() {
		families = append(families, true)
	}
	buckets := map[string]*bucket{}
	for _, name := range ifaces {
		for _, v6 := range families {
			c, err := listen(name, v6)
			if err != nil {
				return err
			}
			conns[side{name, v6}] = c
		}
		buckets[name] = &bucket{tokens: burst, last: time.Now()}
	}
	f := NewFilter()
	var wg sync.WaitGroup
	for s, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dst := net.UDPAddrFromAddrPort(Group)
			if s.v6 {
				dst = &net.UDPAddr{IP: Group6.Addr().AsSlice(), Port: int(Group6.Port())}
			}
			relay(c, func(pkt []byte, port uint16, now time.Time) {
				outs := plan.Route(s.name, port, pkt)
				m, ok := parse(pkt)
				if !ok {
					return
				}
				f.Hear(s.name, m, now)
				if len(outs) == 0 || !buckets[s.name].take(now) {
					return
				}
				out := f.Pass(s.name, prefixes(s.name), m, now)
				if out == nil || len(out) > maxPacket {
					return
				}
				for _, o := range outs {
					if s.v6 {
						dst.Zone = o
					}
					conns[side{o, s.v6}].WriteToUDP(out, dst)
				}
			})
		}()
	}
	<-ctx.Done()
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	return nil
}

// hasIPv6: the kernel has IPv6. Without it there is no IPv6 mDNS to
// relay, so the relay runs on IPv4 alone.
func hasIPv6() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err == nil {
		syscall.Close(fd)
	}
	return !errors.Is(err, syscall.EAFNOSUPPORT)
}

// relay reads c until it closes, handing each packet no larger than
// maxPacket to handle.
func relay(c *net.UDPConn, handle func(pkt []byte, port uint16, now time.Time)) {
	buf := make([]byte, maxPacket+1)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n <= maxPacket {
			handle(buf[:n], from.Port(), time.Now())
		}
	}
}

// prefixes is the enforcer's addresses on iface, each with its prefix;
// none if they cannot be read, so nothing is the sender's own.
func prefixes(iface string) []netip.Prefix {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			ip, _ := netip.AddrFromSlice(ipn.IP)
			ones, _ := ipn.Mask.Size()
			out = append(out, netip.PrefixFrom(ip.Unmap(), ones))
		}
	}
	return out
}

// listen opens iface's socket for one family: bound to the device and the
// group's port, a member of the group on that interface only, sending
// there with TTL (hop limit) 255 and without looping its sends back.
func listen(name string, v6 bool) (*net.UDPConn, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRelay, err)
	}
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			s := int(fd)
			serr = errors.Join(
				syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1),
				syscall.BindToDevice(s, name))
			if v6 {
				mreq := &syscall.IPv6Mreq{Multiaddr: Group6.Addr().As16(), Interface: uint32(ifi.Index)}
				serr = errors.Join(serr,
					syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, ipv6MulticastAll, 0),
					syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_LOOP, 0),
					syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_HOPS, 255),
					syscall.SetsockoptInt(s, syscall.IPPROTO_IPV6, syscall.IPV6_MULTICAST_IF, ifi.Index),
					syscall.SetsockoptIPv6Mreq(s, syscall.IPPROTO_IPV6, syscall.IPV6_JOIN_GROUP, mreq))
				return
			}
			mreq := &syscall.IPMreqn{Multiaddr: Group.Addr().As4(), Ifindex: int32(ifi.Index)}
			serr = errors.Join(serr,
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipMulticastAll, 0),
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0),
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255),
				syscall.SetsockoptIPMreqn(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, mreq),
				syscall.SetsockoptIPMreqn(s, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq))
		})
		return errors.Join(err, serr)
	}}
	network, addr := "udp4", Group.String()
	if v6 {
		network, addr = "udp6", net.JoinHostPort(Group6.Addr().String()+"%"+name, strconv.Itoa(int(Group6.Port())))
	}
	pc, err := lc.ListenPacket(context.Background(), network, addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRelay, name, err)
	}
	return pc.(*net.UDPConn), nil
}
