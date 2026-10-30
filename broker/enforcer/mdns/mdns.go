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
	"sync"
	"syscall"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
)

var ErrRelay = errors.New("mdns: relay refused")

// Group is mDNS's IPv4 group and port (RFC 6762).
var Group = netip.AddrPortFrom(netip.MustParseAddr(nft.MDNSGroup), nft.MDNSPort)

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

// Rate limits per interface: a device that floods gets its packets
// dropped, not multiplied onto a network.
const (
	burst  = 40
	perSec = 20
)

// maxPacket is the largest packet relayed; a larger one is dropped, never
// truncated (RFC 6762 §17 allows 9000 bytes).
const maxPacket = 9000

// ipMulticastAll is Linux's IP_MULTICAST_ALL, which the syscall package
// does not name. Off, a socket hears only the groups it joined itself.
const ipMulticastAll = 49

// Serve relays along plan until ctx ends. Each interface gets one socket,
// bound to that interface (SO_BINDTODEVICE) and to the group, so a packet
// is heard only on the interface it came in on; the relay hears none of
// its own sends.
func Serve(ctx context.Context, plan Plan) error {
	ifaces := plan.Ifaces()
	if len(ifaces) == 0 {
		<-ctx.Done()
		return nil
	}
	conns := map[string]*net.UDPConn{}
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for _, name := range ifaces {
		c, err := listen(name)
		if err != nil {
			return err
		}
		conns[name] = c
	}
	var wg sync.WaitGroup
	for name, c := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			relay(plan, name, c, conns)
		}()
	}
	<-ctx.Done()
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	return nil
}

func relay(plan Plan, name string, c *net.UDPConn, conns map[string]*net.UDPConn) {
	buf := make([]byte, maxPacket+1)
	tokens, last := float64(burst), time.Now()
	dst := net.UDPAddrFromAddrPort(Group)
	for {
		n, from, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		now := time.Now()
		tokens = min(burst, tokens+now.Sub(last).Seconds()*perSec)
		last = now
		if n > maxPacket || tokens < 1 {
			continue
		}
		outs := plan.Route(name, from.Port(), buf[:n])
		if len(outs) == 0 {
			continue
		}
		tokens--
		for _, o := range outs {
			conns[o].WriteToUDP(buf[:n], dst)
		}
	}
}

// listen opens iface's socket: bound to the device and the group's port,
// a member of the group on that interface only, sending there with TTL 255
// and without looping its sends back.
func listen(name string) (*net.UDPConn, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRelay, err)
	}
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		err := rc.Control(func(fd uintptr) {
			s := int(fd)
			mreq := &syscall.IPMreqn{Multiaddr: Group.Addr().As4(), Ifindex: int32(ifi.Index)}
			serr = errors.Join(
				syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1),
				syscall.BindToDevice(s, name),
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, ipMulticastAll, 0),
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_LOOP, 0),
				syscall.SetsockoptInt(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, 255),
				syscall.SetsockoptIPMreqn(s, syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, mreq),
				syscall.SetsockoptIPMreqn(s, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP, mreq),
			)
		})
		return errors.Join(err, serr)
	}}
	pc, err := lc.ListenPacket(context.Background(), "udp4", Group.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrRelay, name, err)
	}
	return pc.(*net.UDPConn), nil
}
