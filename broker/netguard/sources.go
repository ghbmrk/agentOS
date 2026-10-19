package netguard

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sources are where the home network is learned from (DEV-2). The zero
// value of each field is the Linux source; tests replace them.
type Sources struct {
	// Addrs lists the interface addresses (netlink, through the net
	// package). Nil means net.InterfaceAddrs.
	Addrs func() ([]net.Addr, error)
	// ReadFile reads a file. Nil means os.ReadFile.
	ReadFile func(string) ([]byte, error)
	// External asks the gateway for the router's external address. Nil
	// means ExternalAddr (NAT-PMP).
	External func(ctx context.Context, gateway netip.Addr) (netip.Addr, error)

	mu   sync.Mutex
	exts []gatewayExternal // most recently read first, at most maxGatewayExternals
}

// gatewayKey tells gateways apart: the address, the default route's
// interface, and the MAC in the neighbour table (empty where none is known,
// or on a link with no neighbour table such as ppp or tun). Routers behind
// one address on different networks differ in MAC or interface (#1536).
type gatewayKey struct {
	gw  netip.Addr
	dev string
	mac string
}

// keyOf returns n's gateway key.
func keyOf(n Network) gatewayKey {
	return gatewayKey{n.Gateway, n.GatewayDev, n.GatewayMAC}
}

// gatewayExternal is the router's external address last read on a gateway.
type gatewayExternal struct {
	key gatewayKey
	ext netip.Addr
}

// maxGatewayExternals bounds how many gateways' external addresses Sources
// keeps. A forgotten gateway is read again like a new one.
const maxGatewayExternals = 8

// externalReadTimeout bounds one NAT-PMP request; a full read makes at most
// two, and externalHold in policy.go must stay past them.
const externalReadTimeout = 3 * time.Second

// ErrGatewayMoved is returned by Read when the gateway changed during each
// of its two router reads, so no answer is from the gateway it ends on. The
// network returned with it is the end one, without that router's answer.
var ErrGatewayMoved = errors.New("netguard: the gateway changed during the router read")

// externalLocked returns the external address last read on gateway k; s.mu
// is held.
func (s *Sources) externalLocked(k gatewayKey) netip.Addr {
	for _, e := range s.exts {
		if e.key == k {
			return e.ext
		}
	}
	return netip.Addr{}
}

// rememberLocked records ext as gateway k's and makes it the most recent,
// dropping the least recently read gateway past the bound; s.mu is held.
func (s *Sources) rememberLocked(k gatewayKey, ext netip.Addr) {
	out := []gatewayExternal{{k, ext}}
	for _, e := range s.exts {
		if e.key != k && len(out) < maxGatewayExternals {
			out = append(out, e)
		}
	}
	s.exts = out
}

// resolvConfs are read in order; the first with a usable nameserver wins.
// The systemd-resolved file lists the real servers its stub (127.0.0.53)
// hides. DHCP and RA clients write whichever file the host uses.
var resolvConfs = []string{"/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"}

// Read learns the network now: prefixes from the interface addresses, the
// default gateway from the kernel routing tables, the resolver from the
// DHCP- or RA-written resolv.conf, and the router's external address from
// NAT-PMP (when the gateway does not answer, the last address read on that
// gateway, else none). A read that finds no non-loopback interface
// prefix fails, so the last learned set stays.
//
// The host is read again after each router request (answered or timed
// out), and the network at that point is the one returned. The answer is
// kept only if the gateway is the one asked: the same address, interface
// and MAC. A MAC unknown at the start and known after the wait counts as a
// move too, since the router that answered cannot be told from another
// behind the same address (#1725). After a move during the wait, the answer
// may be another router's, so it is dropped and the gateway the read ended
// on is asked in its place; a second move returns ErrGatewayMoved (#1536).
func (s *Sources) Read() (Network, error) {
	n, err := s.ReadLocal()
	if err != nil || !n.Gateway.IsValid() {
		return n, err
	}
	ext := s.External
	if ext == nil {
		ext = ExternalAddr
	}
	for try := 0; ; try++ {
		ctx, cancel := context.WithTimeout(context.Background(), externalReadTimeout)
		a, err := ext(ctx, n.Gateway)
		cancel()
		m, merr := s.ReadLocal()
		if merr != nil || !m.Gateway.IsValid() {
			return m, merr
		}
		if m.Gateway != n.Gateway || m.GatewayDev != n.GatewayDev || m.GatewayMAC != n.GatewayMAC {
			if try == 0 {
				n = m
				continue
			}
			return m, ErrGatewayMoved
		}
		k := keyOf(m)
		s.mu.Lock()
		if err == nil && a.IsValid() {
			s.rememberLocked(k, a.Unmap())
		} else if e := s.externalLocked(k); e.IsValid() {
			s.rememberLocked(k, e)
		}
		m.External = s.externalLocked(k)
		s.mu.Unlock()
		return m, nil
	}
}

// ReadLocal is Read without the router: interface prefixes, gateway and
// resolver from the host alone, never blocking on the network. The gateway's
// interface is its default route's, and its MAC is its complete entry in the
// neighbour table on that interface (IPv4 only: there is no IPv6 neighbour
// table file), else empty. The external address is the last one read on
// this gateway (address, interface and MAC), else empty, so a return to a known gateway refuses that router's
// address at once, and another router behind the same address gets none. A
// change event applies it before the full Read completes.
func (s *Sources) ReadLocal() (Network, error) {
	addrs := s.Addrs
	if addrs == nil {
		addrs = net.InterfaceAddrs
	}
	read := s.ReadFile
	if read == nil {
		read = os.ReadFile
	}
	as, err := addrs()
	if err != nil {
		return Network{}, err
	}
	var n Network
	n.Prefixes = Prefixes(as)
	if len(n.Prefixes) == 0 {
		return Network{}, errors.New("netguard: no non-loopback interface address")
	}
	if b, err := read("/proc/net/route"); err == nil {
		n.Gateway, n.GatewayDev = gateway4(string(b))
		if n.Gateway.IsValid() {
			if b, err := read("/proc/net/arp"); err == nil {
				n.GatewayMAC = NeighbourMAC(string(b), n.Gateway, n.GatewayDev)
			}
		}
	}
	if !n.Gateway.IsValid() {
		if b, err := read("/proc/net/ipv6_route"); err == nil {
			n.Gateway, n.GatewayDev = gateway6(string(b))
		}
	}
	for _, f := range resolvConfs {
		if b, err := read(f); err == nil {
			if r := Nameserver(string(b)); r.IsValid() {
				n.Resolver = r
				break
			}
		}
	}
	s.mu.Lock()
	if n.Gateway.IsValid() {
		n.External = s.externalLocked(keyOf(n))
	}
	s.mu.Unlock()
	return n, nil
}

// Prefixes returns the masked prefix of each interface address that is not
// loopback: the uplink and access-point prefixes.
func Prefixes(as []net.Addr) []netip.Prefix {
	var out []netip.Prefix
	for _, a := range as {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		ones, bits := ipn.Mask.Size()
		if bits == 0 || ip.IsLoopback() {
			continue
		}
		if bits == 128 && ip.Is4() { // an IPv4-in-IPv6 length for an IPv4 address
			if ones < 96 { // wider than the mapped range: kept as IPv6, which Learn widens to all of IPv4
				out = append(out, netip.PrefixFrom(netip.AddrFrom16(ip.As16()), ones).Masked())
				continue
			}
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones).Masked())
	}
	return out
}

// Gateway4 returns the default gateway in /proc/net/route text: the
// lowest-metric row whose destination and mask are zero.
func Gateway4(table string) netip.Addr {
	gw, _ := gateway4(table)
	return gw
}

// gateway4 is Gateway4 with the route's interface.
func gateway4(table string) (netip.Addr, string) {
	var best netip.Addr
	var dev string
	bestMetric := -1
	sc := bufio.NewScanner(strings.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// Iface Destination Gateway Flags RefCnt Use Metric Mask
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&0x3 != 0x3 { // RTF_UP and RTF_GATEWAY
			continue
		}
		gw, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || gw == 0 {
			continue
		}
		m, err := strconv.Atoi(f[6])
		if err != nil {
			continue
		}
		if bestMetric < 0 || m < bestMetric {
			var b [4]byte
			binary.LittleEndian.PutUint32(b[:], uint32(gw))
			best, bestMetric, dev = netip.AddrFrom4(b), m, f[0]
		}
	}
	return best, dev
}

// NeighbourMAC returns ip's MAC in /proc/net/arp text: a complete entry
// (ATF_COM) on interface dev, in canonical lower case, else empty.
func NeighbourMAC(table string, ip netip.Addr, dev string) string {
	sc := bufio.NewScanner(strings.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// IP address, HW type, Flags, HW address, Mask, Device
		if len(f) < 6 || f[5] != dev {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || a != ip {
			continue
		}
		flags, err := strconv.ParseUint(strings.TrimPrefix(f[2], "0x"), 16, 32)
		if err != nil || flags&0x2 == 0 {
			continue
		}
		hw, err := net.ParseMAC(f[3])
		if err != nil || strings.Trim(string(hw), "\x00") == "" {
			continue
		}
		return hw.String()
	}
	return ""
}

// Gateway6 returns the default gateway in /proc/net/ipv6_route text: the
// lowest-metric row whose destination prefix length is zero.
func Gateway6(table string) netip.Addr {
	gw, _ := gateway6(table)
	return gw
}

// gateway6 is Gateway6 with the route's interface.
func gateway6(table string) (netip.Addr, string) {
	var best netip.Addr
	var dev string
	bestMetric := int64(-1)
	sc := bufio.NewScanner(strings.NewReader(table))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// dest destlen src srclen nexthop metric refcnt use flags iface
		if len(f) < 9 || f[1] != "00" || f[0] != strings.Repeat("0", 32) {
			continue
		}
		flags, err := strconv.ParseUint(f[8], 16, 32)
		if err != nil || flags&0x3 != 0x3 {
			continue
		}
		raw, err := hex.DecodeString(f[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		a := netip.AddrFrom16([16]byte(raw))
		if a.IsUnspecified() {
			continue
		}
		m, err := strconv.ParseInt(f[5], 16, 64)
		if err != nil {
			continue
		}
		if bestMetric < 0 || m < bestMetric {
			best, bestMetric = a, m
			if len(f) > 9 {
				dev = f[9]
			}
		}
	}
	return best, dev
}

// Nameserver returns the first usable nameserver in resolv.conf text. A
// unspecified, loopback (the systemd-resolved stub) and link-local
// (undialable without its zone) entries are skipped, so the next entry is
// tried.
func Nameserver(conf string) netip.Addr {
	sc := bufio.NewScanner(strings.NewReader(conf))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		a, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		a = a.Unmap()
		if a.IsUnspecified() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			continue
		}
		return a
	}
	return netip.Addr{}
}
