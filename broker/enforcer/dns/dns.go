// Package dns generates the enforcer's dnsmasq configuration (SPEC NET-2
// The core's list, Hardening, NET-3; briefs/ENF.md slice f, decision 5).
//
// Several dnsmasq instances run, each from one generated file:
//
//   - Listed instances, one per view: one answers the core's segment, and
//     one each Devices VLAN. Each resolves only its own list's names (the
//     core's signed list, or that device's allow list), each name exactly
//     (its subdomains get NXDOMAIN, every other name REFUSED), and puts
//     each answer's addresses into that list's nft allow set (nftset=). A
//     device so never learns another list's addresses, and its queries for
//     them never leave the enforcer. Only addresses its own resolver
//     returned enter an allow set, so a core or device that dials any
//     other address under a listed name is dropped. None keeps a cache, so
//     every answer comes from upstream and fills the set again after a
//     ruleset load.
//   - People answers Owner, Household, Guests and the admin port with any
//     name, filling no set: those networks reach the internet anyway.
//   - DHCP serves addresses, with the enforcer as router and resolver, on
//     the networks the setup marks, and answers no DNS.
//
// No instance names the edge's segment, the WAN or the access point's
// management interface, and Generate refuses a setup that would (NET-2
// Segments: the edge hears nothing). No instance logs queries (NET-3:
// Guests are never observed). It is enforcer code: it imports the standard
// library and the enforcer's policy and nft packages only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var ErrConfig = errors.New("dns: configuration refused")

// MaxTTL caps the TTL the listed instance hands out, so a device asks
// again, and so refills its allow set, within this many seconds of a
// ruleset load emptying it (ASSUMPTIONS ENF-f-3).
const MaxTTL = 300

// Net is one network an instance answers on: its interface, the prefixes
// of the enforcer's addresses there (IPv4, and optionally an IPv6 /64),
// and whether the enforcer serves DHCP on it. The enforcer's own address
// is each prefix's first host; leases start at the tenth.
type Net struct {
	Iface   string
	Prefix4 netip.Prefix
	Prefix6 netip.Prefix // zero for none
	DHCP    bool
}

// Setup is the enforcer's own resolver and addressing. Like nft.Layout it
// comes from the image and setup, never from the core or the policy.
type Setup struct {
	// Upstream is the enforcer's outside resolvers, global addresses only.
	Upstream []netip.AddrPort
	// Nets is every network an instance answers on, with the prefixes of
	// every address the enforcer holds there: the Owner, Household,
	// Guests, admin and core interfaces and each listed device's VLAN. A
	// setup that leaves one out is refused, so no served prefix escapes the
	// upstream check (ASSUMPTIONS ENF-f-5). DHCP serves the ones marked.
	Nets []Net
	// LeaseFile is the absolute path of the DHCP lease file.
	LeaseFile string
}

// Files is every instance's configuration file.
type Files struct {
	// Listed is one listed instance per view: the core's first, then each
	// device VLAN's in the document's order.
	Listed       []Listed
	People, DHCP string
}

// Listed is one listed instance: the interface it alone answers on, and
// its configuration file.
type Listed struct {
	Iface, Conf string
}

// Generate is the configuration for one policy document on one layout. The
// same inputs give the same bytes. A document whose names are not DNS host
// names is refused, so the previous configuration stays.
func Generate(d policy.Document, l nft.Layout, s Setup) (Files, error) {
	sets, err := nft.AllowSets(d, l)
	if err != nil {
		return Files{}, err
	}
	// One listed instance per view: the core's segment with the core's
	// list, then each device with a VLAN with its own. A device without
	// an allow set gets an instance with no names, which refuses every
	// query (ASSUMPTIONS ENF-f-4).
	setOf := map[string]nft.AllowSet{}
	for _, set := range sets {
		setOf[set.Set4] = set
	}
	views := []Listed{{Iface: l.Core}}
	viewSets := []nft.AllowSet{setOf[nft.CoreSet(false)]}
	for _, dev := range d.Devices {
		if n, ok := nft.VLAN(dev.WiFi); ok && dev.Network == policy.NetDevices {
			views = append(views, Listed{Iface: l.Trunk + "." + strconv.Itoa(n)})
			viewSets = append(viewSets, setOf[nft.DeviceSet(n, false)])
		}
	}
	peopleIfaces := []string{l.Owner, l.Household, l.Guests, l.Admin}
	answered := slices.Clone(peopleIfaces)
	for _, v := range views {
		answered = append(answered, v.Iface)
	}
	if err := s.check(l, answered); err != nil {
		return Files{}, err
	}
	for i, set := range viewSets {
		conf, err := s.listed(views[i].Iface, set)
		if err != nil {
			return Files{}, err
		}
		views[i].Conf = conf
	}

	var people lines
	people.common(peopleIfaces)
	people.add("domain-needed")
	people.add("bogus-priv")
	for _, u := range s.Upstream {
		people.add("server=" + upstream(u))
	}

	var dhcp lines
	var ifaces []string
	var leased []Net
	for _, n := range s.Nets {
		if n.DHCP {
			ifaces = append(ifaces, n.Iface)
			leased = append(leased, n)
		}
	}
	dhcp.add("port=0")
	dhcp.common(ifaces)
	dhcp.add("dhcp-leasefile=" + s.LeaseFile)
	dhcp.add("dhcp-authoritative")
	dhcp.add("dhcp-option=option:dns-server,0.0.0.0")
	v6 := false
	for _, n := range leased {
		first, last := hosts4(n.Prefix4)
		// dnsmasq serves a range on the interface whose address is in it.
		dhcp.add("dhcp-range=" + first.String() + "," + last.String() + ",12h")
		if n.Prefix6.IsValid() {
			b := n.Prefix6.Addr().As16()
			b[14], b[15] = 0x10, 0x00
			lo := netip.AddrFrom16(b)
			b[14], b[15] = 0xff, 0xff
			hi := netip.AddrFrom16(b)
			dhcp.add("dhcp-range=" + lo.String() + "," + hi.String() + ",64,12h")
			v6 = true
		}
	}
	if v6 {
		dhcp.add("enable-ra")
		dhcp.add("dhcp-option=option6:dns-server,[::]")
	}
	return Files{Listed: views, People: people.String(), DHCP: dhcp.String()}, nil
}

// listed is the listed instance for one view: it answers on iface alone
// and forwards only set's names, each filling set alone.
func (s Setup) listed(iface string, set nft.AllowSet) (string, error) {
	names := slices.Clone(set.Names)
	slices.Sort(names)
	names = slices.Compact(names)
	var w lines
	w.common([]string{iface})
	w.add("cache-size=0")
	w.add("max-ttl=" + strconv.Itoa(MaxTTL))
	for _, n := range names {
		if !Hostname(n) {
			return "", fmt.Errorf("%w: %q is not a DNS host name", ErrConfig, n)
		}
		for _, u := range s.Upstream {
			w.add("server=/" + n + "/" + upstream(u))
		}
		// Exactly the name: its subdomains are answered locally, which
		// is NXDOMAIN, and never forwarded (ASSUMPTIONS ENF-f-2).
		w.add("local=/*." + n + "/")
		w.add("nftset=/" + n + "/4#inet#" + nft.Table + "#" + set.Set4 + ",6#inet#" + nft.Table + "#" + set.Set6)
	}
	return w.String(), nil
}

// check refuses a setup that names an interface the layout does not serve
// (the edge's segment, the WAN and the access point's management
// interface among them), leaves out one an instance answers on (answered),
// holds a prefix that is not a masked private block, an upstream that is
// not a global address or is on a served network, or a lease file path
// that needs quoting.
func (s Setup) check(l nft.Layout, answered []string) error {
	bad := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrConfig}, a...)...) }
	if len(s.Upstream) == 0 {
		return bad("no upstream resolver")
	}
	for _, u := range s.Upstream {
		a := u.Addr()
		if !a.IsGlobalUnicast() || a.IsPrivate() || a.Is4In6() || a.Zone() != "" || u.Port() == 0 {
			return bad("upstream %v", u)
		}
	}
	if !strings.HasPrefix(s.LeaseFile, "/") || !safePath(s.LeaseFile) {
		return bad("lease file %q", s.LeaseFile)
	}
	served := []string{l.Owner, l.Household, l.Guests, l.Admin, l.Core}
	var seen []string
	for _, n := range s.Nets {
		if slices.Contains(seen, n.Iface) {
			return bad("network %q twice", n.Iface)
		}
		seen = append(seen, n.Iface)
		vlan, isDev := strings.CutPrefix(n.Iface, l.Trunk+".")
		if _, ok := nft.VLAN("vlan" + vlan); !slices.Contains(served, n.Iface) && !(isDev && ok) {
			return bad("%q is not a served network", n.Iface)
		}
		p := n.Prefix4
		if !p.IsValid() || !p.Addr().Is4() || p != p.Masked() || !p.Addr().IsPrivate() || p.Bits() < 16 || p.Bits() > 28 {
			return bad("%s: IPv4 prefix %v", n.Iface, p)
		}
		if q := n.Prefix6; q.IsValid() && (!q.Addr().Is6() || q.Addr().Is4In6() || q != q.Masked() || q.Bits() != 64 || q.Addr().Zone() != "") {
			return bad("%s: IPv6 prefix %v", n.Iface, q)
		}
	}
	for _, i := range answered {
		if !slices.Contains(seen, i) {
			return bad("no network for %q, which an instance answers on", i)
		}
	}
	// An upstream on a served network would be reached through that
	// network, where the reverse-path filter cannot tell its answers from
	// a forger's there (ASSUMPTIONS ENF-f-5). Every served network is in
	// Nets, with or without DHCP, so every served prefix is checked.
	for _, u := range s.Upstream {
		for _, n := range s.Nets {
			if n.Prefix4.Contains(u.Addr()) || n.Prefix6.Contains(u.Addr()) {
				return bad("upstream %v is on %s", u, n.Iface)
			}
		}
	}
	return nil
}

// Hostname reports whether s is a DNS host name dnsmasq can take as is:
// lower-case letters, digits and inner hyphens, in labels of 1 to 63
// bytes, at least two labels, 253 bytes at most, no trailing dot. A
// wildcard, an upper-case or non-ASCII name, and anything that would need
// quoting in dnsmasq's syntax (/, #, comma, space) is refused.
func Hostname(s string) bool {
	if len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lb := range labels {
		if lb == "" || len(lb) > 63 || lb[0] == '-' || lb[len(lb)-1] == '-' {
			return false
		}
		for _, c := range []byte(lb) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func safePath(s string) bool {
	for _, c := range []byte(s) {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '/' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

// upstream is a resolver in dnsmasq's server= form, address#port.
func upstream(u netip.AddrPort) string {
	return u.Addr().String() + "#" + strconv.Itoa(int(u.Port()))
}

// hosts4 is the lease range of p: its tenth host to its last before the
// broadcast address.
func hosts4(p netip.Prefix) (first, last netip.Addr) {
	b := p.Addr().As4()
	n := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	size := uint32(1) << (32 - p.Bits())
	at := func(v uint32) netip.Addr {
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	return at(n + 10), at(n + size - 2)
}

// lines is one configuration file.
type lines struct{ b strings.Builder }

func (w *lines) add(s string) { w.b.WriteString(s); w.b.WriteByte('\n') }

func (w *lines) String() string { return w.b.String() }

// common is what every instance starts with: no outside configuration
// (resolv.conf, /etc/hosts), and listening only on ifaces, bound to each
// interface's own addresses, never loopback, never a wildcard address.
func (w *lines) common(ifaces []string) {
	w.add("no-resolv")
	w.add("no-hosts")
	w.add("no-poll")
	w.add("stop-dns-rebind")
	w.add("bind-dynamic")
	w.add("except-interface=lo")
	for _, i := range ifaces {
		w.add("interface=" + i)
	}
}
