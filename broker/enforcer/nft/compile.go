// Package nft compiles one enforcer policy version into one nftables
// ruleset (SPEC NET-2 Segments, The core's list, Device paths, NET-3,
// NET-1; briefs/ENF.md slice e, decision 4). The ruleset is default deny on
// every segment, and the subpackage load replaces the running one
// atomically.
//
// Nothing the core or a device chooses reaches the ruleset text: devices
// appear only by their VLAN number, and host names never appear (slice f's
// resolver fills the allow sets this package declares). Layout fields are
// checked before they are written. It is enforcer code: it imports the
// standard library and broker/enforcer/policy only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package nft

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

var ErrPolicy = errors.New("nft: policy cannot be compiled")

// Table is the one inet table the ruleset defines; ARPTable filters ARP on
// the edge's segment.
const (
	Table    = "enforcer"
	ARPTable = "enforcer_arp"
)

// CoreSet is the allow set slice f's resolver fills with the addresses the
// core's signed destinations resolve to.
func CoreSet(v6 bool) string { return "core" + fam(v6) }

// DeviceSet is the allow set slice f's resolver fills for the device on
// vlan with the addresses its allow list resolves to.
func DeviceSet(vlan int, v6 bool) string { return "d" + strconv.Itoa(vlan) + fam(v6) }

// TrafficSet is the set that counts, per internet address, the bytes the
// device on vlan exchanged on connections the ruleset accepted, both ways
// (NET-5):
// at most TrafficSize addresses per family, each dropped a day after its
// last packet. TrafficOut and TrafficIn are the device's byte counters for
// the same connections. Slice i's summaries read them; nothing is kept per
// packet.
func TrafficSet(vlan int, v6 bool) string { return "t" + strconv.Itoa(vlan) + fam(v6) }
func TrafficOut(vlan int) string          { return "t" + strconv.Itoa(vlan) + "_out" }
func TrafficIn(vlan int) string           { return "t" + strconv.Itoa(vlan) + "_in" }

const TrafficSize = 64

func fam(v6 bool) string {
	if v6 {
		return "_6"
	}
	return "_4"
}

// Counter names. Guests are counted only as a whole network (NET-3); the
// rest count what the log rules log.
const (
	GuestsOut   = "guests_out"
	GuestsIn    = "guests_in"
	GuestsConns = "guests_conns"
	Inbound     = "inbound"      // new connections from the internet
	Blocked     = "blocked"      // forwarded traffic no rule allowed
	CoreDevice  = "core_device"  // connections the core starts to a device's control port
	CoreStream  = "core_stream"  // connections the core starts to a camera's or microphone's stream port
	EdgeDevice  = "edge_device"  // connections the edge starts to a device
	EdgeIn      = "edge_in"      // anything the edge sends the enforcer itself
	RADropped   = "ra_dropped"   // router advertisements from any segment
	DNSOutside  = "dns_outside"  // a device's outside or encrypted DNS
	DNSRedirect = "dns_redirect" // a device's port-53 traffic answered by the enforcer
	Spoofed     = "spoofed"      // a source address not routed back out of its interface
	APAdminDrop = "ap_admin"     // the access point's admin from anywhere but the admin port
	ISPDrop     = "isp"          // the ISP router's admin or LAN
	CoreEdge    = "core_edge"    // between the core's and the edge's segments
)

// Log prefixes. Each names a refusal: every rule that logs with one of
// them drops, and the forward chain logs nothing else from a device but
// the accepted core and edge connections, which carry the device's VLAN
// in their own prefixes. Slice i's summaries count a device's blocked
// traffic from these lines (broker/enforcer/traffic).
const (
	LogInbound   = "enf inbound "
	LogAPAdmin   = "enf ap-admin "
	LogISP       = "enf isp "
	LogNonGlobal = "enf nonglobal "
	LogCoreEdge  = "enf core-edge "
	LogDNS       = "enf dns "
	LogDrop      = "enf drop "
)

// BlockedPrefixes is every log prefix that names a refusal.
var BlockedPrefixes = []string{LogInbound, LogAPAdmin, LogISP, LogNonGlobal, LogCoreEdge, LogDNS, LogDrop}

var counters = []string{GuestsOut, GuestsIn, GuestsConns, Inbound, Blocked, CoreDevice, CoreStream, EdgeDevice, EdgeIn, RADropped, DNSOutside, DNSRedirect, Spoofed, APAdminDrop, ISPDrop, CoreEdge}

// The relays' ports (slice f): the mDNS pair relay hears 224.0.0.251:5353
// and [ff02::fb]:5353 only on the interfaces of signed pairs, and the
// Wake-on-LAN relay hears the core only.
const (
	MDNSPort   = 5353
	MDNSGroup  = "224.0.0.251"
	MDNSGroup6 = "ff02::fb"
	WoLPort    = 9
)

// Addresses that are not the internet (the IANA special-purpose blocks
// that route nowhere public). No segment reaches them through the WAN.
var nonGlobal4 = []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"}
var nonGlobal6 = []string{"::/127", "::ffff:0.0.0.0/96", "64:ff9b:1::/48", "fc00::/7", "fe80::/10", "ff00::/8"}

// Known outside encrypted-DNS resolvers (NET-3), blocked from Devices on
// every port. Plain DNS to anywhere but the enforcer is blocked by port.
var doh4 = []string{"1.0.0.1", "1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9", "45.90.28.0/24", "45.90.30.0/24", "94.140.14.14", "94.140.15.15", "149.112.112.112", "185.228.168.9", "208.67.220.220", "208.67.222.222"}
var doh6 = []string{"2001:4860:4860::8844", "2001:4860:4860::8888", "2606:4700:4700::1001", "2606:4700:4700::1111", "2620:fe::9", "2620:fe::fe", "2a07:a8c0::/33", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"}

// device is one Devices-network device with its own VLAN, which is its
// identity at the enforcer (D-225): what the access point or the device
// reports, its hardware address included, is never used.
type device struct {
	vlan  int
	iface string
	d     policy.Device
}

// Path rules (NET-2 Device paths, Cameras and microphones), from the
// document's fields: a device reaches the internet (its allow set) only
// while its vendor cloud is allowed; an everyday device with its cloud is
// online and the edge reaches its control ports; an everyday device
// without is offline and the core reaches its control ports. Of a
// safety-list device, the core reaches only an offline camera's or
// microphone's stream ports, and the edge nothing. An isolated device gets
// nothing.
func (v device) internet() bool { return !v.d.Isolated && v.d.VendorCloud }
func (v device) online() bool   { return !v.d.Isolated && v.d.Everyday && v.d.VendorCloud }
func (v device) offline() bool  { return !v.d.Isolated && v.d.Everyday && !v.d.VendorCloud }
func (v device) stream() bool   { return !v.d.Isolated && v.d.Recorder() && !v.d.VendorCloud }

// dports is one match per protocol for ports, such as "tcp dport { 80, 443 }",
// in a fixed order; none for no ports.
func dports(ports []policy.Port) []match {
	var out []match
	for _, proto := range []string{policy.ProtoTCP, policy.ProtoUDP} {
		var nums []string
		for _, p := range ports {
			if p.Proto == proto {
				nums = append(nums, port(p.Num))
			}
		}
		if len(nums) > 0 {
			out = append(out, l4Ports(proto, "{ "+strings.Join(nums, ", ")+" }"))
		}
	}
	return out
}

// VLAN reads a device's Wi-Fi identity, "vlan<N>" with N from 2 to 4094 in
// its shortest form; ok is false for anything else.
func VLAN(wifi string) (int, bool) {
	s, found := strings.CutPrefix(wifi, "vlan")
	if !found || s == "" || len(s) > 4 || s[0] == '0' {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, n >= 2 && n <= 4094
}

func devices(d policy.Document, l Layout) ([]device, error) {
	var out []device
	seen := map[int]string{}
	for _, dev := range d.Devices {
		if dev.WiFi == "" {
			continue // a radio or wired device without a VLAN: no IP path
		}
		n, ok := VLAN(dev.WiFi)
		if !ok {
			return nil, fmt.Errorf("%w: device %q has Wi-Fi identity %q", ErrPolicy, dev.ID, dev.WiFi)
		}
		if dev.Network != policy.NetDevices {
			return nil, fmt.Errorf("%w: device %q has a VLAN but is on %q", ErrPolicy, dev.ID, dev.Network)
		}
		if other, dup := seen[n]; dup {
			return nil, fmt.Errorf("%w: devices %q and %q share VLAN %d", ErrPolicy, other, dev.ID, n)
		}
		seen[n] = dev.ID
		out = append(out, device{vlan: n, iface: l.Trunk + "." + strconv.Itoa(n), d: dev})
	}
	slices.SortFunc(out, func(a, b device) int { return a.vlan - b.vlan })
	return out, nil
}

// Path is one signed pair compiled to interfaces: From may start
// connections to To, and both may when Both (two devices). Slice f's mDNS
// relay passes records along the same paths (Paths).
type Path struct {
	From, To string
	Both     bool
}

// pairs compiles the signed pairs (NET-3, NET-2 Device paths). A pair is
// between two Devices-network devices, or from an Owner or Household
// device to one: those two networks share one password each, so that side
// of the pair is the whole network. A pair has a path only when both ends
// are policy.Document.Linked: never with an isolated, unpatched (NET-7) or
// VLAN-less device.
func pairs(d policy.Document, l Layout, devs []device) ([]Path, error) {
	byID := map[string]device{}
	for _, v := range devs {
		byID[v.d.ID] = v
	}
	end := func(id string) (iface string, isDevice, live bool, err error) {
		dev := d.Device(id)
		switch {
		case dev == nil:
			return "", false, false, fmt.Errorf("%w: pair names %q", ErrPolicy, id)
		case dev.Network == policy.NetOwner:
			return l.Owner, false, true, nil
		case dev.Network == policy.NetHousehold:
			return l.Household, false, true, nil
		case dev.Network != policy.NetDevices:
			return "", false, false, fmt.Errorf("%w: pair with %q on %q", ErrPolicy, id, dev.Network)
		}
		v, ok := byID[id]
		return v.iface, true, ok && d.Linked(id), nil
	}
	var out []Path
	for _, p := range d.Pairs {
		a, aDev, aLive, err := end(p.A)
		if err != nil {
			return nil, err
		}
		b, bDev, bLive, err := end(p.B)
		if err != nil {
			return nil, err
		}
		switch {
		case !aDev && !bDev:
			return nil, fmt.Errorf("%w: pair %q-%q has no device on the devices network", ErrPolicy, p.A, p.B)
		case !aLive || !bLive:
		case aDev && bDev:
			out = append(out, Path{From: a, To: b, Both: true})
		case aDev:
			out = append(out, Path{From: b, To: a})
		default:
			out = append(out, Path{From: a, To: b})
		}
	}
	slices.SortFunc(out, func(x, y Path) int { return strings.Compare(x.From+" "+x.To, y.From+" "+y.To) })
	return slices.Compact(out), nil
}

// compiled checks the layout and the document and gives the devices with a
// VLAN and the signed pairs' paths, which every export below shares.
func compiled(d policy.Document, l Layout) ([]device, []Path, error) {
	if err := l.Check(); err != nil {
		return nil, nil, err
	}
	if _, err := policy.Encode(d); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	devs, err := devices(d, l)
	if err != nil {
		return nil, nil, err
	}
	paths, err := pairs(d, l, devs)
	if err != nil {
		return nil, nil, err
	}
	return devs, paths, nil
}

// Paths is the signed pairs' paths the ruleset opens, which are the only
// paths slice f's mDNS relay passes records on (NET-3 Casting).
func Paths(d policy.Document, l Layout) ([]Path, error) {
	_, paths, err := compiled(d, l)
	return paths, err
}

// AllowSet is one allow set the ruleset declares and the names whose
// answers slice f's resolver puts in it.
type AllowSet struct {
	Set4, Set6 string
	Names      []string
}

// AllowSets is every allow set the ruleset declares: the core's, with its
// signed destinations, then each device's that reaches the internet, with
// its allow list, by VLAN. A device the ruleset gives no internet has no
// set, so no answer reaches it (NET-2 The core's list, NET-3).
func AllowSets(d policy.Document, l Layout) ([]AllowSet, error) {
	devs, _, err := compiled(d, l)
	if err != nil {
		return nil, err
	}
	out := []AllowSet{{Set4: CoreSet(false), Set6: CoreSet(true), Names: slices.Clone(d.Destinations)}}
	for _, v := range devs {
		if v.internet() {
			out = append(out, AllowSet{Set4: DeviceSet(v.vlan, false), Set6: DeviceSet(v.vlan, true), Names: slices.Clone(v.d.Allow)})
		}
	}
	return out, nil
}

// Compile is the ruleset for one policy document on one layout: a single
// text that starts by flushing the running ruleset, so loading it replaces
// everything in one transaction. The same inputs give the same bytes.
func Compile(d policy.Document, l Layout) (string, error) {
	devs, paths, err := compiled(d, l)
	if err != nil {
		return "", err
	}
	var isp4, isp6, ap4, ap6 []string
	for _, p := range l.ISP {
		if p.Addr().Is4() {
			isp4 = append(isp4, p.Masked().String())
		} else {
			isp6 = append(isp6, p.Masked().String())
		}
	}
	for _, a := range l.APAdmin {
		if a.Is4() {
			ap4 = append(ap4, a.String())
		} else {
			ap6 = append(ap6, a.String())
		}
	}

	w := &writer{}
	q := strconv.Quote
	T := q(l.Trunk + ".*")
	w.line("flush ruleset")
	w.line("")
	w.open("table inet " + Table)
	for _, c := range counters {
		w.line("counter " + c + " { }")
	}
	var counted []device // an isolated device has no traffic to count
	for _, v := range devs {
		if !v.d.Isolated {
			counted = append(counted, v)
		}
	}
	for _, v := range counted {
		w.line("counter " + TrafficOut(v.vlan) + " { }")
		w.line("counter " + TrafficIn(v.vlan) + " { }")
	}
	w.set("isp_4", "ipv4_addr", "interval", isp4)
	w.set("isp_6", "ipv6_addr", "interval", isp6)
	w.set("nonglobal_4", "ipv4_addr", "interval", nonGlobal4)
	w.set("nonglobal_6", "ipv6_addr", "interval", nonGlobal6)
	w.set("doh_4", "ipv4_addr", "interval", doh4)
	w.set("doh_6", "ipv6_addr", "interval", doh6)
	w.set("ap_4", "ipv4_addr", "", ap4)
	w.set("ap_6", "ipv6_addr", "", ap6)
	w.set(CoreSet(false), "ipv4_addr", "timeout", nil)
	w.set(CoreSet(true), "ipv6_addr", "timeout", nil)
	for _, v := range devs {
		if v.internet() {
			w.set(DeviceSet(v.vlan, false), "ipv4_addr", "timeout", nil)
			w.set(DeviceSet(v.vlan, true), "ipv6_addr", "timeout", nil)
		}
	}

	for _, v := range counted {
		for _, v6 := range []bool{false, true} {
			w.open("set " + TrafficSet(v.vlan, v6))
			w.line("type " + map[bool]string{false: "ipv4_addr", true: "ipv6_addr"}[v6] + ";")
			w.line("size " + strconv.Itoa(TrafficSize) + ";")
			w.line("flags dynamic,timeout;")
			w.line("timeout 1d;")
			w.close()
		}
	}

	served := "{ " + strings.Join([]string{q(l.Owner), q(l.Household), q(l.Guests), q(l.Admin), q(l.Core), T}, ", ") + " }"
	edge, core, wan := q(l.Edge), q(l.Core), q(l.WAN)

	// Reverse path, on every interface: a packet whose source address is
	// not routed back out of the interface it came in on is dropped before
	// conntrack or any service sees it, so no segment can pose as the
	// upstream resolver, the internet or another segment, and a forged
	// answer never reaches the resolver that fills the allow sets (NET-2
	// The core's list). The unspecified sources of a DHCP request and of
	// IPv6 address setup have no route and pass to the rules below.
	w.open("chain rpf")
	w.line("type filter hook prerouting priority raw; policy accept;")
	w.line(`iif "lo" accept`)
	w.line("ip saddr 0.0.0.0 udp sport 68 udp dport 67 accept")
	w.line("ip6 saddr :: meta l4proto ipv6-icmp accept")
	w.line("fib saddr . iif oif missing counter name " + q(Spoofed) + " drop")
	w.close()

	w.open("chain input")
	w.line("type filter hook input priority filter; policy drop;")
	w.line(`iif "lo" accept`)
	// The edge's segment hears nothing (NET-2 Segments): no DHCP, DNS, NTP,
	// mDNS, page or other listener, before any other rule can answer it.
	w.line("iifname " + edge + " counter name " + q(EdgeIn) + " drop")
	w.line("ct state invalid drop")
	w.line("ct state established,related accept")
	w.line("icmpv6 type nd-router-advert iifname != " + wan + " counter name " + q(RADropped) + " drop")
	w.line("iifname " + wan + " udp sport 67 udp dport 68 accept")
	w.line("iifname " + wan + " udp sport 547 udp dport 546 accept")
	w.line("iifname " + wan + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept")
	w.line("iifname " + wan + ` log prefix ` + q(LogInbound) + ` counter name ` + q(Inbound) + " drop")
	w.line("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	w.line("iifname " + served + " udp dport { 53, 67, 547 } accept")
	w.line("iifname " + served + " tcp dport 53 accept")
	w.line("iifname { " + q(l.Owner) + ", " + q(l.Admin) + " } tcp dport " + port(l.PagePort) + " accept")
	w.line("iifname " + core + " tcp dport " + port(l.ChannelPort) + " accept")
	// Slice f's relays: the Wake-on-LAN relay hears only the core, and the
	// mDNS relay only the two ends of a signed pair (NET-2, NET-3).
	w.line("iifname " + core + " udp dport " + strconv.Itoa(WoLPort) + " accept")
	var ends []string
	for _, p := range paths {
		for _, e := range []string{p.From, p.To} {
			if !slices.Contains(ends, q(e)) {
				ends = append(ends, q(e))
			}
		}
	}
	if len(ends) > 0 {
		slices.Sort(ends)
		w.line("iifname { " + strings.Join(ends, ", ") + " } ip daddr " + MDNSGroup + " udp dport " + strconv.Itoa(MDNSPort) + " accept")
		w.line("iifname { " + strings.Join(ends, ", ") + " } ip6 daddr " + MDNSGroup6 + " udp dport " + strconv.Itoa(MDNSPort) + " accept")
	}
	w.close()

	// A device's DNS to anywhere is answered by the enforcer's own
	// resolver (NET-3), so only names on a list resolve.
	w.open("chain prerouting")
	w.line("type nat hook prerouting priority dstnat; policy accept;")
	w.line("iifname " + T + " meta l4proto { tcp, udp } th dport 53 counter name " + q(DNSRedirect) + " redirect")
	w.close()

	// The forward chain's rules after the established accept decide a
	// connection's first packet. The same rules, read from each
	// connection's own record (ct.go), make the live chain, which every
	// established or related packet passes first: a connection lives only
	// while the ruleset in force would still admit its first packet, so a
	// load that removes a path ends the connections open along it, both
	// ways (NET-3, NET-7).
	g := q(l.Guests)
	var fwd []rule
	add := func(in, out, tail, verdict string, m ...match) {
		fwd = append(fwd, rule{in: in, out: out, m: m, tail: tail, verdict: verdict})
	}
	logged := func(prefix, counter string) string {
		return "log prefix " + q(prefix) + " counter name " + q(counter)
	}
	add(wan, "", logged(LogInbound, Inbound), "drop")
	add(g, wan, "", "accept", daddr(false, "!= @isp_4"), daddr(false, "!= @nonglobal_4"))
	add(g, wan, "", "accept", daddr(true, "!= @isp_6"), daddr(true, "!= @nonglobal_6"))
	add(g, "", "", "drop")
	add("{ "+q(l.Owner)+", "+q(l.Household)+" }", "", "", "jump people")
	add(q(l.Admin), q(l.APMgmt), "", "accept", daddr(false, "@ap_4"))
	add(q(l.Admin), q(l.APMgmt), "", "accept", daddr(true, "@ap_6"))
	add("", "", logged(LogAPAdmin, APAdminDrop), "drop", daddr(false, "@ap_4"))
	add("", "", logged(LogAPAdmin, APAdminDrop), "drop", daddr(true, "@ap_6"))
	add("", "", logged(LogISP, ISPDrop), "drop", daddr(false, "@isp_4"))
	add("", "", logged(LogISP, ISPDrop), "drop", daddr(true, "@isp_6"))
	add("", wan, logged(LogNonGlobal, Blocked), "drop", daddr(false, "@nonglobal_4"))
	add("", wan, logged(LogNonGlobal, Blocked), "drop", daddr(true, "@nonglobal_6"))
	add(edge, core, logged(LogCoreEdge, CoreEdge), "drop")
	add(core, edge, logged(LogCoreEdge, CoreEdge), "drop")
	// From here on, oifname WAN is the internet.
	add(q(l.Admin), core, "", "accept", l4Ports("tcp", port(l.CorePagePort)))
	add(edge, wan, "", "accept")
	add(core, wan, "", "accept", resolved(false, CoreSet(false)))
	add(core, wan, "", "accept", resolved(true, CoreSet(true)))
	// Devices: outside DNS and known encrypted-DNS resolvers are blocked
	// before any allow set is consulted (NET-3).
	add(T, wan, logged(LogDNS, DNSOutside), "drop", daddr(false, "@doh_4"))
	add(T, wan, logged(LogDNS, DNSOutside), "drop", daddr(true, "@doh_6"))
	add(T, wan, logged(LogDNS, DNSOutside), "drop", match{"meta l4proto { tcp, udp } th dport { 53, 853 }", "ct protocol { tcp, udp } ct original proto-dst { 53, 853 }"})
	for _, v := range devs {
		i := q(v.iface)
		vl := strconv.Itoa(v.vlan)
		if v.internet() {
			add(i, wan, "", "accept", resolved(false, DeviceSet(v.vlan, false)))
			add(i, wan, "", "accept", resolved(true, DeviceSet(v.vlan, true)))
		}
		for _, m := range dports(v.d.Control) {
			if v.online() {
				add(edge, i, `log prefix "enf edge-dev `+vl+` " counter name `+q(EdgeDevice), "accept", m)
			}
			if v.offline() {
				add(core, i, `log prefix "enf core-dev `+vl+` " counter name `+q(CoreDevice), "accept", m)
			}
		}
		for _, m := range dports(v.d.Stream) {
			if v.stream() {
				add(core, i, `log prefix "enf core-stream `+vl+` " counter name `+q(CoreStream), "accept", m)
			}
		}
	}
	for _, p := range paths {
		if p.Both {
			add(q(p.From), q(p.To), "", "accept")
			add(q(p.To), q(p.From), "", "accept")
		}
	}

	// Owner and Household: the internet, their signed pairs and, from Owner
	// only, the core's page (CH-9). They are not inspected (NET-1), so what
	// they are refused is dropped without a log line or a counter.
	var people []rule
	padd := func(in, out, verdict string, m ...match) {
		people = append(people, rule{in: in, out: out, m: m, verdict: verdict})
	}
	padd("", "", "drop", daddr(false, "@ap_4"))
	padd("", "", "drop", daddr(true, "@ap_6"))
	padd("", "", "drop", daddr(false, "@isp_4"))
	padd("", "", "drop", daddr(true, "@isp_6"))
	padd("", wan, "drop", daddr(false, "@nonglobal_4"))
	padd("", wan, "drop", daddr(true, "@nonglobal_6"))
	padd(q(l.Owner), wan, "accept")
	padd(q(l.Household), wan, "accept")
	padd(q(l.Owner), core, "accept", l4Ports("tcp", port(l.CorePagePort)))
	for _, p := range paths {
		if !p.Both {
			padd(q(p.From), q(p.To), "accept")
		}
	}

	// Every accept binds its connection to its interface pair (live.go,
	// bind), so every accept names one interface each way.
	idx := map[string]uint32{}
	for k, n := range []string{l.WAN, l.Owner, l.Household, l.Guests, l.Admin, l.Core, l.Edge, l.APMgmt} {
		idx[q(n)] = 0x1001 + uint32(k)
	}
	for _, v := range devs {
		idx[q(v.iface)] = uint32(v.vlan)
	}
	for _, rs := range [][]rule{fwd, people} {
		if err := bindAll(idx, rs); err != nil {
			return "", err
		}
	}
	// A related packet that reaches the end of a live chain names a
	// connection that does not run on the interfaces it crossed: an ICMP
	// error forged from another segment, or a genuine one about a connection
	// a load cut (#4113, A18 Segments). It is dropped and, like any other
	// refusal, logged and counted, except from the networks that are never
	// observed (NET-1, NET-3); a cut connection's own later packets are
	// dropped without a line, since a load can cut many at once.
	related := "ct state related iifname != { " + g + ", " + q(l.Owner) + ", " + q(l.Household) + " } " + logged(LogDrop, Blocked) + " drop"

	w.open("chain forward")
	w.line("type filter hook forward priority filter; policy drop;")
	// Guests: counted only as a whole network, never per device or per
	// destination, and never logged (NET-3).
	w.line("iifname " + g + " counter name " + q(GuestsOut))
	w.line("oifname " + g + " counter name " + q(GuestsIn))
	w.line("iifname " + g + " ct state new counter name " + q(GuestsConns))
	w.line("ct state invalid drop")
	w.line("ct state established,related jump " + live("forward"))
	// Each device's traffic on accepted connections is counted before the
	// accept below (NET-5). Only established packets count: an address the
	// device was refused never enters its set, and neither does the sender
	// of a related packet such as an ICMP error, which anyone can forge.
	if len(counted) > 0 {
		var outs, ins []string
		for _, v := range counted {
			outs = append(outs, q(v.iface)+" : jump "+trafficChain(v.vlan, "out"))
			ins = append(ins, q(v.iface)+" : jump "+trafficChain(v.vlan, "in"))
		}
		w.line("ct state established iifname vmap { " + strings.Join(outs, ", ") + " }")
		w.line("ct state established oifname vmap { " + strings.Join(ins, ", ") + " }")
	}
	w.line("ct state established,related accept")
	for _, r := range fwd {
		w.line(r.first())
	}
	w.line(logged(LogDrop, Blocked) + " drop")
	w.close()

	w.open("chain people")
	for _, r := range people {
		w.line(r.first())
	}
	w.line("drop")
	w.close()

	w.open("chain " + live("forward"))
	for _, r := range fwd {
		for _, s := range r.later() {
			w.line(s)
		}
	}
	w.line(related)
	w.line("drop")
	w.close()

	w.open("chain " + live("people"))
	for _, r := range people {
		for _, s := range r.later() {
			w.line(s)
		}
	}
	w.line(related)
	w.line("drop")
	w.close()

	// A device's counting chains: all its bytes are counted, and its
	// internet traffic by address, what it sends by destination and what it
	// receives by source. A peer at home (a box, a paired device, a person
	// on Owner or Household) is never recorded by address (NET-1).
	for _, v := range counted {
		for _, dir := range []string{"out", "in"} {
			c, addr, side := TrafficOut(v.vlan), "daddr", "oifname "
			if dir == "in" {
				c, addr, side = TrafficIn(v.vlan), "saddr", "iifname "
			}
			w.open("chain " + trafficChain(v.vlan, dir))
			w.line("counter name " + q(c))
			w.line(side + wan + " update @" + TrafficSet(v.vlan, false) + " { ip " + addr + " counter }")
			w.line(side + wan + " update @" + TrafficSet(v.vlan, true) + " { ip6 " + addr + " counter }")
			w.close()
		}
	}

	w.open("chain output")
	w.line("type filter hook output priority filter; policy accept;")
	w.line("oifname " + edge + " drop")
	w.close()

	w.open("chain postrouting")
	w.line("type nat hook postrouting priority srcnat; policy accept;")
	w.line("oifname " + wan + " masquerade")
	w.close()
	w.close()
	w.line("")

	// ARP on the edge's segment is answered only for the gateway (NET-2
	// Segments); the kernel would otherwise answer for any of its addresses.
	w.open("table arp " + ARPTable)
	w.open("chain input")
	w.line("type filter hook input priority filter; policy accept;")
	w.line("iifname " + edge + " arp operation request arp daddr ip != " + l.EdgeGateway.String() + " drop")
	w.close()
	w.close()
	return w.b.String(), nil
}

func trafficChain(vlan int, dir string) string {
	return "t" + strconv.Itoa(vlan) + "_" + dir + "_count"
}

func port(p uint16) string { return strconv.Itoa(int(p)) }

type writer struct {
	b     strings.Builder
	depth int
}

func (w *writer) line(s string) {
	if s != "" {
		w.b.WriteString(strings.Repeat("\t", w.depth))
		w.b.WriteString(s)
	}
	w.b.WriteByte('\n')
}

func (w *writer) open(s string) { w.line(s + " {"); w.depth++ }
func (w *writer) close()        { w.depth--; w.line("}") }

func (w *writer) set(name, typ, flags string, elems []string) {
	w.open("set " + name)
	w.line("type " + typ + ";")
	if flags != "" {
		w.line("flags " + flags + ";")
	}
	if len(elems) > 0 {
		w.line("elements = { " + strings.Join(elems, ", ") + " }")
	}
	w.close()
}
