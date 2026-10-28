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
	Inbound     = "inbound"     // new connections from the internet
	Blocked     = "blocked"     // forwarded traffic no rule allowed
	CoreDevice  = "core_device" // connections the core starts to a device
	EdgeDevice  = "edge_device" // connections the edge starts to a device
	EdgeIn      = "edge_in"     // anything the edge sends the enforcer itself
	RADropped   = "ra_dropped"  // router advertisements from any segment
	DNSOutside  = "dns_outside" // a device's outside or encrypted DNS
	APAdminDrop = "ap_admin"    // the access point's admin from anywhere but the admin port
	ISPDrop     = "isp"         // the ISP router's admin or LAN
	CoreEdge    = "core_edge"   // between the core's and the edge's segments
)

var counters = []string{GuestsOut, GuestsIn, GuestsConns, Inbound, Blocked, CoreDevice, EdgeDevice, EdgeIn, RADropped, DNSOutside, APAdminDrop, ISPDrop, CoreEdge}

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

// Path rules (NET-2 Device paths), from the document's fields: a device
// reaches the internet (its allow set) only while its vendor cloud is
// allowed; an everyday device with its cloud is online and the edge relays
// it; an everyday device without is offline and the core reaches it
// directly. A safety-list device is reached by neither box. An isolated
// device gets nothing.
func (v device) internet() bool { return !v.d.Isolated && v.d.VendorCloud }
func (v device) online() bool   { return !v.d.Isolated && v.d.Everyday && v.d.VendorCloud }
func (v device) offline() bool  { return !v.d.Isolated && v.d.Everyday && !v.d.VendorCloud }

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

// path is one signed pair compiled to interfaces: from may start
// connections to to, and both may when both are devices.
type path struct {
	from, to string
	both     bool
}

// pairs compiles the signed pairs (NET-3, NET-2 Device paths). A pair is
// between two Devices-network devices, or from an Owner or Household
// device to one: those two networks share one password each, so that side
// of the pair is the whole network. A pair with an isolated or VLAN-less
// device has no path.
func pairs(d policy.Document, l Layout, devs []device) ([]path, error) {
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
		return v.iface, true, ok && !v.d.Isolated, nil
	}
	var out []path
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
			out = append(out, path{from: a, to: b, both: true})
		case aDev:
			out = append(out, path{from: b, to: a})
		default:
			out = append(out, path{from: a, to: b})
		}
	}
	slices.SortFunc(out, func(x, y path) int { return strings.Compare(x.from+" "+x.to, y.from+" "+y.to) })
	return slices.Compact(out), nil
}

// Compile is the ruleset for one policy document on one layout: a single
// text that starts by flushing the running ruleset, so loading it replaces
// everything in one transaction. The same inputs give the same bytes.
func Compile(d policy.Document, l Layout) (string, error) {
	if err := l.Check(); err != nil {
		return "", err
	}
	if _, err := policy.Encode(d); err != nil {
		return "", fmt.Errorf("%w: %v", ErrPolicy, err)
	}
	devs, err := devices(d, l)
	if err != nil {
		return "", err
	}
	paths, err := pairs(d, l, devs)
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

	served := "{ " + strings.Join([]string{q(l.Owner), q(l.Household), q(l.Guests), q(l.Admin), q(l.Core), T}, ", ") + " }"
	edge, core, wan := q(l.Edge), q(l.Core), q(l.WAN)

	w.open("chain input")
	w.line("type filter hook input priority filter; policy drop;")
	w.line(`iif "lo" accept`)
	// The edge's segment hears nothing (NET-2 Segments): no DHCP, DNS, NTP,
	// mDNS, page or other listener, before any other rule can answer it.
	if l.EdgeGateway6.IsValid() {
		w.line("iifname " + edge + " icmpv6 type nd-neighbor-solicit icmpv6 taddr " + l.EdgeGateway6.String() + " accept")
	}
	w.line("iifname " + edge + " counter name " + q(EdgeIn) + " drop")
	w.line("ct state invalid drop")
	w.line("ct state established,related accept")
	w.line("icmpv6 type nd-router-advert iifname != " + wan + " counter name " + q(RADropped) + " drop")
	w.line("iifname " + wan + " udp sport 67 udp dport 68 accept")
	w.line("iifname " + wan + " udp sport 547 udp dport 546 accept")
	w.line("iifname " + wan + " icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-advert } accept")
	w.line("iifname " + wan + ` log prefix "enf inbound " counter name ` + q(Inbound) + " drop")
	w.line("icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit } accept")
	w.line("iifname " + served + " udp dport { 53, 67, 547 } accept")
	w.line("iifname " + served + " tcp dport 53 accept")
	w.line("iifname { " + q(l.Owner) + ", " + q(l.Admin) + " } tcp dport " + port(l.PagePort) + " accept")
	w.line("iifname " + core + " tcp dport " + port(l.ChannelPort) + " accept")
	w.close()

	w.open("chain forward")
	w.line("type filter hook forward priority filter; policy drop;")
	// Guests: counted only as a whole network, never per device or per
	// destination, and never logged (NET-3).
	g := q(l.Guests)
	w.line("iifname " + g + " counter name " + q(GuestsOut))
	w.line("oifname " + g + " counter name " + q(GuestsIn))
	w.line("iifname " + g + " ct state new counter name " + q(GuestsConns))
	w.line("ct state invalid drop")
	w.line("ct state established,related accept")
	w.line("iifname " + wan + ` log prefix "enf inbound " counter name ` + q(Inbound) + " drop")
	w.line("iifname " + g + " oifname " + wan + " ip daddr != @isp_4 ip daddr != @nonglobal_4 accept")
	w.line("iifname " + g + " oifname " + wan + " ip6 daddr != @isp_6 ip6 daddr != @nonglobal_6 accept")
	w.line("iifname " + g + " drop")
	w.line("iifname { " + q(l.Owner) + ", " + q(l.Household) + " } jump people")
	w.line("iifname " + q(l.Admin) + " oifname " + q(l.APMgmt) + " ip daddr @ap_4 accept")
	w.line("iifname " + q(l.Admin) + " oifname " + q(l.APMgmt) + " ip6 daddr @ap_6 accept")
	w.line(`ip daddr @ap_4 log prefix "enf ap-admin " counter name ` + q(APAdminDrop) + " drop")
	w.line(`ip6 daddr @ap_6 log prefix "enf ap-admin " counter name ` + q(APAdminDrop) + " drop")
	w.line(`ip daddr @isp_4 log prefix "enf isp " counter name ` + q(ISPDrop) + " drop")
	w.line(`ip6 daddr @isp_6 log prefix "enf isp " counter name ` + q(ISPDrop) + " drop")
	w.line("oifname " + wan + ` ip daddr @nonglobal_4 log prefix "enf nonglobal " counter name ` + q(Blocked) + " drop")
	w.line("oifname " + wan + ` ip6 daddr @nonglobal_6 log prefix "enf nonglobal " counter name ` + q(Blocked) + " drop")
	w.line("iifname " + edge + " oifname " + core + ` log prefix "enf core-edge " counter name ` + q(CoreEdge) + " drop")
	w.line("iifname " + core + " oifname " + edge + ` log prefix "enf core-edge " counter name ` + q(CoreEdge) + " drop")
	// From here on, oifname WAN is the internet.
	w.line("iifname " + q(l.Admin) + " oifname " + core + " tcp dport " + port(l.CorePagePort) + " accept")
	w.line("iifname " + edge + " oifname " + wan + " accept")
	w.line("iifname " + core + " oifname " + wan + " ip daddr @" + CoreSet(false) + " accept")
	w.line("iifname " + core + " oifname " + wan + " ip6 daddr @" + CoreSet(true) + " accept")
	// Devices: outside DNS and known encrypted-DNS resolvers are blocked
	// before any allow set is consulted (NET-3).
	w.line("iifname " + T + " oifname " + wan + ` ip daddr @doh_4 log prefix "enf dns " counter name ` + q(DNSOutside) + " drop")
	w.line("iifname " + T + " oifname " + wan + ` ip6 daddr @doh_6 log prefix "enf dns " counter name ` + q(DNSOutside) + " drop")
	w.line("iifname " + T + " oifname " + wan + ` meta l4proto { tcp, udp } th dport { 53, 853 } log prefix "enf dns " counter name ` + q(DNSOutside) + " drop")
	for _, v := range devs {
		i := q(v.iface)
		vl := strconv.Itoa(v.vlan)
		if v.internet() {
			w.line("iifname " + i + " oifname " + wan + " ip daddr @" + DeviceSet(v.vlan, false) + " accept")
			w.line("iifname " + i + " oifname " + wan + " ip6 daddr @" + DeviceSet(v.vlan, true) + " accept")
		}
		if v.online() {
			w.line("iifname " + edge + " oifname " + i + ` log prefix "enf edge-dev ` + vl + ` " counter name ` + q(EdgeDevice) + " accept")
		}
		if v.offline() {
			w.line("iifname " + core + " oifname " + i + ` log prefix "enf core-dev ` + vl + ` " counter name ` + q(CoreDevice) + " accept")
		}
	}
	for _, p := range paths {
		if p.both {
			w.line("iifname " + q(p.from) + " oifname " + q(p.to) + " accept")
			w.line("iifname " + q(p.to) + " oifname " + q(p.from) + " accept")
		}
	}
	w.line(`log prefix "enf drop " counter name ` + q(Blocked) + " drop")
	w.close()

	// Owner and Household: the internet, their signed pairs and, from Owner
	// only, the core's page (CH-9). They are not inspected (NET-1), so what
	// they are refused is dropped without a log line or a counter.
	w.open("chain people")
	w.line("ip daddr @ap_4 drop")
	w.line("ip6 daddr @ap_6 drop")
	w.line("ip daddr @isp_4 drop")
	w.line("ip6 daddr @isp_6 drop")
	w.line("oifname " + wan + " ip daddr @nonglobal_4 drop")
	w.line("oifname " + wan + " ip6 daddr @nonglobal_6 drop")
	w.line("oifname " + wan + " accept")
	w.line("iifname " + q(l.Owner) + " oifname " + core + " tcp dport " + port(l.CorePagePort) + " accept")
	for _, p := range paths {
		if !p.both {
			w.line("iifname " + q(p.from) + " oifname " + q(p.to) + " accept")
		}
	}
	w.line("drop")
	w.close()

	w.open("chain output")
	w.line("type filter hook output priority filter; policy accept;")
	if l.EdgeGateway6.IsValid() {
		w.line("oifname " + edge + " icmpv6 type nd-neighbor-advert ip6 saddr " + l.EdgeGateway6.String() + " accept")
	}
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
