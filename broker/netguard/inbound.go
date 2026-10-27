package netguard

import (
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// InboundTable is the nftables table InboundRules renders. It is separate
// from CH-9's agentos_ap table, which stays as it is: a drop in either
// table is final, so the access point's interface is exempt here and
// governed there.
const InboundTable = "agentos_inbound"

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,15}$`)

// DiscoveryPort is a passive-discovery listener (DEV-1) the home network may
// reach: a named service on a fixed UDP port.
type DiscoveryPort string

const (
	DiscoverMDNS   DiscoveryPort = "mdns"   // udp 5353
	DiscoverSSDP   DiscoveryPort = "ssdp"   // udp 1900
	DiscoverMatter DiscoveryPort = "matter" // udp 5540
)

var discoveryUDP = map[DiscoveryPort]uint16{DiscoverMDNS: 5353, DiscoverSSDP: 1900, DiscoverMatter: 5540}

// DeviceAllow admits one connected device's pinned address (DEV-2 In) to
// the listed TCP ports only.
type DeviceAllow struct {
	Addr     netip.Addr
	TCPPorts []uint16
}

// Inbound configures the inbound rule set. The zero value is valid: it
// exempts only loopback and admits nothing else beyond replies and the
// host's own link configuration. That zero value is what the image loads at
// boot, before any listener (DEV-net-e 2a).
type Inbound struct {
	// Exempt are interfaces besides loopback that another table governs:
	// the access point, whose loader adds it to the set when it loads
	// CH-9's agentos_ap (ASSUMPTIONS N13), and any agent-machine link.
	Exempt []string
	// Devices is the per-device allow hook.
	Devices []DeviceAllow
	// Discovery is the passive-discovery allow hook.
	Discovery []DiscoveryPort
	// Page admits the owner page's TCP 80 and 443 from RFC 1918 sources on
	// en* (Ethernet) interfaces only, not ap0 (CH-9, D-178; WIFI-del-a3-1).
	Page bool
}

// Image is what the image loads at boot: the zero value and the page.
var Image = Inbound{Page: true}

// Validate says why the configuration cannot be rendered.
func (c Inbound) Validate() error {
	for _, u := range c.Exempt {
		if !ifaceRe.MatchString(u) {
			return fmt.Errorf("netguard: inbound exempt interface %q is not an interface name", u)
		}
	}
	for _, d := range c.Devices {
		a := d.Addr
		if !a.IsValid() || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return fmt.Errorf("netguard: inbound device address %q is not a single unicast address", a)
		}
		if len(d.TCPPorts) == 0 {
			return fmt.Errorf("netguard: inbound device %s needs explicit ports", a)
		}
		for _, p := range d.TCPPorts {
			if p == 0 {
				return fmt.Errorf("netguard: inbound device %s lists port 0", a)
			}
		}
	}
	for _, p := range c.Discovery {
		if _, ok := discoveryUDP[p]; !ok {
			return fmt.Errorf("netguard: inbound discovery port %q unknown", p)
		}
	}
	return nil
}

// InboundExemptSet is the named set of interfaces the table leaves to other
// tables. A loader adds an interface with
// "nft add element inet agentos_inbound exempt { <iface> }".
const InboundExemptSet = "exempt"

// InboundExemptRemove renders the nft script that takes iface out of the
// exempt set (DEV-2, DEV-net-g): an add then a delete in one transaction,
// so it succeeds whether or not iface is still there, and touches no other
// element. It refuses "lo", which the set always holds, and any name
// ifaceRe refuses. Removing an access point's interface closes it: the
// interface falls to this table's drop.
func InboundExemptRemove(iface string) (string, error) {
	if !ifaceRe.MatchString(iface) || iface == "lo" {
		return "", fmt.Errorf("netguard: %q is not an exempt interface", iface)
	}
	el := fmt.Sprintf("inet %s %s { %q }", InboundTable, InboundExemptSet, iface)
	return "add element " + el + "\ndelete element " + el + "\n", nil
}

// InboundRules renders the nftables ruleset that drops every connection the
// home network opens to a box port (DEV-2 In), on every interface: one the
// box has not named yet (a USB tether, a second NIC) is dropped too. It
// admits, in order: any interface in the exempt set (loopback always);
// replies to what the box opened; the host's own link configuration, which
// DEV-2 does not count as connections (router advertisements from a
// link-local source, neighbour solicitations and advertisements from any
// source as RFC 4861 allows, all with hop limit 255 so none was routed in;
// DHCPv4 and DHCPv6 replies from their server ports); the page's ports
// (Page); the listed devices and discovery ports; and drops the rest.
//
// The box routes nothing (image I21), so the table also drops every
// forwarded packet, IPv4 and IPv6, unless it enters or leaves an exempt
// interface, whose table governs it (agentos_ap drops all but passthrough).
// A second table of the same name in the bridge family drops every bridged
// frame, which the inet hooks never see. Forwarding that NetworkManager or
// a sysctl turns on (a shared or access-point profile, #2824) is then
// inert: a drop in any table is final, whatever another table accepts.
func InboundRules(c Inbound) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	ex := map[string]bool{"lo": true}
	for _, u := range c.Exempt {
		ex[u] = true
	}
	names := make([]string, 0, len(ex))
	for u := range ex {
		names = append(names, fmt.Sprintf("%q", u))
	}
	sort.Strings(names)
	var b strings.Builder
	line := func(s string, a ...any) { fmt.Fprintf(&b, s+"\n", a...) }
	line("table inet %s {", InboundTable)
	line("  set %s {", InboundExemptSet)
	line("    type ifname")
	line("    elements = { %s }", strings.Join(names, ", "))
	line("  }")
	line("  chain input {")
	line("    type filter hook input priority filter; policy accept;")
	line("    iifname @%s accept", InboundExemptSet)
	line("    ct state established,related accept")
	line("    ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert accept")
	line("    ip6 hoplimit 255 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept")
	line("    udp sport 67 udp dport 68 accept")
	line("    ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept")
	if c.Page {
		line(`    iifname "en*" ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } tcp dport { 80, 443 } accept`)
	}
	for _, d := range c.Devices {
		ports := make([]string, len(d.TCPPorts))
		for i, p := range d.TCPPorts {
			ports[i] = fmt.Sprint(p)
		}
		fam := "ip"
		if d.Addr.Is6() {
			fam = "ip6"
		}
		line("    %s saddr %s tcp dport { %s } accept", fam, d.Addr, strings.Join(ports, ", "))
	}
	for _, p := range c.Discovery {
		line("    udp dport %d accept", discoveryUDP[p])
	}
	line("    drop")
	line("  }")
	line("  chain forward {")
	line("    type filter hook forward priority filter; policy drop;")
	line("    iifname @%s accept", InboundExemptSet)
	line("    oifname @%s accept", InboundExemptSet)
	line("  }")
	line("}")
	line("table bridge %s {", InboundTable)
	line("  chain forward {")
	line("    type filter hook forward priority filter; policy drop;")
	line("  }")
	line("}")
	return b.String(), nil
}
