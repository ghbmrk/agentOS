package netguard

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// InboundTable is the nftables table InboundRules renders. It is separate
// from CH-9's agentos_ap table, which stays as it is: a drop in either
// table is final, so the two compose.
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

// Inbound configures the inbound rule set. The zero value of Devices and
// Discovery, empty at release, admits nothing beyond replies.
type Inbound struct {
	// Uplinks are the interfaces that face the home network. Required.
	Uplinks []string
	// Devices is the per-device allow hook.
	Devices []DeviceAllow
	// Discovery is the passive-discovery allow hook.
	Discovery []DiscoveryPort
}

// Validate says why the configuration cannot be rendered.
func (c Inbound) Validate() error {
	if len(c.Uplinks) == 0 {
		return errors.New("netguard: inbound needs at least one uplink interface")
	}
	for _, u := range c.Uplinks {
		if !ifaceRe.MatchString(u) {
			return fmt.Errorf("netguard: inbound uplink %q is not an interface name", u)
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

// InboundRules renders the nftables ruleset that drops every connection the
// home network opens to a box port (DEV-2 In). On each uplink interface it
// admits, in order: replies to what the box opened; the host's own link
// configuration (router and neighbour discovery from a link-local source,
// DHCPv4 and DHCPv6 replies from their server ports), which DEV-2 does not
// count as connections; the listed devices and discovery ports; and drops
// everything else. Traffic on any other interface, the access point's
// included, is left to CH-9's table.
func InboundRules(c Inbound) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	ups := append([]string(nil), c.Uplinks...)
	sort.Strings(ups)
	var b strings.Builder
	line := func(s string, a ...any) { fmt.Fprintf(&b, s+"\n", a...) }
	line("table inet %s {", InboundTable)
	line("  chain input {")
	line("    type filter hook input priority filter; policy accept;")
	for _, u := range ups {
		line(`    iifname "%s" ct state established,related accept`, u)
		line(`    iifname "%s" ip6 saddr fe80::/10 icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept`, u)
		line(`    iifname "%s" udp sport 67 udp dport 68 accept`, u)
		line(`    iifname "%s" ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept`, u)
		for _, d := range c.Devices {
			ports := make([]string, len(d.TCPPorts))
			for i, p := range d.TCPPorts {
				ports[i] = fmt.Sprint(p)
			}
			fam := "ip"
			if d.Addr.Is6() {
				fam = "ip6"
			}
			line(`    iifname "%s" %s saddr %s tcp dport { %s } accept`, u, fam, d.Addr, strings.Join(ports, ", "))
		}
		for _, p := range c.Discovery {
			line(`    iifname "%s" udp dport %d accept`, u, discoveryUDP[p])
		}
		line(`    iifname "%s" drop`, u)
	}
	line("  }")
	line("}")
	return b.String(), nil
}
