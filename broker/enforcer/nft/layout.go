package nft

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

var ErrLayout = errors.New("nft: bad layout")

// Layout is the enforcer's own wiring: its interfaces, the access point's
// and the ISP router's addresses, and its service ports. It comes from the
// enforcer's image and setup, never from the core or the policy, and holds
// nothing the owner signs. Every field is checked before it reaches the
// ruleset text (Check).
type Layout struct {
	WAN       string // to the ISP router
	Owner     string // the Owner network's VLAN
	Household string
	Guests    string
	Admin     string // the wired admin port (NET-3, CH-9)
	Core      string // the core's enforcer segment (HW-12)
	Edge      string // the edge's enforcer segment
	// Trunk carries the Devices network from the access point, one VLAN
	// per device (D-225); a device's interface is Trunk.<VLAN>.
	Trunk string
	// APMgmt is the interface the access point's admin address is on, and
	// APAdmin that address: reachable only from the admin port.
	APMgmt  string
	APAdmin []netip.Addr
	// ISP is the ISP router's admin and LAN addresses, its external
	// address included: no segment reaches them (NET-1).
	ISP []netip.Prefix
	// EdgeGateway is the enforcer's one address on the edge's segment, the
	// only one it answers ARP for there (NET-2 Segments). The edge's
	// segment is IPv4 only: the enforcer answers no neighbour discovery
	// there and forwards no IPv6 from it.
	EdgeGateway  netip.Addr
	PagePort     uint16 // the enforcer's page (Owner and admin port only)
	ChannelPort  uint16 // the kernel's enforcer channel (core only)
	CorePagePort uint16 // the core's owner page (Owner and admin port only)
}

func (l Layout) ifaces() []string {
	return []string{l.WAN, l.Owner, l.Household, l.Guests, l.Admin, l.Core, l.Edge, l.Trunk, l.APMgmt}
}

// Check refuses a layout whose names or addresses could not be written
// safely into a ruleset, or whose interfaces collide.
func (l Layout) Check() error {
	names := l.ifaces()
	for i, n := range names {
		if !ifname(n) {
			return fmt.Errorf("%w: interface %q", ErrLayout, n)
		}
		if slices.Contains(names[:i], n) {
			return fmt.Errorf("%w: interface %q twice", ErrLayout, n)
		}
		// Trunk.* is every device's VLAN; nothing else may match it.
		if strings.HasPrefix(n, l.Trunk+".") {
			return fmt.Errorf("%w: interface %q is under the device trunk", ErrLayout, n)
		}
	}
	// A device interface is Trunk.<1-4 digits>; the trunk's name must
	// leave room for it within the kernel's 15 bytes.
	if len(l.Trunk) > 10 {
		return fmt.Errorf("%w: trunk %q too long for a VLAN interface", ErrLayout, l.Trunk)
	}
	if len(l.APAdmin) == 0 || len(l.ISP) == 0 || !l.EdgeGateway.Is4() {
		return fmt.Errorf("%w: access point, ISP router or edge gateway address missing", ErrLayout)
	}
	for _, a := range l.APAdmin {
		if !a.IsValid() || a.Is4In6() || a.Zone() != "" {
			return fmt.Errorf("%w: access point address %v", ErrLayout, a)
		}
	}
	for _, p := range l.ISP {
		if !p.IsValid() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
			return fmt.Errorf("%w: ISP prefix %v", ErrLayout, p)
		}
	}
	if l.PagePort == 0 || l.ChannelPort == 0 || l.CorePagePort == 0 || l.PagePort == l.ChannelPort {
		return fmt.Errorf("%w: ports", ErrLayout)
	}
	return nil
}

// ifname is a Linux interface name made only of characters that need no
// quoting in nft: 1 to 15 of [A-Za-z0-9_.-], not starting with a dot or dash.
func ifname(s string) bool {
	if s == "" || len(s) > 15 || s[0] == '.' || s[0] == '-' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// deviceIface is the interface of the Devices network's VLAN n: Trunk.n
// (D-225).
func (l Layout) deviceIface(n int) string { return l.Trunk + "." + strconv.Itoa(n) }

// DeviceIface is the interface of the device whose Wi-Fi identity is
// wifi; false if wifi names no VLAN.
func (l Layout) DeviceIface(wifi string) (string, bool) {
	n, ok := VLAN(wifi)
	if !ok {
		return "", false
	}
	return l.deviceIface(n), true
}
