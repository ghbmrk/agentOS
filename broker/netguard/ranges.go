// Package netguard is the home-network address policy (DEV-2, REV-5, ARC-6,
// CAP-2, CAP-13, PLAN DEV-net-a).
//
// Every outbound dialer of the broker's own components checks the address
// it is about to connect to, after resolution, against one small policy: no
// non-global address (the IANA special-purpose registries, plus the IPv4
// and IPv6 forms that embed an IPv4 address), none of the uplink's or the
// access point's prefixes, not the learned gateway, not the router's
// external address. Exactly four things are excepted, each matched as
// stated in DEV-2; see Policy.Check.
//
// The check runs where the connection is made: Policy.DialContext resolves
// the name itself, checks every answer, and connects to a literal address
// whose net.Dialer carries the same check as its ControlContext hook, so a
// name that answers differently the second time (rebinding) is checked
// again. A CI check (tools/netguardcheck.py) fails any dialer that does
// not use it.
package netguard

import (
	"net/netip"

	"github.com/ghbmrk/agentos/broker/kernel/ipform"
)

type rng struct {
	prefix netip.Prefix
	name   string
}

func mustRanges(rows [][2]string) []rng {
	out := make([]rng, 0, len(rows))
	for _, r := range rows {
		out = append(out, rng{netip.MustParsePrefix(r[0]), r[1]})
	}
	return out
}

// special4 is the IANA IPv4 Special-Purpose Address Registry, plus
// multicast. Entries the registry marks globally reachable (192.0.0.9/32,
// 192.31.196.0/24, 192.52.193.0/24, 192.175.48.0/24) are denied too: the
// home network gains nothing from them and a broader range is simpler to
// state.
var special4 = mustRanges([][2]string{
	{"0.0.0.0/8", "this network"},
	{"10.0.0.0/8", "private use"},
	{"100.64.0.0/10", "shared address space"},
	{"127.0.0.0/8", "loopback"},
	{"169.254.0.0/16", "link local"},
	{"172.16.0.0/12", "private use"},
	{"192.0.0.0/24", "IETF protocol assignments"},
	{"192.0.2.0/24", "documentation"},
	{"192.31.196.0/24", "AS112-v4"},
	{"192.52.193.0/24", "AMT"},
	{"192.88.99.0/24", "6to4 relay anycast"},
	{"192.168.0.0/16", "private use"},
	{"192.175.48.0/24", "direct delegation AS112"},
	{"198.18.0.0/15", "benchmarking"},
	{"198.51.100.0/24", "documentation"},
	{"203.0.113.0/24", "documentation"},
	{"224.0.0.0/4", "multicast"},
	{"240.0.0.0/4", "reserved and limited broadcast"},
})

// special6 is the IANA IPv6 Special-Purpose Address Registry, plus the
// reserved ::/8 (unspecified, loopback, IPv4-compatible) and multicast.
// IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96), 6to4 and ISATAP forms
// are unwrapped first (see forms); 6to4 is denied as a whole.
var special6 = mustRanges([][2]string{
	{"::/8", "unspecified, loopback, IPv4-compatible"},
	{"64:ff9b:1::/48", "local-use NAT64"},
	{"100::/64", "discard only"},
	{"2001::/23", "IETF protocol assignments (Teredo, benchmarking, ORCHID, AMT, AS112)"},
	{"2001:db8::/32", "documentation"},
	{"2002::/16", "6to4"},
	{"2620:4f:8000::/48", "direct delegation AS112"},
	{"3fff::/20", "documentation"},
	{"5f00::/16", "SRv6 SIDs"},
	{"fc00::/7", "unique local"},
	{"fe80::/10", "link local"},
	{"fec0::/10", "site local (deprecated)"},
	{"ff00::/8", "multicast"},
})

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// forms is the address and every IPv4 address it embeds (ipform.Forms).
// Each is checked, so an embedded private or decoy address cannot hide in a
// global-looking IPv6 one.
var forms = ipform.Forms

// Special reports whether a is not a global unicast address by the IANA
// special-purpose registries, and which entry says so. An address that
// embeds an IPv4 address is special if either form is.
func Special(a netip.Addr) (string, bool) {
	if !a.IsValid() {
		return "invalid address", true
	}
	for _, f := range forms(a) {
		table := special6
		if f.Is4() {
			table = special4
		}
		for _, r := range table {
			if r.prefix.Contains(f) {
				if r.prefix.Bits() == 8 && nat64.Contains(f) {
					continue // 64:ff9b::/96 sits inside ::/8; its embedded v4 form decides
				}
				return r.name, true
			}
		}
	}
	return "", false
}
