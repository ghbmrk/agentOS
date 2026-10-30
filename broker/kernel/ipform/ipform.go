// Package ipform gives every IPv4 address an IPv6 address can carry a
// connection to, so a check on an IPv4 address (a decoy, a private range)
// cannot be passed by naming it as IPv6 (KRN-12, DEV-2). The kernel's plan
// check and netguard's connect-time check share it.
package ipform

import "net/netip"

// The IPv6 prefixes through which an IPv4 destination can be named: the
// well-known and local-use NAT64 prefixes (RFC 6052, RFC 8215), SIIT's
// IPv4-translated prefix (RFC 6145), 6to4 (RFC 3056) and Teredo (RFC 4380).
var (
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")
	siit       = netip.MustParsePrefix("::ffff:0:0:0/96")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	teredo     = netip.MustParsePrefix("2001::/32")
)

// Forms is a without its zone, then every IPv4 address it embeds:
// IPv4-mapped (alone, unmapped), IPv4-compatible, NAT64 (well-known, and
// local-use at its /48 and /96 positions), SIIT IPv4-translated, 6to4,
// ISATAP and Teredo (its server and its client).
func Forms(a netip.Addr) []netip.Addr {
	a = a.WithZone("").Unmap()
	out := []netip.Addr{a}
	if !a.Is6() {
		return out
	}
	b := a.As16()
	v4 := func(i, j, k, l int) netip.Addr { return netip.AddrFrom4([4]byte{b[i], b[j], b[k], b[l]}) }
	tail := v4(12, 13, 14, 15)
	switch {
	case nat64.Contains(a), siit.Contains(a):
		out = append(out, tail)
	case nat64Local.Contains(a):
		out = append(out, tail, v4(6, 7, 9, 10))
	case sixToFour.Contains(a):
		out = append(out, v4(2, 3, 4, 5))
	case teredo.Contains(a):
		out = append(out, v4(4, 5, 6, 7), netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}))
	case [12]byte(b[:12]) == [12]byte{}:
		out = append(out, tail) // IPv4-compatible
	}
	if (b[8] == 0 || b[8] == 2) && b[9] == 0 && b[10] == 0x5e && b[11] == 0xfe { // ISATAP
		out = append(out, tail)
	}
	return out
}
