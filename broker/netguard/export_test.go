package netguard

import "net/netip"

// Gateway4 returns the default gateway in /proc/net/route text: the
// lowest-metric row whose destination and mask are zero.
func Gateway4(table string) netip.Addr {
	gw, _ := gateway4(table)
	return gw
}

// Gateway6 returns the default gateway in /proc/net/ipv6_route text: the
// lowest-metric row whose destination prefix length is zero.
func Gateway6(table string) netip.Addr {
	gw, _ := gateway6(table)
	return gw
}
