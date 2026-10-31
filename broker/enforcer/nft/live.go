package nft

import "strings"

// A connection lives only while the ruleset in force would still admit its
// first packet (NET-3, NET-7). Each forward rule is written twice: once as
// it reads the packet, which decides a connection's first packet, and once
// in its live chain as it reads the connection's own record, the tuple of
// that first packet, which every later packet of the connection passes
// first. A load that removes a path therefore ends the connections open
// along it, in both directions, in the same transaction that removes the
// path; no conntrack entry needs deleting and none can be missed.
//
// The live form keeps every match but one: an allow set that slice f's
// resolver fills (CoreSet, DeviceSet). A load empties those sets and the
// resolver refills them as devices ask again (ENF-e-3, ENF-f-3), so the
// live form checks only the address family there; the path itself (the
// device's internet, the core's list) is still checked.

// rule is one rule of the forward or people chain.
type rule struct {
	in, out string  // iifname and oifname operands; "" matches any
	m       []match // further matches
	tail    string  // the log and counter part, on the first form only
	verdict string  // accept, drop, or jump <chain>
}

// match is one match in its two forms: on the packet, and on the
// connection's original tuple.
type match struct{ pkt, ct string }

// live names the live chain of a chain.
func live(chain string) string { return chain + "_live" }

func daddr(v6 bool, expr string) match {
	f := family(v6)
	return match{f + " daddr " + expr, "ct original " + f + " daddr " + expr}
}

// resolved is a destination in an allow set the resolver fills; its live
// form checks the family only.
func resolved(v6 bool, set string) match {
	nf := map[bool]string{false: "ipv4", true: "ipv6"}[v6]
	return match{family(v6) + " daddr @" + set, "meta nfproto " + nf}
}

// l4Ports matches destination ports of one protocol; ports is one port or
// an anonymous set.
func l4Ports(proto, ports string) match {
	return match{proto + " dport " + ports, "ct protocol " + proto + " ct original proto-dst " + ports}
}

func family(v6 bool) string {
	if v6 {
		return "ip6"
	}
	return "ip"
}

// first is the rule as it reads a connection's first packet.
func (r rule) first() string {
	var p []string
	if r.in != "" {
		p = append(p, "iifname "+r.in)
	}
	if r.out != "" {
		p = append(p, "oifname "+r.out)
	}
	for _, m := range r.m {
		p = append(p, m.pkt)
	}
	if r.tail != "" {
		p = append(p, r.tail)
	}
	return strings.Join(append(p, r.verdict), " ")
}

// live is the rule as it reads a later packet's connection: in the
// original direction the packet crosses the interfaces the first packet
// did, in the reply direction the other way. Accept becomes return, so the
// packet goes on to be counted and accepted; a jump becomes a goto, so the
// target's return ends the live check too.
func (r rule) live() []string {
	verdict := r.verdict
	switch {
	case verdict == "accept":
		verdict = "return"
	case strings.HasPrefix(verdict, "jump "):
		verdict = "goto " + live(strings.TrimPrefix(verdict, "jump "))
	}
	var ms []string
	for _, m := range r.m {
		ms = append(ms, m.ct)
	}
	tail := strings.Join(append(ms, verdict), " ")
	if r.in == "" && r.out == "" {
		return []string{tail}
	}
	ifs := func(in, out string) string {
		var p []string
		if in != "" {
			p = append(p, "iifname "+in)
		}
		if out != "" {
			p = append(p, "oifname "+out)
		}
		return strings.Join(p, " ")
	}
	return []string{
		"ct direction original " + ifs(r.in, r.out) + " " + tail,
		"ct direction reply " + ifs(r.out, r.in) + " " + tail,
	}
}
