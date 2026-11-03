package nft

import (
	"fmt"
	"strings"
)

// A connection lives only while the ruleset in force would still admit its
// first packet (NET-3, NET-7). Each forward rule is written twice: once as
// it reads the packet, which decides a connection's first packet, and once
// in its live chain as it reads the connection's own record, the tuple of
// that first packet, which every later packet of the connection passes
// first. A load that removes a path therefore ends the connections open
// along it, in both directions, in the same transaction that removes the
// path; no conntrack entry needs deleting and none can be missed.
//
// The live form keeps every match, the allow sets slice f's resolver fills
// (CoreSet, DeviceSet) included: a load through Reload carries each set's
// answers for the names still listed, so a connection to an address only a
// dropped name answered ends with the load, and one to a kept name's goes
// on (ENF-set-keep-1).

// An accept binds its connection to the interfaces its first packet
// crossed: it sets the connection's mark to that interface pair, and its
// live form passes a later packet only on a connection with the same mark
// (#4286). Conntrack calls an ICMP error related to whichever connection
// its inner header names, whoever sent it; without the mark, a segment
// with its own path out of the same interface (any segment with internet
// access) could forge an error into another segment's internet connection
// and have it masqueraded to that connection's peer, or one into a
// device's connection from a paired device. With it, such an error matches
// no live accept and is dropped.
//
// The mark is the pair's interface numbers, the egress in the high 16 bits
// and the ingress in the low: a device interface is its VLAN (2 to 4094),
// the layout's own interfaces 0x1001 upwards in a fixed order. The numbers
// depend on nothing a load changes but the interfaces themselves, so a load
// that keeps a path keeps its connections' marks valid. Mark 0, which a
// connection has unless an accept set it (one opened before this ruleset
// was first loaded), matches no live accept.
//
// Bound to an interface pair, not to a host: two hosts on one segment
// (two guests, two people on Household) share their pair, so the mark
// cannot tell one's connection from the other's. On those shared segments
// (Guests, Owner, Household) a connection is bound to its host as well
// (#4324, #4480): the accept of its first packet, and of no later one,
// records the connection's conntrack ID and original source with the
// packet's source address and hardware address, in its segment's set
// (learn, HostSet; a conntrack label marks it recorded), and every later
// packet that enters from the segment in the connection's original
// direction passes only when its connection and its own source and
// hardware addresses give that same record (bound). Every packet from a
// shared segment also passes only from the hardware address that holds
// its source address (claim, ClaimSet). So another host on the segment
// cannot send into a host's connection, an ICMP error or a datagram from
// the host's address and port, unless it copies both that host's address
// and its hardware address, nor open a connection first on an address
// another host holds; the host's own packets pass. The host is always the
// side that starts the connection: no accept leads into a shared segment
// (bindAll), so no connection has a shared end its first packet did not
// come from.

// bind is the mark of a connection that enters on in and leaves on out,
// each a quoted interface name the ruleset uses; ok is false when either
// is not one interface of idx.
func bind(idx map[string]uint32, in, out string) (string, bool) {
	i, iok := idx[in]
	o, ook := idx[out]
	if !iok || !ook {
		return "", false
	}
	return fmt.Sprintf("0x%08x", o<<16|i), true
}

// rule is one rule of the forward or people chain.
type rule struct {
	in, out string  // iifname and oifname operands; "" matches any
	m       []match // further matches
	verdict string  // accept, drop, or jump <chain>
	mark    string  // an accept's connection mark (bind); "" otherwise
	learn   string  // an accept from a shared segment: the chain that records its host
	logged  string  // a logged rule: the chain that counts, logs and gives the verdict of its first packet (loggedDecls)
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
	if i := ifaces(r.in, r.out); i != "" {
		p = append(p, i)
	}
	for _, m := range r.m {
		p = append(p, m.pkt)
	}
	if r.mark != "" {
		p = append(p, "ct mark set "+r.mark)
	}
	verdict := r.verdict
	if r.learn != "" {
		verdict = "goto " + r.learn
	}
	if r.logged != "" {
		verdict = "goto " + r.logged
	}
	return strings.Join(append(p, verdict), " ")
}

// later is the rule as it reads a later packet's connection: in the
// original direction the packet crosses the interfaces the first packet
// did, in the reply direction the other way. Accept becomes return, so the
// packet goes on to be counted and accepted; a jump becomes a goto, so the
// target's return ends the live check too.
func (r rule) later() []string {
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
	if r.mark != "" {
		ms = append(ms, "ct mark "+r.mark)
	}
	tail := strings.Join(append(ms, verdict), " ")
	if r.in == "" && r.out == "" {
		return []string{tail}
	}
	return []string{
		"ct direction original " + ifaces(r.in, r.out) + " " + tail,
		"ct direction reply " + ifaces(r.out, r.in) + " " + tail,
	}
}

// ifaces is the interface part of a rule; "" for neither.
func ifaces(in, out string) string {
	var p []string
	if in != "" {
		p = append(p, "iifname "+in)
	}
	if out != "" {
		p = append(p, "oifname "+out)
	}
	return strings.Join(p, " ")
}

// bindAll sets the mark of every accept in rs, and refuses an accept that
// does not name one interface of idx each way: its connection could not be
// bound, so a related packet forged into it would pass on any interface
// its rule allows. An accept from a shared segment (shared maps each one's
// interface to its name) records its host (learn); one into a shared
// segment is refused, since its host there would not be the one that sent
// the first packet, so no record could bind it.
func bindAll(idx map[string]uint32, shared map[string]string, rs []rule) error {
	for i, r := range rs {
		if r.verdict != "accept" {
			continue
		}
		m, ok := bind(idx, r.in, r.out)
		if !ok {
			return fmt.Errorf("nft: an accept from %s to %s is not one interface each way", r.in, r.out)
		}
		if _, ok := shared[r.out]; ok {
			return fmt.Errorf("nft: an accept from %s leads into the shared segment %s", r.in, r.out)
		}
		rs[i].mark = m
		if seg, ok := shared[r.in]; ok {
			rs[i].learn = learn(seg)
		}
	}
	return nil
}
