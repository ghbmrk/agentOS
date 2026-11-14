package nft

// REQ: NET-3, NET-1

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// NET-3, NET-1 (#5726): on a shared segment (Guests, Owner, Household) a
// host's link-local address is held by its host, so another host cannot
// move the enforcer's neighbour entry for it and read the enforcer's
// answers to it (its DHCPv6 replies). On each segment, with the holds and
// the enforcer's entries cleared first:
//   - the second host, its lease taken away, sends to the enforcer from a
//     free link-local address: it takes no hold (lease);
//   - the first host queries the enforcer's resolver from its link-local
//     address and is answered, which holds the address with its hardware
//     address; the second host, leased again and holding nothing, then
//     sends from that address: it takes no hold (held);
//   - the second host sends from its own link-local address, which it
//     then holds, and from another free one: it takes no second hold (one
//     per hardware address);
//   - the first host's hold, cut to 3 s, is refreshed by its next query
//     and is still there 4 s later (refresh);
//   - the second host advertises the first host's address with its own
//     hardware address: the enforcer's entry stays at the first host's,
//     and the first host's next query is answered.
//
// Then five rulesets, each with one of these taken out, are loaded and the
// same steps run: without the ll jump the advertisement moves the entry to
// the second host (the harness sees the attack), and without each guard
// its step gives the second host the hold, or lets the first host's run
// out. So every rule of the ll chain fails a test.
func TestLinkLocalIsHeld(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	if !h.v6 {
		t.Skip("IPv6 only: the kernel has none")
	}
	d := cutPolicy()
	segs := []string{"guest", "owner", "household"}
	for _, seg := range segs {
		h.share(seg)
	}
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.settled(nil)
	// The hosts' own link-up reports (MLD) are sent from their link-local
	// addresses; let them end before any step.
	time.Sleep(2 * time.Second)

	type side struct {
		a, b, enf      string // link-local addresses: first host, second host, enforcer
		hwA, hwB, hwE  net.HardwareAddr
		elemA, elemB   string // the hosts' hardware addresses as NeighSet reads them
		ifc, nseg, seg string
	}
	sides := map[string]*side{}
	for _, seg := range segs {
		s := &side{seg: seg, ifc: segIfc(seg), nseg: nftSeg(seg)}
		s.a = linkLocal(t, h.in(h.hosts[seg], "ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "link"))
		s.b = linkLocal(t, h.in(h.hosts[seg+"2"], "ip", "-6", "-o", "addr", "show", "dev", "eth0", "scope", "link"))
		s.enf = linkLocal(t, run(t, "ip", "-6", "-o", "addr", "show", "dev", s.ifc, "scope", "link"))
		var err error
		if s.hwA, err = net.ParseMAC(h.mac(h.hosts[seg], "eth0")); err != nil {
			t.Fatal(err)
		}
		if s.hwB, err = net.ParseMAC(h.mac(h.hosts[seg+"2"], "eth0")); err != nil {
			t.Fatal(err)
		}
		f := strings.Fields(run(t, "ip", "-o", "link", "show", "dev", s.ifc))
		for i, w := range f {
			if w == "link/ether" && i+1 < len(f) {
				s.hwE, err = net.ParseMAC(f[i+1])
			}
		}
		if s.hwE == nil || err != nil {
			t.Fatalf("%s: no hardware address for %s", seg, s.ifc)
		}
		s.elemA, s.elemB = hwElem(hwInt(s.hwA)), hwElem(hwInt(s.hwB))
		sides[seg] = s
	}

	// spoof has the second host send a datagram from src to the
	// enforcer's link-local address, to a port nothing listens on, so
	// nothing answers it.
	spoof := func(s *side, src string) {
		t.Helper()
		h.frame(h.hosts[s.seg+"2"], 0x86dd, s.hwE, udp6(src, s.enf, 9801, 9, []byte("x")))
		time.Sleep(100 * time.Millisecond)
	}
	// query opens a UDP flow from the first host's link-local address to
	// the enforcer's resolver port (the harness's listener echoes it).
	query := func(s *side, first string) *flow {
		t.Helper()
		f := &flow{t: t, seen: map[string]bool{}}
		within(t, h.hosts[s.seg], func() {
			var err error
			if f.c, err = net.Dial("udp", "["+s.enf+"%eth0]:53"); err != nil {
				t.Fatal(err)
			}
		})
		t.Cleanup(func() { f.c.Close() })
		f.say(first)
		return f
	}
	nftSet := func(verb, set, elem string) {
		t.Helper()
		run(t, "nft", verb, "element", "inet", Table, set, "{ "+elem+" }")
	}

	type seen struct {
		unleased, held, second, refreshed bool
		entry                             string
	}
	steps := func(rules string, main bool) map[string]seen {
		t.Helper()
		h.load(withDrops(t, d, rules))
		h.fillSets()
		out := map[string]seen{}
		for _, seg := range segs {
			s, o := sides[seg], seen{}
			for _, set := range []string{NeighSet(s.nseg), NeighAddrSet(s.nseg), LinkLocalMACSet(s.nseg)} {
				run(t, "nft", "flush", "set", "inet", Table, set)
			}
			run(t, "ip", "-6", "neigh", "flush", "dev", s.ifc)

			// Lease: the second host, unleased, takes no free address.
			nftSet("delete", LeasedSet(s.nseg), s.elemB)
			spoof(s, "fe80::98")
			o.unleased = holds(NeighAddrSet(s.nseg), "fe80::98")
			nftSet("add", LeasedSet(s.nseg), s.elemB)

			// Held: the first host's query holds its address; the second
			// host, leased and holding nothing, takes no hold of it.
			f := query(s, "q1")
			if !f.heard("q1") {
				t.Fatalf("%s: the first host's query from its link-local address is not answered", seg)
			}
			spoof(s, s.a)
			o.held = holds(NeighSet(s.nseg), s.a+" . "+s.elemB)

			// One per hardware address: the second host holds its own
			// address, and then no other.
			spoof(s, s.b)
			if main && !holds(NeighSet(s.nseg), s.b+" . "+s.elemB) {
				t.Errorf("%s: the second host's packet from its own link-local address took no hold", seg)
			}
			spoof(s, "fe80::99")
			o.second = holds(NeighAddrSet(s.nseg), "fe80::99")

			// Refresh: the first host's hold, cut to 3 s, outlives them
			// once its next query passes.
			if holds(NeighSet(s.nseg), s.a+" . "+s.elemA) {
				nftSet("delete", NeighSet(s.nseg), s.a+" . "+s.elemA)
				nftSet("delete", NeighAddrSet(s.nseg), s.a)
				nftSet("delete", LinkLocalMACSet(s.nseg), s.elemA)
				nftSet("add", LinkLocalMACSet(s.nseg), s.elemA+" timeout 3s")
				nftSet("add", NeighAddrSet(s.nseg), s.a+" timeout 3s")
				nftSet("add", NeighSet(s.nseg), s.a+" . "+s.elemA+" timeout 3s")
				f.say("r1")
				if !f.heard("r1") {
					t.Errorf("%s: the first host's second query is not answered", seg)
				}
				time.Sleep(4 * time.Second)
				o.refreshed = holds(NeighSet(s.nseg), s.a+" . "+s.elemA)
			}

			// Take: the second host advertises the first host's address
			// with its own hardware address.
			na := append(binary.BigEndian.AppendUint32([]byte{136, 0, 0, 0}, 0x20000000), net.ParseIP(s.a).To16()...)
			h.frame(h.hosts[seg+"2"], 0x86dd, allNodes, icmp6(s.a, "ff02::1", append(na, append([]byte{2, 1}, s.hwB...)...)))
			time.Sleep(100 * time.Millisecond)
			o.entry = h.neighbour(s.ifc, s.a)
			if o.entry == s.hwA.String() {
				f.say("q2")
				if !f.heard("q2") {
					t.Errorf("%s: the first host's query after the advertisement was not answered to it", seg)
				}
			}
			out[seg] = o
		}
		return out
	}

	for seg, o := range steps(text, true) {
		s := sides[seg]
		if o.unleased {
			t.Errorf("%s: an unleased hardware address took a link-local hold", seg)
		}
		if o.held {
			t.Errorf("%s: the second host took the first host's held link-local address", seg)
		}
		if o.second {
			t.Errorf("%s: the second host took a second link-local hold", seg)
		}
		if !o.refreshed {
			t.Errorf("%s: the first host's query did not refresh its link-local hold", seg)
		}
		if o.entry != s.hwA.String() {
			t.Errorf("%s: after the second host's advertisement the enforcer's entry for %s names %q, want the first host's %s", seg, s.a, o.entry, s.hwA)
		}
	}

	// The mutants: each takes out one rule (the jump, or one line of each
	// segment's ll chain), and the step it guards then fails.
	cut := func(drop func(line string) bool, want int) string {
		t.Helper()
		var kept []string
		for _, ln := range strings.Split(text, "\n") {
			if !drop(strings.TrimSpace(ln)) {
				kept = append(kept, ln)
			}
		}
		if n := len(strings.Split(text, "\n")) - len(kept); n != want {
			t.Fatalf("the mutant took out %d lines, want %d", n, want)
		}
		return strings.Join(kept, "\n")
	}
	chainLine := func(f func(seg string) string) func(string) bool {
		return func(ln string) bool {
			for _, seg := range segs {
				if ln == f(nftSeg(seg)) {
					return true
				}
			}
			return false
		}
	}
	mutants := []struct {
		name  string
		rules string
		seen  func(s *side, o seen) bool // whether the harness sees the mutant
	}{
		{"no ll jump", cut(func(ln string) bool { return strings.HasPrefix(ln, "ip6 saddr fe80::/10 iifname vmap {") }, 1),
			func(s *side, o seen) bool { return o.entry == s.hwB.String() }},
		{"no lease check", cut(chainLine(func(n string) string { return "@ll,48,48 != @leased_" + n + " return" }), 3),
			func(s *side, o seen) bool { return o.unleased }},
		{"no held check", cut(chainLine(func(n string) string { return "ip6 saddr @neighaddr_" + n + "_6 return" }), 3),
			func(s *side, o seen) bool { return o.held }},
		{"no one-per-hardware-address check", cut(chainLine(func(n string) string { return "@ll,48,48 @llmac_" + n + "_6 return" }), 3),
			func(s *side, o seen) bool { return o.second }},
		{"no refresh", cut(func(ln string) bool {
			return strings.HasPrefix(ln, "ip6 saddr . @ll,48,48 @neigh_") && strings.Contains(ln, " update @llmac_")
		}, 3), func(s *side, o seen) bool { return !o.refreshed }},
	}
	for _, m := range mutants {
		for seg, o := range steps(m.rules, false) {
			if !m.seen(sides[seg], o) {
				t.Errorf("%s: under the mutant with %s the harness sees no difference (%+v): the test cannot catch it", seg, m.name, o)
			}
		}
	}
}

// linkLocal is the link-local address in one line of ip -6 -o addr show.
func linkLocal(t *testing.T, out string) string {
	t.Helper()
	f := strings.Fields(out)
	for i, w := range f {
		if w == "inet6" && i+1 < len(f) && strings.HasPrefix(f[i+1], "fe80:") {
			a, _, _ := strings.Cut(f[i+1], "/")
			return a
		}
	}
	t.Fatalf("no link-local address in %q", out)
	return ""
}

// udp6 is an IPv6 packet from src to dst, hop limit 64, carrying a UDP
// datagram from sport to dport with its checksum filled.
func udp6(src, dst string, sport, dport int, payload []byte) []byte {
	s, d := net.ParseIP(src).To16(), net.ParseIP(dst).To16()
	u := binary.BigEndian.AppendUint16(nil, uint16(sport))
	u = binary.BigEndian.AppendUint16(u, uint16(dport))
	u = binary.BigEndian.AppendUint16(u, uint16(8+len(payload)))
	u = append(append(u, 0, 0), payload...)
	pseudo := append(append(append([]byte(nil), s...), d...), binary.BigEndian.AppendUint32(nil, uint32(len(u)))...)
	pseudo = append(append(pseudo, 0, 0, 0, unix.IPPROTO_UDP), u...)
	c := csum(pseudo)
	if c == 0 {
		c = 0xffff // a zero UDP checksum over IPv6 is dropped (RFC 8200 8.1)
	}
	binary.BigEndian.PutUint16(u[6:], c)
	hdr := binary.BigEndian.AppendUint16([]byte{0x60, 0, 0, 0}, uint16(len(u)))
	hdr = append(append(append(hdr, unix.IPPROTO_UDP, 64), s...), d...)
	return append(hdr, u...)
}
