package nft

// REQ: NET-3, NET-1

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// NET-3, NET-1 (#5686): on a shared segment (Guests, Owner, Household) an
// IPv6 address that speaks only to the enforcer itself is held by its
// host, so another host cannot take its neighbour entry and read the
// enforcer's answers to it. On each, the first host sends DNS to the
// enforcer's resolver port over IPv6 and nothing else; the second host
// then sends a forwarded packet from the first host's address and an
// override advertisement naming it with its own hardware address. The
// forwarded packet takes no hold, the enforcer's entry stays at the first
// host's hardware address, and the first host's next query is answered.
// Then a ruleset without the input-side claim is loaded, and the same
// steps give the second host the address's hold and move the entry to it:
// the harness sees the attack, so the input-side claim is what stops it.
// Catches a hold taken only by forwarded packets, and an input-side claim
// that neighbour discovery from the second host's own address could take
// (the advertisement is accepted before the claim).
func TestEnforcerOnlyAddressIsHeld(t *testing.T) {
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
	h.load(withDrops(t, d, text))
	h.fillSets()
	h.echo("isp", net6Other)
	macA, macB := map[string]string{}, map[string]string{}
	for _, seg := range segs {
		for i, m := range []map[string]string{macA, macB} {
			hw, err := net.ParseMAC(h.mac(h.hosts[[]string{seg, seg + "2"}[i]], "eth0"))
			if err != nil {
				t.Fatal(err)
			}
			m[seg] = hw.String()
		}
		// The second host sends from the first host's address only when
		// told to.
		h.in(h.hosts[seg+"2"], "ip", "addr", "add", seg6Addr(seg, 0)+"/128", "dev", "lo", "nodad")
	}
	// dns opens a UDP flow from seg's first host to the enforcer's
	// resolver port on the segment (the harness's listener echoes it).
	dns := func(seg, first string) *flow {
		t.Helper()
		f := &flow{t: t, seen: map[string]bool{}}
		within(t, h.hosts[seg], func() {
			var err error
			if f.c, err = net.Dial("udp", "["+seg6Net(seg)+"1]:53"); err != nil {
				t.Fatal(err)
			}
		})
		t.Cleanup(func() { f.c.Close() })
		f.say(first)
		return f
	}
	// take has the second host forward a packet from the first host's
	// address and then advertise that address with its own hardware
	// address.
	take := func(seg string) {
		t.Helper()
		a, b := seg6Addr(seg, 0), h.hosts[seg+"2"]
		h.inject(seg+"2", a, 9801, net6Other, "take")
		time.Sleep(100 * time.Millisecond)
		own, err := net.ParseMAC(macB[seg])
		if err != nil {
			t.Fatal(err)
		}
		na := append(binary.BigEndian.AppendUint32([]byte{136, 0, 0, 0}, 0x20000000), net.ParseIP(a).To16()...)
		h.frame(b, 0x86dd, allNodes, icmp6(a, "ff02::1", append(na, append([]byte{2, 1}, own...)...)))
		time.Sleep(100 * time.Millisecond)
	}

	for _, seg := range segs {
		a := seg6Addr(seg, 0)
		f := dns(seg, "q1")
		if !f.heard("q1") {
			t.Fatalf("%s: the first host's query to the enforcer is not answered", seg)
		}
		if !holds(ClaimSet(nftSeg(seg)), a+" . "+macA[seg]) {
			t.Errorf("%s: the first host's query to the enforcer took no hold of its address", seg)
		}
		take(seg)
		if holds(ClaimSet(nftSeg(seg)), a+" . "+macB[seg]) {
			t.Errorf("%s: the second host's forwarded packet took the first host's address", seg)
		}
		if got := h.neighbour(segIfc(seg), a); got != macA[seg] {
			t.Errorf("%s: after the second host's advertisement the enforcer's entry for %s names %q, want the first host's %s", seg, a, got, macA[seg])
		}
		f.say("q2")
		if !f.heard("q2") {
			t.Errorf("%s: the first host's next query was not answered to it", seg)
		}
	}

	// The mutant: no input-side claim.
	var cut []string
	for _, ln := range strings.Split(text, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(ln), "ip6 saddr != { ::, fe80::/10 } iifname vmap {") {
			cut = append(cut, ln)
		}
	}
	if n := len(strings.Split(text, "\n")) - len(cut); n != 1 {
		t.Fatalf("the mutant took out %d lines, want 1", n)
	}
	h.load(withDrops(t, d, strings.Join(cut, "\n")))
	h.fillSets()
	for _, seg := range segs {
		a := seg6Addr(seg, 0)
		f := dns(seg, "m1")
		if !f.heard("m1") {
			t.Fatalf("%s: the first host's query is not answered under the mutant", seg)
		}
		take(seg)
		if !holds(ClaimSet(nftSeg(seg)), a+" . "+macB[seg]) {
			t.Errorf("%s: without the input-side claim the second host did not take the address: the test cannot see the attack", seg)
		}
		if got := h.neighbour(segIfc(seg), a); got != macB[seg] {
			t.Errorf("%s: without the input-side claim the entry for %s names %q, want the second host's %s: the test cannot see the attack", seg, a, got, macB[seg])
		}
	}
}
