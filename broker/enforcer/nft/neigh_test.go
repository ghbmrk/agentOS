package nft

// REQ: NET-3, NET-1

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// NET-3, NET-1 (#4686): on a shared segment (Guests, Owner, Household)
// another host cannot move the enforcer's neighbour entry for an address a
// host holds, so the host's downstream packets stay its own. On each, the
// first host has an answered flow to the internet, and the second host
// names the first host's address with its own hardware address:
//   - IPv4: an unasked ARP reply and an ARP request from that address
//     leave the enforcer's entry at the first host's hardware address, and
//     the flow goes on;
//   - IPv6 (in CI): an override advertisement, a solicitation and a router
//     solicitation from that address, each with its link-layer option, and
//     an advertisement with another option before it (Linux reads the
//     first link-layer option wherever it is), leave the entry and the
//     flow;
//   - IPv6, a holder gone silent (#4702): the first host's hold runs out
//     (as after ClaimTimeout) and the second host takes the address with a
//     forwarded packet, but the first host's flow's record still names it,
//     so the second host's advertisement leaves the entry, and an answer
//     the internet sends on the flow after the takeover reaches the first
//     host.
//
// A load carries it: after one, both hosts' messages leave the entries.
// Then a ruleset with the ARP and neighbour discovery checks taken out is
// loaded, and the same ARP reply and advertisement move the entries to the
// second host: the harness sees the attack, so the checks are what stop
// it. Catches a missing or misplaced ARP or neighbour discovery check, one
// keyed by address alone, a neighbour hold that follows a taken-over
// claim, a check that reads a link-layer option the kernel does not, and
// a load that drops the leases' or the holds' copies.
func TestNeighboursFollowHolds(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	segs := []string{"guest", "owner", "household"}
	for _, seg := range segs {
		h.share(seg)
	}
	// share makes each segment's interface anew; the load after it binds
	// NeighTable's chains to the new ones on any kernel.
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, d, text))
	h.fillSets()
	fams := []bool{false}
	if h.v6 {
		fams = append(fams, true)
	}
	peerOf := func(v6 bool) string {
		if v6 {
			return net6Other
		}
		return netOther
	}
	for _, v6 := range fams {
		h.echo("isp", peerOf(v6))
		h.later("isp", peerOf(v6), 3*time.Second)
	}
	macA, macB := map[string]net.HardwareAddr{}, map[string]net.HardwareAddr{}
	for _, seg := range segs {
		ifc := segIfc(seg)
		// An ARP reply within locktime (1 s) of an entry's last change
		// does not move it; the test does not wait for that.
		if err := os.WriteFile("/proc/sys/net/ipv4/neigh/"+ifc+"/locktime", []byte("0"), 0); err != nil {
			t.Fatal(err)
		}
		b := h.hosts[seg+"2"]
		for _, x := range []*host{h.hosts[seg], b} {
			hw, err := net.ParseMAC(h.mac(x, "eth0"))
			if err != nil {
				t.Fatal(err)
			}
			if x == b {
				macB[seg] = hw
			} else {
				macA[seg] = hw
			}
		}
		// The second host reaches the enforcer from its own addresses
		// only, and sends from the first host's when told to.
		h.in(b, "sh", "-c", "echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce")
		h.in(b, "ip", "addr", "add", segAddr(seg, 0)+"/32", "dev", "lo")
		if h.v6 {
			h.in(b, "ip", "addr", "add", seg6Addr(seg, 0)+"/128", "dev", "lo", "nodad")
		}
	}
	addrOf := func(seg string, v6 bool) string {
		if v6 {
			return seg6Addr(seg, 0)
		}
		return segAddr(seg, 0)
	}
	// attack sends the second host's messages naming the first host's
	// address on seg: all of them, or only the plain ARP reply and
	// advertisement.
	attack := func(seg string, v6, all bool) {
		b, a, own := h.hosts[seg+"2"], addrOf(seg, v6), macB[seg]
		if !v6 {
			h.frame(b, 0x0806, bcast, arp(2, own, a, enfAddr(seg)))
			if all {
				h.frame(b, 0x0806, bcast, arp(1, own, a, enfAddr(seg)))
			}
			return
		}
		gw := seg6Net(seg) + "1"
		lla := func(typ byte) []byte { return append([]byte{typ, 1}, own...) }
		na := append(binary.BigEndian.AppendUint32([]byte{136, 0, 0, 0}, 0x20000000), net.ParseIP(a).To16()...)
		h.frame(b, 0x86dd, allNodes, icmp6(a, "ff02::1", append(na, lla(2)...)))
		if !all {
			return
		}
		ns := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, net.ParseIP(gw).To16()...)
		h.frame(b, 0x86dd, multicast6(solicited(gw)), icmp6(a, solicited(gw), append(ns, lla(1)...)))
		h.frame(b, 0x86dd, allRouters, icmp6(a, "ff02::2", append([]byte{133, 0, 0, 0, 0, 0, 0, 0}, lla(1)...)))
		nonce := []byte{14, 1, 1, 2, 3, 4, 5, 6}
		h.frame(b, 0x86dd, allNodes, icmp6(a, "ff02::1", append(append(na, nonce...), lla(2)...)))
	}
	// kept checks the enforcer's entry for the first host's address on
	// seg still names the first host's hardware address.
	kept := func(seg string, v6 bool, why string) {
		t.Helper()
		time.Sleep(100 * time.Millisecond)
		if got := h.neighbour(segIfc(seg), addrOf(seg, v6)); got != macA[seg].String() {
			t.Errorf("%s (v6 %v), %s: the enforcer's entry for %s names %q, want the first host's %s", seg, v6, why, addrOf(seg, v6), got, macA[seg])
		}
	}

	type open struct {
		seg string
		v6  bool
		f   *flow
	}
	var flows []open
	for _, v6 := range fams {
		for _, seg := range segs {
			why := fmt.Sprintf("%s (v6 %v)", seg, v6)
			f := h.udpFlow(seg, peerOf(v6), 0, "first")
			if !f.heard("first") {
				t.Fatalf("%s: the first host's flow is not answered", why)
			}
			attack(seg, v6, true)
			kept(seg, v6, "after the second host's messages")
			f.say("after")
			if !f.heard("after") {
				t.Errorf("%s: the first host's flow stopped after the second host's messages", why)
			}
			flows = append(flows, open{seg, v6, f})
		}
	}

	// A holder gone silent: its hold is taken, its flow's record lives.
	if h.v6 {
		for _, seg := range segs {
			why := seg + " (v6), a silent holder"
			a := seg6Addr(seg, 0)
			late := h.udpFlowTo(seg, peerOf(true), laterPort, "late")
			h.move(seg, a, macA[seg].String(), macB[seg].String(), true)
			h.injectTo(seg+"2", a, 9800, peerOf(true), laterPort, "take")
			if !holds(ClaimSet(nftSeg(seg)), a+" . "+macB[seg].String()) {
				t.Fatalf("%s: the second host did not take the address's hold", why)
			}
			attack(seg, true, false)
			kept(seg, true, "after the second host took the address")
			if !late.heardWithin("late", 5*time.Second) {
				t.Errorf("%s: the internet's answer on the first host's flow, sent after the takeover, did not reach it", why)
			}
			h.move(seg, a, macB[seg].String(), macA[seg].String(), true)
		}
	}

	// A load carries the leases' copies and the neighbour holds.
	h.reload(d)
	h.fillSets()
	for _, k := range flows {
		attack(k.seg, k.v6, true)
		kept(k.seg, k.v6, "after a load")
		k.f.say("carried")
		if !k.f.heard("carried") {
			t.Errorf("%s (v6 %v): the first host's flow stopped after a load", k.seg, k.v6)
		}
	}

	// The mutant: no ARP or neighbour discovery check.
	var cut []string
	for _, ln := range strings.Split(text, "\n") {
		if s := strings.TrimSpace(ln); !strings.HasPrefix(s, "meta protocol arp ") && !strings.Contains(s, " jump nd_") {
			cut = append(cut, ln)
		}
	}
	if n := len(strings.Split(text, "\n")) - len(cut); n != 9 {
		t.Fatalf("the mutant took out %d lines, want 9", n)
	}
	h.load(withDrops(t, d, strings.Join(cut, "\n")))
	h.fillSets()
	for _, v6 := range fams {
		for _, seg := range segs {
			f := h.udpFlow(seg, peerOf(v6), 0, "mutant")
			if !f.heard("mutant") {
				t.Fatalf("%s (v6 %v): the first host's flow is not answered under the mutant", seg, v6)
			}
			attack(seg, v6, false)
			time.Sleep(100 * time.Millisecond)
			if got := h.neighbour(segIfc(seg), addrOf(seg, v6)); got != macB[seg].String() {
				t.Errorf("%s (v6 %v): with the checks taken out, the second host's message left the entry at %q, want %s: the test cannot see the attack", seg, v6, got, macB[seg])
			}
		}
	}
}

// Link-layer destinations: broadcast, all nodes, all routers.
var (
	bcast      = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	allNodes   = multicast6("ff02::1")
	allRouters = multicast6("ff02::2")
)

// multicast6 is the hardware address of IPv6 group g (RFC 2464 7).
func multicast6(g string) net.HardwareAddr {
	ip := net.ParseIP(g).To16()
	return net.HardwareAddr{0x33, 0x33, ip[12], ip[13], ip[14], ip[15]}
}

// solicited is a's solicited-node group (RFC 4291 2.7.1).
func solicited(a string) string {
	ip := net.ParseIP(a).To16()
	return net.IP{0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, ip[13], ip[14], ip[15]}.String()
}

// arp is an Ethernet IPv4 ARP message of operation op from hardware
// address sha and address spa, about address tpa.
func arp(op uint16, sha net.HardwareAddr, spa, tpa string) []byte {
	b := binary.BigEndian.AppendUint16([]byte{0, 1, 8, 0, 6, 4}, op)
	b = append(append(b, sha...), net.ParseIP(spa).To4()...)
	return append(append(b, make([]byte, 6)...), net.ParseIP(tpa).To4()...)
}

// icmp6 is an IPv6 packet from src to dst, hop limit 255, carrying ICMPv6
// message m with its checksum filled.
func icmp6(src, dst string, m []byte) []byte {
	s, d := net.ParseIP(src).To16(), net.ParseIP(dst).To16()
	m = append([]byte(nil), m...)
	pseudo := append(append(append([]byte(nil), s...), d...), binary.BigEndian.AppendUint32(nil, uint32(len(m)))...)
	pseudo = append(append(pseudo, 0, 0, 0, unix.IPPROTO_ICMPV6), m...)
	binary.BigEndian.PutUint16(m[2:], csum(pseudo))
	hdr := binary.BigEndian.AppendUint16([]byte{0x60, 0, 0, 0}, uint16(len(m)))
	hdr = append(append(append(hdr, unix.IPPROTO_ICMPV6, 255), s...), d...)
	return append(hdr, m...)
}

// frame sends payload of Ethernet type proto from host x's eth0 to
// hardware address dst; the kernel writes x's own as the source.
func (h *home) frame(x *host, proto uint16, dst net.HardwareAddr, payload []byte) {
	t := h.t
	t.Helper()
	within(t, x, func() {
		ifc, err := net.InterfaceByName("eth0")
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, 0) // sends only
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		to := &unix.SockaddrLinklayer{Protocol: proto<<8 | proto>>8, Ifindex: ifc.Index, Halen: 6}
		copy(to.Addr[:], dst)
		if err := unix.Sendto(fd, payload, 0, to); err != nil {
			t.Fatal(err)
		}
	})
}

// neighbour is the hardware address the enforcer's entry for addr on ifc
// names, or "" for none.
func (h *home) neighbour(ifc, addr string) string {
	f := strings.Fields(run(h.t, "ip", "neigh", "show", addr, "dev", ifc))
	for i, w := range f {
		if w == "lladdr" && i+1 < len(f) {
			return f[i+1]
		}
	}
	return ""
}

// laterPort is the UDP port later listens on.
const laterPort = 9124

// later answers every datagram to addr's laterPort in host on, wait after
// it arrives.
func (h *home) later(on, addr string, wait time.Duration) {
	t := h.t
	within(t, h.hosts[on], func() {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, strconv.Itoa(laterPort)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 1500)
			for {
				n, from, err := pc.ReadFrom(buf)
				if err != nil {
					return
				}
				msg := append([]byte(nil), buf[:n]...)
				time.AfterFunc(wait, func() { pc.WriteTo(msg, from) })
			}
		}()
	})
}

// udpFlowTo is udpFlow to peer's port.
func (h *home) udpFlowTo(from, peer string, port int, first string) *flow {
	t := h.t
	t.Helper()
	f := &flow{t: t, seen: map[string]bool{}}
	within(t, h.hosts[from], func() {
		var err error
		if f.c, err = net.Dial("udp", net.JoinHostPort(peer, strconv.Itoa(port))); err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { f.c.Close() })
	f.say(first)
	return f
}

// injectTo is inject to peer's port.
func (h *home) injectTo(from, local string, lport int, peer string, port int, msg string) {
	t := h.t
	t.Helper()
	within(t, h.hosts[from], func() {
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(local), Port: lport}}
		c, err := d.Dial("udp", net.JoinHostPort(peer, strconv.Itoa(port)))
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(msg))
		c.Close()
	})
	time.Sleep(100 * time.Millisecond)
}

// heardWithin is heard, waiting up to wait.
func (f *flow) heardWithin(msg string, wait time.Duration) bool {
	f.c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 64)
	for !f.seen[msg] {
		n, err := f.c.Read(buf)
		if err != nil {
			break
		}
		f.seen[string(buf[:n])] = true
	}
	return f.seen[msg]
}

// holds is whether set holds element key, written as nft writes it.
func holds(set, key string) bool {
	return exec.Command("nft", "get", "element", "inet", Table, set, "{ "+key+" }").Run() == nil
}
