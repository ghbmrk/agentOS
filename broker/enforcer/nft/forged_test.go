package nft

// REQ: NET-3

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"testing"
)

// icmpErr is an ICMP or ICMPv6 "packet too big" error (IPv4: destination
// unreachable, fragmentation needed) about the TCP packet src:sport ->
// dst:dport, with mtu as its next-hop MTU, which the tests use as the
// error's tag. The IPv4 checksum is filled here; the kernel fills ICMPv6's.
func icmpErr(v6 bool, mtu uint16, src, dst string, sport, dport int) []byte {
	s, d := net.ParseIP(src), net.ParseIP(dst)
	var b []byte
	if v6 {
		b = []byte{2, 0, 0, 0, 0, 0, byte(mtu >> 8), byte(mtu)}
		in := make([]byte, 40)
		in[0] = 0x60
		binary.BigEndian.PutUint16(in[4:], 20)
		in[6], in[7] = 6, 64
		copy(in[8:], s.To16())
		copy(in[24:], d.To16())
		b = append(b, in...)
	} else {
		b = []byte{3, 4, 0, 0, 0, 0, byte(mtu >> 8), byte(mtu)}
		in := make([]byte, 20)
		in[0] = 0x45
		binary.BigEndian.PutUint16(in[2:], 40)
		in[8], in[9] = 64, 6
		copy(in[12:], s.To4())
		copy(in[16:], d.To4())
		binary.BigEndian.PutUint16(in[10:], csum(in))
		b = append(b, in...)
	}
	tcp := make([]byte, 8)
	binary.BigEndian.PutUint16(tcp[0:], uint16(sport))
	binary.BigEndian.PutUint16(tcp[2:], uint16(dport))
	b = append(b, tcp...)
	if !v6 {
		binary.BigEndian.PutUint16(b[2:], csum(b))
	}
	return b
}

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

func icmpNet(v6 bool) string {
	if v6 {
		return "ip6:ipv6-icmp"
	}
	return "ip4:icmp"
}

// sendErr sends pkt from host from (bound to its address bind, "" for the
// route's choice) to addr.
func (h *home) sendErr(from, bind, addr string, v6 bool, pkt []byte) {
	t := h.t
	t.Helper()
	within(t, h.hosts[from], func() {
		c, err := net.ListenPacket(icmpNet(v6), bind)
		if err != nil {
			t.Fatalf("%s: raw socket: %v", from, err)
		}
		defer c.Close()
		if _, err := c.WriteTo(pkt, &net.IPAddr{IP: net.ParseIP(addr)}); err != nil {
			t.Fatalf("%s: send to %s: %v", from, addr, err)
		}
	})
}

// tags is what an ICMP listener in one host has heard: the tag (next-hop
// MTU) of every packet-too-big error.
type tags struct {
	mu  sync.Mutex
	got map[uint16]bool
}

func (g *tags) has(tag uint16) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.got[tag]
}

// hear listens for packet-too-big errors in host on until the test ends.
func (h *home) hear(on string, v6 bool) *tags {
	t := h.t
	g := &tags{got: map[uint16]bool{}}
	within(t, h.hosts[on], func() {
		c, err := net.ListenPacket(icmpNet(v6), "")
		if err != nil {
			t.Fatalf("%s: raw socket: %v", on, err)
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			buf := make([]byte, 1500)
			for {
				n, _, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				if n >= 8 && ((!v6 && buf[0] == 3 && buf[1] == 4) || (v6 && buf[0] == 2)) {
					g.mu.Lock()
					g.got[binary.BigEndian.Uint16(buf[6:])] = true
					g.mu.Unlock()
				}
			}
		}()
	})
	return g
}

func hostPort(t *testing.T, a net.Addr) (string, int) {
	t.Helper()
	host, p, err := net.SplitHostPort(a.String())
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return host, n
}

// seg6 gives segment host seg an IPv6 address and default route, which
// the fixture leaves out: only the devices have IPv6 there. The edge is
// never given one, since its segment is IPv4 only (ENF-e-6).
func (h *home) seg6(seg string) {
	l := fixtureLayout()
	ifc := map[string]string{"owner": l.Owner, "household": l.Household, "guest": l.Guests, "core": l.Core}[seg]
	p := "fd10:" + strings.Split(segNets[seg], ".")[1] + "::"
	run(h.t, "ip", "addr", "add", p+"1/64", "dev", ifc, "nodad")
	h.in(h.hosts[seg], "ip", "addr", "add", p+"2/64", "dev", "eth0", "nodad")
	h.in(h.hosts[seg], "ip", "-6", "route", "add", "default", "via", p+"1")
}

// NET-3, NET-2 Device paths (#4286, #4367): a related packet passes only on
// the interfaces of the connection it names, in either direction and over
// either family. Every segment with an internet path forges an ICMP error,
// as conntrack reads it related to the TV's open internet connection: one
// in the original direction, sent toward the TV's peer, and one in the
// reply direction, sent to the enforcer's WAN address, which the NAT turns
// back toward the TV. None arrives, though each original-direction forger's
// own internet rule matches its error's interfaces. In the reply direction
// the speaker, which the core reaches, forges an error into the core's
// internet connection: the reply form of the core's rule to the speaker
// matches its interfaces and port, so only the mark stops it. Genuine
// errors on a connection's own path (path MTU, from the peer back to the TV
// and to the core) still arrive, and so does the plug's error about its own
// internet connection, which shows the forgers' channel works and the drop
// is the binding.
func TestForgedRelatedDropped(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	text, err := Compile(cutPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	h.fillSets()
	run(t, "nft", "add", "element", "inet", Table, DeviceSet(103, false), "{ "+netAllow+" }")
	type fam struct {
		v6                bool
		allow, wan, cored string
	}
	fams := []fam{{false, netAllow, enfWAN, netCore}}
	if h.v6 {
		run(t, "nft", "add", "element", "inet", Table, DeviceSet(103, true), "{ "+net6Allow+" }")
		run(t, "nft", "add", "element", "inet", Table, CoreSet(true), "{ "+net6Allow+" }")
		for _, seg := range []string{"owner", "household", "guest", "core"} {
			h.seg6(seg)
		}
		fams = append(fams, fam{true, net6Allow, "2001:db8:1::2", net6Allow})
	}
	forgers := []string{"103", "guest", "owner", "household", "core", "edge"}
	for _, f := range fams {
		tvAddr, plugAddr := devAddr(101), devAddr(103)
		if f.v6 {
			tvAddr, plugAddr = devAddr6(101), devAddr6(103)
		}
		atPeer, atTV, atCore := h.hear("isp", f.v6), h.hear("101", f.v6), h.hear("core", f.v6)
		tv := h.hold("the TV to its allow list", "101", "isp", f.allow, 9211)
		plug := h.hold("the plug to its allow list", "103", "isp", f.allow, 9212)
		core := h.hold("the core to its list", "core", "isp", f.cored, 9100)
		_, tvPort := hostPort(t, tv.c.LocalAddr())
		_, plugPort := hostPort(t, plug.c.LocalAddr())
		mWAN, tvMasq := hostPort(t, tv.s.RemoteAddr())
		_, coreMasq := hostPort(t, core.s.RemoteAddr())

		// The forgeries. Original direction: each names the TV's
		// connection as its device sees it, a packet from the peer to the
		// TV. Reply direction: each names it as the peer sees it, a packet
		// from the TV (the enforcer's WAN address after the NAT) to the
		// peer.
		var tag uint16 = 1300
		forged := map[uint16]string{}  // heard at the TV's peer
		replied := map[uint16]string{} // heard at the TV
		for _, from := range forgers {
			if f.v6 && from == "edge" {
				continue // the edge's segment is IPv4 only (ENF-e-6)
			}
			tag++
			forged[tag] = from
			h.sendErr(from, "", f.allow, f.v6, icmpErr(f.v6, tag, f.allow, tvAddr, 9211, tvPort))
			tag++
			replied[tag] = from
			h.sendErr(from, "", f.wan, f.v6, icmpErr(f.v6, tag, mWAN, f.allow, tvMasq, 9211))
		}
		const intoCore = 1390
		h.sendErr("102", "", f.wan, f.v6, icmpErr(f.v6, intoCore, mWAN, f.cored, coreMasq, 9100))
		// The plug's own error about its own connection, and the peer's
		// genuine ones back to the TV and the core.
		const own, genuine, genuineCore = 1400, 1401, 1402
		h.sendErr("103", "", f.allow, f.v6, icmpErr(f.v6, own, f.allow, plugAddr, 9212, plugPort))
		h.sendErr("isp", f.allow, f.wan, f.v6, icmpErr(f.v6, genuine, mWAN, f.allow, tvMasq, 9211))
		h.sendErr("isp", f.cored, f.wan, f.v6, icmpErr(f.v6, genuineCore, mWAN, f.cored, coreMasq, 9100))
		time.Sleep(probeWait)

		for tag, from := range forged {
			if atPeer.has(tag) {
				t.Errorf("v6 %v: an ICMP error %s forged about the TV's connection reached the TV's peer", f.v6, from)
			}
		}
		for tag, from := range replied {
			if atTV.has(tag) {
				t.Errorf("v6 %v: a reply-direction ICMP error %s forged about the TV's connection reached the TV", f.v6, from)
			}
		}
		if atCore.has(intoCore) {
			t.Errorf("v6 %v: the speaker's reply-direction error about the core's internet connection reached the core", f.v6)
		}
		if !atPeer.has(own) {
			t.Errorf("v6 %v: the plug's error about its own connection did not reach its peer", f.v6)
		}
		if !atTV.has(genuine) {
			t.Errorf("v6 %v: the peer's path-MTU error did not reach the TV", f.v6)
		}
		if !atCore.has(genuineCore) {
			t.Errorf("v6 %v: the peer's path-MTU error did not reach the core", f.v6)
		}
		h.expectOpen(true, tv, plug, core)
	}
}

// NET-3, A18 Segments (#4113): an ICMP error from a device to another
// device it has no path to is dropped and logged. The speaker forges
// errors about the edge's open connection to the TV, to each end, and the
// plug one about a device pair's connection, to the pair's starting end:
// none arrives, and each moves the blocked counter, which only the logged
// refusal rules count. The same forgeries from Owner, Household and Guests
// are dropped too, without a log line or a count, and so is a device's
// forgery into Household's pair with the printer, sent to Household (NET-1,
// NET-3: those networks are never observed, either way). A genuine error along an allowed path still
// passes: from the pair's other end, and from the internet router on the
// TV's own internet connection, so path-MTU discovery keeps working.
func TestRelatedNeedsPath(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	text, err := Compile(cutPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	h.fillSets()
	atTV, atEdge, at106, atHH := h.hear("101", false), h.hear("edge", false), h.hear("106", false), h.hear("household", false)
	edge := h.hold("the edge to the TV", "edge", "101", devAddr(101), 9100)
	pair := h.hold("a device pair", "106", "107", devAddr(107), 9301)
	people := h.hold("Household's pair", "household", "105", devAddr(105), 9302)
	hhAddr, hhPort := hostPort(t, people.c.LocalAddr())
	tv := h.hold("the TV to its allow list", "101", "isp", netAllow, 9213)
	edgeAddr, edgePort := hostPort(t, edge.c.LocalAddr())
	_, pairPort := hostPort(t, pair.c.LocalAddr())
	mWAN, tvMasq := hostPort(t, tv.s.RemoteAddr())

	type forgery struct {
		from, to string
		at       *tags
		pkt      func(tag uint16) []byte
	}
	toTV := func(tag uint16) []byte { return icmpErr(false, tag, devAddr(101), edgeAddr, 9100, edgePort) }
	toEdge := func(tag uint16) []byte { return icmpErr(false, tag, edgeAddr, devAddr(101), edgePort, 9100) }
	toPair := func(tag uint16) []byte { return icmpErr(false, tag, devAddr(106), devAddr(107), pairPort, 9301) }
	toHH := func(tag uint16) []byte { return icmpErr(false, tag, hhAddr, devAddr(105), hhPort, 9302) }
	send := func(fs []forgery, tag uint16) map[uint16]forgery {
		sent := map[uint16]forgery{}
		for _, f := range fs {
			tag++
			sent[tag] = f
			h.sendErr(f.from, "", f.to, false, f.pkt(tag))
		}
		time.Sleep(probeWait)
		for tag, f := range sent {
			if f.at.has(tag) {
				t.Errorf("an ICMP error %s forged to %s arrived", f.from, f.to)
			}
		}
		return sent
	}

	before := h.counter(Blocked)
	devs := send([]forgery{
		{"102", devAddr(101), atTV, toTV},
		{"102", edgeAddr, atEdge, toEdge},
		{"103", devAddr(106), at106, toPair},
	}, 1500)
	if n := h.counter(Blocked) - before; n != len(devs) {
		t.Errorf("the devices' %d forged errors moved the blocked counter by %d", len(devs), n)
	}
	var unseen []forgery
	for _, from := range []string{"owner", "household", "guest"} {
		unseen = append(unseen, forgery{from, devAddr(101), atTV, toTV}, forgery{from, edgeAddr, atEdge, toEdge}, forgery{from, devAddr(106), at106, toPair})
	}
	unseen = append(unseen, forgery{"102", hhAddr, atHH, toHH})
	before = h.counter(Blocked)
	send(unseen, 1520)
	if n := h.counter(Blocked) - before; n != 0 {
		t.Errorf("errors forged from or to the networks never observed moved the blocked counter by %d", n)
	}

	const fromPair, fromRouter = 1600, 1601
	h.sendErr("107", "", devAddr(106), false, icmpErr(false, fromPair, devAddr(106), devAddr(107), pairPort, 9301))
	h.sendErr("isp", ispRouter, enfWAN, false, icmpErr(false, fromRouter, mWAN, netAllow, tvMasq, 9213))
	time.Sleep(probeWait)
	if !at106.has(fromPair) {
		t.Error("the pair's genuine error did not reach the device that started the connection")
	}
	if !atTV.has(fromRouter) {
		t.Error("the internet router's path-MTU error did not reach the TV")
	}
	h.expectOpen(true, edge, pair, tv, people)
}
