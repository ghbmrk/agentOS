package nft

// REQ: NET-3

import (
	"encoding/binary"
	"net"
	"strconv"
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

// NET-3, NET-2 Device paths (#4286): a related packet passes only on the
// interfaces of the connection it names. Every segment with an internet
// path forges an ICMP error, as conntrack reads it related to the TV's
// open internet connection, and sends it toward the TV's peer: none
// arrives, though each of those segments' own internet rule matches the
// error's interfaces. A genuine error on the connection's own path (path
// MTU, from the peer back to the TV) still arrives, and so does the plug's
// error about its own internet connection, which shows the forgers'
// channel works and the drop is the binding.
func TestForgedRelatedDropped(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	type fam struct {
		v6         bool
		allow, wan string
	}
	fams := []fam{{false, netAllow, enfWAN}}
	if h.v6 {
		run(t, "nft", "add", "element", "inet", Table, DeviceSet(103, true), "{ "+net6Allow+" }")
		fams = append(fams, fam{true, net6Allow, "2001:db8:1::2"})
	}
	forgers := []string{"103", "guest", "owner", "household", "core", "edge"}
	for _, f := range fams {
		tvAddr, plugAddr := devAddr(101), devAddr(103)
		if f.v6 {
			tvAddr, plugAddr = devAddr6(101), devAddr6(103)
		}
		atPeer, atTV := h.hear("isp", f.v6), h.hear("101", f.v6)
		tv := h.hold("the TV to its allow list", "101", "isp", f.allow, 9211)
		plug := h.hold("the plug to its allow list", "103", "isp", f.allow, 9212)
		_, tvPort := hostPort(t, tv.c.LocalAddr())
		_, plugPort := hostPort(t, plug.c.LocalAddr())
		mWAN, tvMasq := hostPort(t, tv.s.RemoteAddr())

		// The forgeries: each names the TV's connection as its device sees
		// it, a packet from the peer to the TV.
		var tag uint16 = 1300
		forged := map[uint16]string{}
		for _, from := range forgers {
			if f.v6 && from != "103" {
				continue // only the devices have IPv6 in the fixture
			}
			tag++
			forged[tag] = from
			h.sendErr(from, "", f.allow, f.v6, icmpErr(f.v6, tag, f.allow, tvAddr, 9211, tvPort))
		}
		// The plug's own error about its own connection, and the peer's
		// genuine one back to the TV.
		const own, genuine = 1400, 1401
		h.sendErr("103", "", f.allow, f.v6, icmpErr(f.v6, own, f.allow, plugAddr, 9212, plugPort))
		h.sendErr("isp", f.allow, f.wan, f.v6, icmpErr(f.v6, genuine, mWAN, f.allow, tvMasq, 9211))
		time.Sleep(probeWait)

		for tag, from := range forged {
			if atPeer.has(tag) {
				t.Errorf("v6 %v: an ICMP error %s forged about the TV's connection reached the TV's peer", f.v6, from)
			}
		}
		if !atPeer.has(own) {
			t.Errorf("v6 %v: the plug's error about its own connection did not reach its peer", f.v6)
		}
		if !atTV.has(genuine) {
			t.Errorf("v6 %v: the peer's path-MTU error did not reach the TV", f.v6)
		}
		h.expectOpen(true, tv, plug)
	}
}
