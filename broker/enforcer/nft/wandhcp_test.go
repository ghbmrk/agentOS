package nft

// REQ: NET-2

import (
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// leaseTimeout bounds each answer the stand-in servers send.
const leaseTimeout = 2 * time.Second

// clientMAC is the enforcer's WAN client's hardware address in its
// messages.
var clientMAC = []byte{2, 0, 0, 0x40, 0x78, 1}

// onDevice is a ListenConfig whose sockets are bound to the interface ifc
// and may send to a broadcast address, as a DHCP client's and server's are.
func onDevice(ifc string) net.ListenConfig {
	return net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, ifc); serr == nil {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		if err != nil {
			return err
		}
		return serr
	}}
}

// bootp is a DHCP message (RFC 2131) of type typ: a request (op 1) asks
// for a broadcast answer, an answer (op 2) offers yiaddr in 192.168.1.0/24
// with router as its gateway.
func bootp(op byte, xid uint32, typ byte, yiaddr, router net.IP) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	b[10] = 0x80
	copy(b[28:], clientMAC)
	copy(b[236:], []byte{99, 130, 83, 99})
	b = append(b, 53, 1, typ)
	if op == 2 {
		copy(b[16:20], yiaddr.To4())
		b = append(b, 54, 4)
		b = append(b, router.To4()...)
		b = append(b, 1, 4, 255, 255, 255, 0, 3, 4)
		b = append(b, router.To4()...)
		b = append(b, 51, 4, 0, 0, 0x0e, 0x10)
	}
	return append(b, 255)
}

// dhcp6 is a DHCPv6 message (RFC 8415) of type typ with the client's ID
// and an IA_NA, holding addr when it is not nil.
func dhcp6(typ byte, xid uint32, addr net.IP) []byte {
	opt := func(code uint16, data []byte) []byte {
		return append(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, code), uint16(len(data))), data...)
	}
	ia := make([]byte, 12) // IAID, T1, T2
	ia[3] = 1
	if addr != nil {
		ia = append(ia, opt(5, append(append([]byte{}, addr.To16()...), 0, 0, 0x0e, 0x10, 0, 0, 0x1c, 0x20))...)
	}
	b := []byte{typ, byte(xid >> 16), byte(xid >> 8), byte(xid)}
	b = append(b, opt(1, append([]byte{0, 3, 0, 1}, clientMAC...))...)
	return append(b, opt(3, ia)...)
}

// leased6 is the address in a DHCPv6 answer's IA_NA, nil if it has none.
func leased6(b []byte) net.IP {
	find := func(b []byte, code uint16) []byte {
		for len(b) >= 4 {
			c, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
			if len(b) < 4+n {
				return nil
			}
			if c == code {
				return b[4 : 4+n]
			}
			b = b[4+n:]
		}
		return nil
	}
	if len(b) < 4 {
		return nil
	}
	ia := find(b[4:], 3)
	if len(ia) < 12 {
		return nil
	}
	if a := find(ia[12:], 5); len(a) >= 16 {
		return net.IP(a[:16])
	}
	return nil
}

// TestWANLeases (#4078, NET-2 Fails safe): an enforcer whose WAN has no
// address yet leases one by DHCP from a stand-in ISP router, and, over
// IPv6, by DHCPv6 from a server that answers from a global address, each
// to an ordinary UDP socket. Before the lease no route leads back to the
// server, so the reverse-path filter would drop every answer. Catches an
// uplink that never gets an address.
func TestWANLeases(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := &home{t: t, hosts: map[string]*host{}}
	t.Cleanup(func() {
		for _, c := range h.procs {
			c.Process.Kill()
			c.Wait()
		}
	})
	_, err := os.Stat("/proc/sys/net/ipv6")
	h.v6 = err == nil
	run(t, "ip", "link", "set", "lo", "up")
	isp := h.newHost("isp")
	run(t, "ip", "link", "add", "wan0", "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(isp.pid))
	if h.v6 {
		// The server has no link-local address, so it answers from its
		// global one.
		h.in(isp, "ip", "link", "set", "eth0", "addrgenmode", "none")
		h.in(isp, "ip", "addr", "add", "2001:db8:1::1/64", "dev", "eth0", "nodad")
	}
	h.in(isp, "ip", "addr", "add", ispRouter+"/24", "dev", "eth0")
	h.in(isp, "ip", "link", "set", "eth0", "up")
	run(t, "ip", "link", "set", "wan0", "up")
	text, err := Compile(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, fixturePolicy(), text))
	before := h.counter(Spoofed)

	// DHCP: discover and offer, request and acknowledge, all broadcast.
	var server net.PacketConn
	within(t, isp, func() {
		lc := onDevice("eth0")
		if server, err = lc.ListenPacket(t.Context(), "udp4", ":67"); err != nil {
			t.Fatal(err)
		}
	})
	defer server.Close()
	lc := onDevice("wan0")
	client, err := lc.ListenPacket(t.Context(), "udp4", ":68")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	offered := net.ParseIP(enfWAN)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 243 || buf[0] != 1 {
				continue
			}
			answer := map[byte]byte{1: 2, 3: 5}[buf[242]]
			server.WriteTo(bootp(2, binary.BigEndian.Uint32(buf[4:]), answer, offered, net.ParseIP(ispRouter)), &net.UDPAddr{IP: net.IPv4bcast, Port: 68})
		}
	}()
	var lease net.IP
	for i, step := range [][2]byte{{1, 2}, {3, 5}} {
		xid := uint32(0x4078_0000 + i)
		if _, err := client.WriteTo(bootp(1, xid, step[0], nil, nil), &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 1500)
		client.SetReadDeadline(time.Now().Add(leaseTimeout))
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			t.Fatalf("DHCP message %d: no answer reached the enforcer's client (%v); spoofed moved %d", step[0], err, h.counter(Spoofed)-before)
		}
		if n < 243 || buf[0] != 2 || binary.BigEndian.Uint32(buf[4:]) != xid || buf[242] != step[1] {
			t.Fatalf("DHCP message %d: answer % x", step[0], buf[:min(n, 16)])
		}
		lease = net.IP(bytes.Clone(buf[16:20]))
	}
	if !lease.Equal(offered) {
		t.Fatalf("leased %s, want %s", lease, offered)
	}
	run(t, "ip", "addr", "add", lease.String()+"/24", "dev", "wan0")
	run(t, "ip", "route", "add", "default", "via", ispRouter)
	if out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", "wan0").CombinedOutput(); err != nil || !bytes.Contains(out, []byte(enfWAN+"/24")) {
		t.Fatalf("the WAN holds no lease: %s %v", out, err)
	}

	if h.v6 {
		h.settled(nil)
		// DHCPv6: solicit and advertise, request and reply; the server
		// hears All_DHCP_Relay_Agents_and_Servers and answers the client's
		// link-local address from its global one.
		var server6 net.PacketConn
		within(t, isp, func() {
			lc := onDevice("eth0")
			if server6, err = lc.ListenPacket(t.Context(), "udp6", ":547"); err != nil {
				t.Fatal(err)
			}
			raw, _ := server6.(*net.UDPConn).SyscallConn()
			eth0, err := net.InterfaceByName("eth0")
			if err != nil {
				t.Fatal(err)
			}
			mreq := &unix.IPv6Mreq{Interface: uint32(eth0.Index)}
			copy(mreq.Multiaddr[:], net.ParseIP("ff02::1:2").To16())
			var serr error
			if err := raw.Control(func(fd uintptr) {
				serr = unix.SetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IPV6, unix.IPV6_JOIN_GROUP, mreq)
			}); err != nil || serr != nil {
				t.Fatalf("join ff02::1:2: %v %v", err, serr)
			}
		})
		defer server6.Close()
		client6, err := lc.ListenPacket(t.Context(), "udp6", ":546")
		if err != nil {
			t.Fatal(err)
		}
		defer client6.Close()
		offered6 := net.ParseIP("2001:db8:1::2")
		go func() {
			buf := make([]byte, 1500)
			for {
				n, from, err := server6.ReadFrom(buf)
				if err != nil {
					return
				}
				answer, ok := map[byte]byte{1: 2, 3: 7}[buf[0]]
				if n < 4 || !ok {
					continue
				}
				server6.WriteTo(dhcp6(answer, uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3]), offered6), from)
			}
		}()
		for i, step := range [][2]byte{{1, 2}, {3, 7}} {
			xid := uint32(0x4078 + i)
			if _, err := client6.WriteTo(dhcp6(step[0], xid, nil), &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547, Zone: "wan0"}); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 1500)
			client6.SetReadDeadline(time.Now().Add(leaseTimeout))
			n, from, err := client6.ReadFrom(buf)
			if err != nil {
				t.Fatalf("DHCPv6 message %d: no answer reached the enforcer's client (%v); spoofed moved %d", step[0], err, h.counter(Spoofed)-before)
			}
			if got := from.(*net.UDPAddr).IP; !got.Equal(net.ParseIP("2001:db8:1::1")) {
				t.Fatalf("DHCPv6 answer from %s, want the server's global address", got)
			}
			if n < 4 || buf[0] != step[1] || uint32(buf[1])<<16|uint32(buf[2])<<8|uint32(buf[3]) != xid {
				t.Fatalf("DHCPv6 message %d: answer % x", step[0], buf[:min(n, 16)])
			}
			if got := leased6(buf[:n]); !got.Equal(offered6) {
				t.Fatalf("DHCPv6 leased %s, want %s", got, offered6)
			}
		}
		run(t, "ip", "addr", "add", offered6.String()+"/128", "dev", "wan0", "nodad")
	}
	if n := h.counter(Spoofed) - before; n != 0 {
		t.Errorf("spoofed moved %d during the lease", n)
	}
}

// TestDHCPAnswersOnlyToTheEnforcer (#4078, A18 Segments): the reverse-path
// exemption for DHCP and DHCPv6 answers holds only on the WAN and only for
// a packet addressed to the enforcer itself: one from the internet to a
// device, and one from a device to the enforcer, with a source address
// routed out of another interface, are still dropped as spoofed. Catches
// an exemption that lets the internet pose as a segment, or a segment as
// another, on the DHCP client ports.
func TestDHCPAnswersOnlyToTheEnforcer(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	spoof := func(from *host, nw, src, dst string, sport, dport int) {
		if nw == "udp6" {
			h.in(from, "ip", "addr", "add", src+"/128", "dev", "lo", "nodad")
		} else {
			h.in(from, "ip", "addr", "add", src+"/32", "dev", "lo")
		}
		// The DHCP ports are taken by the hosts' echo listeners, so the
		// datagram is written whole on a raw socket.
		within(t, from, func() {
			c, err := net.DialIP(map[string]string{"udp4": "ip4:udp", "udp6": "ip6:udp"}[nw], &net.IPAddr{IP: net.ParseIP(src)}, &net.IPAddr{IP: net.ParseIP(dst)})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if nw == "udp6" { // the kernel fills the checksum at offset 6
				raw, _ := c.SyscallConn()
				raw.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_CHECKSUM, 6) })
			}
			payload := []byte("answer")
			udp := binary.BigEndian.AppendUint16(nil, uint16(sport))
			udp = binary.BigEndian.AppendUint16(udp, uint16(dport))
			udp = binary.BigEndian.AppendUint16(udp, uint16(8+len(payload)))
			udp = append(binary.BigEndian.AppendUint16(udp, 0), payload...)
			for range 3 {
				if _, err := c.Write(udp); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	before := h.counter(Spoofed)
	// From the internet, in a device's name, to another device.
	spoof(h.hosts["isp"], "udp4", devAddr(102), devAddr(101), 67, 68)
	// From a device, in another's name, to the enforcer's address on its own VLAN.
	spoof(h.hosts["101"], "udp4", devAddr(103), "10.101.0.1", 67, 68)
	want := 6
	if h.v6 {
		spoof(h.hosts["isp"], "udp6", devAddr6(102), devAddr6(101), 547, 546)
		spoof(h.hosts["101"], "udp6", devAddr6(103), "fd00:101::1", 547, 546)
		want = 12
	}
	time.Sleep(100 * time.Millisecond)
	if n := h.counter(Spoofed) - before; n != want {
		t.Errorf("spoofed moved %d, want %d", n, want)
	}
}
