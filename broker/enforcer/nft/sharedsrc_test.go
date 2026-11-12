package nft

// REQ: NET-2, NET-3

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// flow is a UDP flow from a shared host to the internet peer's echo
// listener, with every payload echoed back to it so far.
type flow struct {
	t    *testing.T
	c    net.Conn
	seen map[string]bool
}

// udpFlow opens a flow from host from, from local port lport (0: any), to
// peer's UDP echo port, and says first on it.
func (h *home) udpFlow(from, peer string, lport int, first string) *flow {
	t := h.t
	t.Helper()
	f := &flow{t: t, seen: map[string]bool{}}
	within(t, h.hosts[from], func() {
		d := net.Dialer{}
		if lport != 0 {
			d.LocalAddr = &net.UDPAddr{Port: lport}
		}
		var err error
		if f.c, err = d.Dial("udp", net.JoinHostPort(peer, strconv.Itoa(echoPort))); err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() { f.c.Close() })
	f.say(first)
	return f
}

// echoPort is the UDP port echo listens on.
const echoPort = 9123

// echo answers every datagram to addr's echoPort in host on, from addr
// itself (a wildcard listener would answer from another of the host's
// addresses, which no flow matches).
func (h *home) echo(on, addr string) {
	t := h.t
	within(t, h.hosts[on], func() {
		pc, err := net.ListenPacket("udp", net.JoinHostPort(addr, strconv.Itoa(echoPort)))
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
				pc.WriteTo(buf[:n], from)
			}
		}()
	})
}

func (f *flow) say(msg string) {
	if _, err := f.c.Write([]byte(msg)); err != nil {
		f.t.Fatalf("send %q: %v", msg, err)
	}
}

// heard is whether msg has come back to the flow, reading what arrives
// for probeWait.
func (f *flow) heard(msg string) bool {
	f.c.SetReadDeadline(time.Now().Add(probeWait))
	buf := make([]byte, 64)
	for {
		n, err := f.c.Read(buf)
		if err != nil {
			break
		}
		f.seen[string(buf[:n])] = true
	}
	return f.seen[msg]
}

// local is the flow's own address and port.
func (f *flow) local() (string, int) { return hostPort(f.t, f.c.LocalAddr()) }

// inject sends msg to peer's echo port from host from, from address local
// and port lport, as if it were that flow's: the peer echoes it to the
// flow's owner if it arrives.
func (h *home) inject(from, local string, lport int, peer, msg string) {
	t := h.t
	t.Helper()
	within(t, h.hosts[from], func() {
		d := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(local), Port: lport}}
		c, err := d.Dial("udp", net.JoinHostPort(peer, strconv.Itoa(echoPort)))
		if err != nil {
			t.Fatal(err)
		}
		c.Write([]byte(msg))
		c.Close()
	})
}

// nftSeg is a test segment's name in the ruleset's set and chain names.
func nftSeg(seg string) string {
	return map[string]string{"guest": "guests", "owner": "owner", "household": "household"}[seg]
}

// move ends hardware address from's hold of address addr on seg: on IPv6
// as if from had sent nothing for ClaimTimeout, on IPv4 as if from's lease
// had run out and the server had leased addr to hardware address to.
func (h *home) move(seg, addr, from, to string, v6 bool) {
	h.t.Helper()
	hw, err := net.ParseMAC(from)
	if err != nil {
		h.t.Fatal(err)
	}
	if v6 {
		mac := hwElem(hwInt(hw))
		run(h.t, "nft", "delete", "element", "inet", Table, HeldSet(nftSeg(seg)), "{ "+addr+" }")
		run(h.t, "nft", "delete", "element", "inet", Table, ClaimSet(nftSeg(seg)), "{ "+addr+" . "+from+" }")
		run(h.t, "nft", "delete", "element", "inet", Table, MACSet(nftSeg(seg)), "{ "+mac+" }")
		return
	}
	next, err := net.ParseMAC(to)
	if err != nil {
		h.t.Fatal(err)
	}
	old, _, _ := lease(netip.MustParseAddr(addr), hw)
	now, _, _ := lease(netip.MustParseAddr(addr), next)
	run(h.t, "nft", "delete", "element", "inet", Table, LeaseSet(nftSeg(seg)), "{ "+old+" }")
	run(h.t, "nft", "add", "element", "inet", Table, LeaseSet(nftSeg(seg)), "{ "+now+" }")
}

// NET-3, NET-2 Device paths (#4480): on a shared segment (Guests, Owner,
// Household, both families) a packet another host sends from a host's
// address and port reaches nobody, at any stage of the host's flow, and
// the host's own do. The second host sends from the first host's address
// with its own hardware address:
//   - into the first host's answered UDP flow: dropped, since the first
//     host holds its address (claim), while the first host's own datagram
//     is echoed;
//   - first, on the first host's next port, before the first host opens a
//     flow there (a pre-opened tuple, as for IKE's 500 to 500): dropped, so
//     the first host's flow on that port is its own and only its own
//     datagram is echoed;
//   - into the answered flow after the first host's hold has run out (it
//     sent nothing for ClaimTimeout on IPv6; on IPv4 its lease ran out and
//     the server leased the address to the second host): the second host
//     now holds the address, but the flow's record names the first host's
//     hardware address, so its datagram is still dropped (bound), and once
//     the first host holds it again its own flow goes on;
//   - into a flow that has no record, as a connection opened while a load
//     replaced the ruleset has (the records are flushed as a stand-in for
//     the window between the listing and the load): dropped even with the
//     first host's hardware address copied, and the first host's own is
//     dropped too (fails closed).
//
// A load carries the holds and the records: after it the second host's
// pre-opened tuple is still refused and the first host's flows go on.
// Catches a binding of related packets only (the expired-hold injection
// passes), a binding by address or by claim alone, a record that is not
// required of a later packet, and a load that drops the holds (the
// pre-opened tuple after the load takes the address) or the records (the
// flows are cut).
func TestSharedSourceBound(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, d, text))
	h.fillSets()
	segs := []string{"guest", "owner", "household"}
	for _, seg := range segs {
		h.share(seg)
	}
	fams := []bool{false}
	if h.v6 {
		fams = append(fams, true)
	}
	addrOf := func(seg string, v6 bool) string {
		if v6 {
			return seg6Addr(seg, 0)
		}
		return segAddr(seg, 0)
	}
	peerOf := func(v6 bool) string {
		if v6 {
			return net6Other
		}
		return netOther
	}
	for _, v6 := range fams {
		h.echo("isp", peerOf(v6))
	}
	for _, seg := range segs {
		b := h.hosts[seg+"2"]
		// The second host asks for the gateway's hardware address from its
		// own address, so the enforcer keeps sending the first host's
		// packets to the first host: taking over a neighbour entry is
		// outside the forwarding this test is about.
		h.in(b, "sh", "-c", "echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce")
		h.in(b, "ip", "addr", "add", segAddr(seg, 0)+"/32", "dev", "lo")
		if h.v6 {
			h.in(b, "ip", "addr", "add", seg6Addr(seg, 0)+"/128", "dev", "lo", "nodad")
		}
	}
	macA := map[string]string{}
	macB := map[string]string{}
	for _, seg := range segs {
		macA[seg] = h.mac(h.hosts[seg], "eth0")
		macB[seg] = h.mac(h.hosts[seg+"2"], "eth0")
	}

	lport := 9700
	type kept struct {
		seg string
		v6  bool
		f   *flow
	}
	var flows []kept
	for _, v6 := range fams {
		for _, seg := range segs {
			why := fmt.Sprintf("%s (v6 %v)", seg, v6)
			a, peer := addrOf(seg, v6), peerOf(v6)
			f := h.udpFlow(seg, peer, 0, "first")
			if !f.heard("first") {
				t.Fatalf("%s: the first host's flow is not answered", why)
			}
			local, port := f.local()

			// Into the answered flow, from the held address.
			h.inject(seg+"2", local, port, peer, "held")
			f.say("own")
			if !f.heard("own") || f.heard("held") {
				t.Errorf("%s: into a flow from a held address: own heard %v, injected heard %v; want true, false", why, f.seen["own"], f.seen["held"])
			}

			// A pre-opened tuple on the first host's next port.
			lport++
			h.inject(seg+"2", a, lport, peer, "pre")
			g := h.udpFlow(seg, peer, lport, "mine")
			if !g.heard("mine") || g.heard("pre") {
				t.Errorf("%s: a pre-opened tuple: own heard %v, pre-opened heard %v; want true, false", why, g.seen["mine"], g.seen["pre"])
			}

			// The first host's hold runs out; its flow's record still binds
			// it.
			h.move(seg, a, macA[seg], macB[seg], v6)
			h.inject(seg+"2", local, port, peer, "expired")
			if f.heard("expired") {
				t.Errorf("%s: a datagram injected into a flow after its host's hold ran out arrived", why)
			}
			h.move(seg, a, macB[seg], macA[seg], v6)
			f.say("again")
			if !f.heard("again") {
				t.Errorf("%s: the first host's flow did not go on once its address was free again", why)
			}
			flows = append(flows, kept{seg, v6, f})
		}
	}

	// A load carries the holds and the records.
	h.reload(d)
	h.fillSets()
	for _, k := range flows {
		why := fmt.Sprintf("%s (v6 %v) after a load", k.seg, k.v6)
		k.f.say("carried")
		if !k.f.heard("carried") {
			t.Errorf("%s: the first host's flow was cut", why)
		}
		lport++
		h.inject(k.seg+"2", addrOf(k.seg, k.v6), lport, peerOf(k.v6), "pre after")
		g := h.udpFlow(k.seg, peerOf(k.v6), lport, "mine after")
		if !g.heard("mine after") || g.heard("pre after") {
			t.Errorf("%s: a pre-opened tuple: own heard %v, pre-opened heard %v; want true, false", why, g.seen["mine after"], g.seen["pre after"])
		}
	}

	// A flow without a record: the records are flushed, as a load that
	// replaced the ruleset between its listing and its commit would lose
	// the record of a connection opened in between.
	for _, k := range flows {
		run(t, "nft", "flush", "set", "inet", Table, HostSet(nftSeg(k.seg), k.v6))
	}
	for _, seg := range segs {
		h.in(h.hosts[seg+"2"], "ip", "link", "set", "eth0", "address", macA[seg])
	}
	for _, k := range flows {
		why := fmt.Sprintf("%s (v6 %v) without a record", k.seg, k.v6)
		local, port := k.f.local()
		h.inject(k.seg+"2", local, port, peerOf(k.v6), "copied")
		k.f.say("unrecorded")
		if k.f.heard("copied") || k.f.heard("unrecorded") {
			t.Errorf("%s: copied heard %v, own heard %v; want both dropped", why, k.f.seen["copied"], k.f.seen["unrecorded"])
		}
	}
	for _, seg := range segs {
		h.in(h.hosts[seg+"2"], "ip", "link", "set", "eth0", "address", macB[seg])
	}
}

// NET-3, NET-2 Device paths (#4480, #5294): Reload carries each shared
// segment's host records, leases and IPv6 holds into its own set, with the
// time each had left, and a record refreshed past its set's timeout keeps
// a timeout of its own. A running table from before the leases has IPv4
// claims, which become leases (and their hardware addresses leased ones,
// each once, for its longest time), and IPv4 holds, which go. Each element is parsed and written again: one that is
// malformed, of the wrong family, with no time left or more than its set
// allows, or in another table, is left out, so nothing in a listing
// reaches the load as text. Catches a carry that copies a listing's text,
// that drops a segment's sets (a lease, a leased hardware address, an IPv6
// hold), or that writes a long record past its set's timeout (nft refuses
// the load).
func TestReloadCarriesSharedRecords(t *testing.T) {
	l := fixtureLayout()
	d := cutPolicy()
	el := func(val string, expires int) raw {
		return raw{fmt.Sprintf(`{"elem": {"val": %s, "expires": %d}}`, val, expires)}
	}
	hostEl := func(id, orig, src, hw string, expires int) raw {
		return el(fmt.Sprintf(`{"concat": [%s, "%s", "%s", "%s"]}`, id, orig, src, hw), expires)
	}
	const hw, hw2 = "02:00:00:00:00:01", "02:00:00:00:00:02"
	running := listing(map[string][]any{
		HostSet("guests", false): {
			hostEl("123", "10.30.0.2", "10.30.0.2", hw, 100),
			hostEl("124", "10.30.0.2", "10.30.0.2", hw, 400000), // a TCP record
			hostEl("125", "10.30.0.2", "10.30.0.2", hw, 432001), // past HostTCPTimeout
			hostEl("126", "10.30.0.2", "10.30.0.2", hw, 0),
			hostEl("4294967296", "10.30.0.2", "10.30.0.2", hw, 100),
			hostEl("-1", "10.30.0.2", "10.30.0.2", hw, 100),
			hostEl("127", "fd10:30::2", "fd10:30::2", hw, 100),
			hostEl("128", "10.30.0.2", "10.30.0.2", "02:00:00:00:00:00:00:01", 100),
			hostEl("129", "10.30.0.2 } ; flush ruleset ; add element inet enforcer held_guests_4 { 10.30.0.9", "10.30.0.2", hw, 100),
			hostEl(`"130"`, "10.30.0.2", "10.30.0.2", hw, 100),
			el(`{"concat": [131, "10.30.0.2", "10.30.0.2"]}`, 100),
			"10.30.0.2",
		},
		HostSet("household", true): {hostEl("7", "fd10:20::2", "fd10:20::2", hw2, 3600)},
		HeldSet("owner"):           {el(`"fd10:10::2"`, 50), el(`"10.10.0.2"`, 50), el(`"fe80::1%eth0"`, 50), el(`"::ffff:10.10.0.2"`, 50)},
		ClaimSet("household"):      {el(`{"concat": ["fd10:20::2", "02:00:00:00:00:02"]}`, 50), el(`{"concat": ["10.20.0.2", "02:00:00:00:00:02"]}`, 50), el(`"fd10:20::3"`, 50)},
		MACSet("household"):        {el(`2199023255554`, 50), el(`"02:00:00:00:00:02"`, 50), el(`2199023255555`, 21601)},
		// 10.30.0.2 is 169738242; 02:00:00:00:00:01 is 2199023255553.
		LeaseSet("guests"): {
			el(`{"concat": [169738242, 2199023255553]}`, 100),
			el(`{"concat": [169738243, 2199023255553]}`, 43201), // past LeaseTimeout
			el(`{"concat": [0, 2199023255553]}`, 100),
			el(`{"concat": [169738244, 281474976710656]}`, 100),
			el(`{"concat": [4294967296, 2199023255553]}`, 100),
			el(`{"concat": [-1, 2199023255553]}`, 100),
			el(`{"concat": ["10.30.0.2", "02:00:00:00:00:01"]}`, 100),
			el(`{"concat": [169738242]}`, 100),
		},
		// Never carried: each load writes it from the leases it carries.
		LeaseAddrSet("guests"): {el(`169738249`, 100)},
		LeasedSet("guests"):    {el(`2199023255553`, 43200), el(`281474976710656`, 100), el(`"02:00:00:00:00:01"`, 100), el(`2199023255556`, 0)},
		// A running table from before the leases: its IPv4 claims become
		// leases, its IPv4 holds go.
		"held_owner_4": {el(`"10.10.0.2"`, 21600)},
		"claim_owner_4": {
			el(`{"concat": ["10.10.0.2", "02:00:00:00:00:0A"]}`, 60),
			el(`{"concat": ["10.10.0.5", "02:00:00:00:00:0a"]}`, 30),
			el(`{"concat": ["10.10.0.3", "nope"]}`, 60),
			el(`{"concat": ["10.10.0.4", "02:00:00:00:00:0b"]}`, 21601),
			el(`{"concat": ["0.0.0.0", "02:00:00:00:00:0b"]}`, 60),
			el(`{"concat": ["fd10:10::4", "02:00:00:00:00:0b"]}`, 60),
			el(`"10.10.0.6"`, 60),
		},
		"ip/enforcer/" + HeldSet("owner"):          {el(`"fd10:10::7"`, 50)},
		"inet/other/" + HostSet("guests", false):   {hostEl("1", "10.30.0.2", "10.30.0.2", hw, 100)},
		"inet/enforcer/" + HostSet("lobby", false): {hostEl("2", "10.30.0.2", "10.30.0.2", hw, 100)},
	})
	base, err := Compile(d, l)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Reload(d, l, running)
	if err != nil {
		t.Fatal(err)
	}
	extra, ok := strings.CutPrefix(got, base)
	if !ok {
		t.Fatal("Reload does not start with Compile's ruleset")
	}
	want := strings.Join([]string{
		"add element inet enforcer claim_household_6 { fd10:20::2 . 02:00:00:00:00:02 expires 50s }",
		"add element inet enforcer lease_owner_4 { 0x0a0a0002 . 0x02000000000a expires 60s, 0x0a0a0005 . 0x02000000000a expires 30s }",
		"add element inet enforcer leaseaddr_owner_4 { 0x0a0a0002 expires 60s, 0x0a0a0005 expires 30s }",
		"add element inet enforcer leased_owner { 0x02000000000a expires 60s }",
		"add element inet enforcer held_owner_6 { fd10:10::2 expires 50s }",
		"add element inet enforcer host_guests_4 { 123 . 10.30.0.2 . 10.30.0.2 . 02:00:00:00:00:01 expires 100s, 124 . 10.30.0.2 . 10.30.0.2 . 02:00:00:00:00:01 timeout 400000s expires 400000s }",
		"add element inet enforcer host_household_6 { 7 . fd10:20::2 . fd10:20::2 . 02:00:00:00:00:02 expires 3600s }",
		"add element inet enforcer lease_guests_4 { 0x0a1e0002 . 0x020000000001 expires 100s }",
		"add element inet enforcer leaseaddr_guests_4 { 0x0a1e0002 expires 100s }",
		"add element inet enforcer leased_guests { 0x020000000001 expires 43200s }",
		"add element inet enforcer mac6_household { 0x020000000002 expires 50s }",
	}, "\n") + "\n"
	if extra != want {
		t.Errorf("carried:\n%s\nwant:\n%s", extra, want)
	}
	if got, err := Reload(d, l, nil); err != nil || got != base {
		t.Errorf("first load: %v, carried %q", err, strings.TrimPrefix(got, base))
	}
}

// NET-3, NET-2 Device paths (#5294, #4703): on a shared segment an IPv4
// packet passes only from a lease the enforcer's own DHCP server granted,
// its address with its client's hardware address, and IPv6 gives each
// leased hardware address one address. On each shared segment the first
// host holds its own address's lease and the second host its own (Seed):
//   - the first host's datagram from its own address arrives; from the
//     second host's leased address, or the second host's from the first
//     host's, does not (a lease binds the pair, not the address);
//   - an address no one holds a lease of is refused to both hosts, before
//     the server's ACK leases it to the first host, which the output chain
//     reads as it leaves (snoop); after it the first host's datagram from
//     it arrives and the second host's does not, and the server's ACK of
//     that address to the second host never leaves (#5300);
//   - an ACK of a shorter lease leases its address too, for the floor of
//     its lease band (leaseBands): at each band edge the element's timeout
//     is the band's floor, never longer than the lease, and a renewal ACK
//     near a band's top refreshes it before half the lease (the client's
//     renewal time) has run; an ACK with no address (to an INFORM), or
//     past LeaseTimeout, leases nothing; a later, shorter ACK of another
//     address to a hardware address cuts its leased element to that
//     band, and the first address keeps its own (#5300);
//   - on IPv6 (in CI) the first host's first address holds and a second
//     address of its hardware address is refused, and the second host,
//     whose lease is taken away, holds none.
//
// A load carries all of it: the snooped lease, the hold and the per-host
// limit. The datagrams go to a listener on the internet that records them,
// so a refusal is the datagram not arriving, whoever would get its answer.
// Catches a claim without the lease check, a lease checked by address
// alone, a snoop that misses dnsmasq's ACK, drops a shorter lease or keeps
// it past its band's floor, takes an ACK with no address or past
// LeaseTimeout, lets an ACK of a held address to another host leave, no
// per-hardware-address IPv6 limit or leased check, and a load that drops
// the leases or the limit.
func TestSharedHoldsFollowLeases(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	h.unleased = true
	d := cutPolicy()
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, d, text))
	h.fillSets()
	segs := []string{"guest", "owner", "household"}
	for _, seg := range segs {
		h.share(seg)
	}
	h.lease()

	const port = 9124
	got := make(chan string, 256)
	peers := []string{netOther}
	if h.v6 {
		peers = append(peers, net6Other)
	}
	for _, p := range peers {
		within(t, h.hosts["isp"], func() {
			pc, err := net.ListenPacket("udp", net.JoinHostPort(p, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { pc.Close() })
			go func() {
				buf := make([]byte, 1500)
				for {
					n, _, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					got <- string(buf[:n])
				}
			}()
		})
	}
	// arrives sends msg from host from, from address addr, to the
	// internet, and reports whether it arrived.
	arrives := func(from, addr, msg string) bool {
		t.Helper()
		peer := netOther
		if strings.Contains(addr, ":") {
			peer = net6Other
		}
		within(t, h.hosts[from], func() {
			dl := net.Dialer{LocalAddr: &net.UDPAddr{IP: net.ParseIP(addr)}}
			c, err := dl.Dial("udp", net.JoinHostPort(peer, strconv.Itoa(port)))
			if err != nil {
				t.Fatal(err)
			}
			c.Write([]byte(msg))
			c.Close()
		})
		deadline := time.After(probeWait)
		for {
			select {
			case m := <-got:
				if m == msg {
					return true
				}
			case <-deadline:
				return false
			}
		}
	}
	// ack is the server's DHCPACK leasing yiaddr to hw for lease seconds,
	// written as dnsmasq writes it, sent from the enforcer out of seg's
	// interface; it reports whether the ACK left (the output chain's drop
	// fails the send).
	ack := func(seg, yiaddr, hw string, lease uint32) bool {
		t.Helper()
		b := make([]byte, 240)
		b[0], b[1], b[2] = 2, 1, 6
		copy(b[16:], net.ParseIP(yiaddr).To4())
		m, err := net.ParseMAC(hw)
		if err != nil {
			t.Fatal(err)
		}
		copy(b[28:], m)
		copy(b[236:], []byte{99, 130, 83, 99})
		b = append(append(b, 53, 1, 5, 54, 4), net.ParseIP(enfAddr(seg)).To4()...)
		b = append(binary.BigEndian.AppendUint32(append(b, 51, 4), lease), 1, 4, 255, 255, 255, 0, 255)
		pkt := udp4(enfAddr(seg), "255.255.255.255", 67, 68, string(b))
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW) // header included
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if err := unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, segIfc(seg)); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_BROADCAST, 1); err != nil {
			t.Fatal(err)
		}
		err = unix.Sendto(fd, pkt, 0, &unix.SockaddrInet4{Addr: [4]byte{255, 255, 255, 255}})
		if err != nil && err != unix.EPERM {
			t.Fatal(err)
		}
		return err == nil
	}

	// leased is the timeout and time left, in seconds, of the element
	// leasing addr to hw on seg, as nft lists it.
	leased := func(seg, addr, hw string) (int64, int64, bool) {
		t.Helper()
		m, err := net.ParseMAC(hw)
		if err != nil {
			t.Fatal(err)
		}
		a := netip.MustParseAddr(addr).As4()
		key := []uint64{uint64(binary.BigEndian.Uint32(a[:])), hwInt(m)}
		var doc struct {
			Nftables []struct {
				Set *struct {
					Elem []struct {
						Elem struct {
							Val struct {
								Concat []uint64 `json:"concat"`
							} `json:"val"`
							Timeout int64 `json:"timeout"`
							Expires int64 `json:"expires"`
						} `json:"elem"`
					} `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal([]byte(run(t, "nft", "-j", "list", "set", "inet", Table, LeaseSet(nftSeg(seg)))), &doc); err != nil {
			t.Fatal(err)
		}
		for _, o := range doc.Nftables {
			if o.Set == nil {
				continue
			}
			for _, e := range o.Set.Elem {
				if slices.Equal(e.Elem.Val.Concat, key) {
					if e.Elem.Timeout == 0 { // nft lists no timeout equal to its set's
						e.Elem.Timeout = LeaseTimeout
					}
					return e.Elem.Timeout, e.Elem.Expires, true
				}
			}
		}
		return 0, 0, false
	}

	free, short := map[string]string{}, map[string]string{}
	for _, seg := range segs {
		a, b := h.hosts[seg], h.hosts[seg+"2"]
		free[seg], short[seg] = segAddr(seg, 6), segAddr(seg, 7)
		for _, x := range []*host{a, b} {
			h.in(x, "sh", "-c", "echo 2 > /proc/sys/net/ipv4/conf/all/arp_announce")
			h.in(x, "ip", "addr", "add", free[seg]+"/32", "dev", "lo")
		}
		h.in(a, "ip", "addr", "add", segAddr(seg, 1)+"/32", "dev", "lo")
		h.in(a, "ip", "addr", "add", short[seg]+"/32", "dev", "lo")
		h.in(b, "ip", "addr", "add", segAddr(seg, 0)+"/32", "dev", "lo")
		if h.v6 {
			h.in(a, "ip", "addr", "add", seg6Addr(seg, 7)+"/128", "dev", "lo", "nodad")
		}
	}
	for _, seg := range segs {
		macA := h.mac(h.hosts[seg], "eth0")
		if !arrives(seg, segAddr(seg, 0), seg+" own") {
			t.Errorf("%s: the first host's datagram from its own lease did not arrive", seg)
		}
		if arrives(seg, segAddr(seg, 1), seg+" other's") || arrives(seg+"2", segAddr(seg, 0), seg+" first's") {
			t.Errorf("%s: a datagram from another host's leased address arrived", seg)
		}
		if arrives(seg+"2", free[seg], seg+" free 2") || arrives(seg, free[seg], seg+" free 1") {
			t.Errorf("%s: a datagram from an address no one leased arrived", seg)
		}
		ack(seg, free[seg], macA, LeaseTimeout)
		if !arrives(seg, free[seg], seg+" leased 1") || arrives(seg+"2", free[seg], seg+" leased 2") {
			t.Errorf("%s: after the ACK to the first host, its datagram must arrive and the second host's must not", seg)
		}
		// The server's ACK giving that address to the second host never
		// leaves while the first host's element lasts (#5300).
		macB := h.mac(h.hosts[seg+"2"], "eth0")
		left := ack(seg, free[seg], macB, LeaseTimeout)
		if _, _, ok := leased(seg, free[seg], macB); left || ok || arrives(seg+"2", free[seg], seg+" taken 2") {
			t.Errorf("%s: an ACK of the first host's address to the second host leased it", seg)
		}
		ack(seg, short[seg], macA, 3600)
		if !arrives(seg, short[seg], seg+" short") {
			t.Errorf("%s: an ACK of a shorter lease did not lease its address", seg)
		}
		// Band edges: each ACK leases its own address, for its band's floor.
		bands := leaseBands()
		edges := map[uint32]int{}
		for i, b := range bands {
			edges[uint32(b[0])], edges[uint32(b[1])] = b[0], b[0]
			if i > 0 && b[0] != bands[i-1][1]+1 {
				t.Fatalf("lease bands %v and %v leave a gap", bands[i-1], b)
			}
		}
		i := 20
		for lease, floor := range edges {
			addr := segAddr(seg, i)
			i++
			ack(seg, addr, macA, lease)
			if to, left, ok := leased(seg, addr, macA); !ok || to != int64(floor) || left > to || 2*left <= int64(lease) {
				t.Errorf("%s: a %d s lease: element %v, timeout %d s, %d s left; want its band's floor %d s, past half the lease", seg, lease, ok, to, left, floor)
			}
		}
		// An ACK past LeaseTimeout, the top band, leases nothing (#5300).
		const over, moved = "02:00:00:00:43:21", "02:00:00:00:53:00"
		hwOver, _ := net.ParseMAC(over)
		ack(seg, segAddr(seg, 80), over, LeaseTimeout+1)
		_, ok1 := element(t, LeasedSet(nftSeg(seg)), hwInt(hwOver))
		_, ok2 := element(t, LeaseAddrSet(nftSeg(seg)), addrInt(segAddr(seg, 80)))
		if _, _, ok := leased(seg, segAddr(seg, 80), over); ok || ok1 || ok2 {
			t.Errorf("%s: an ACK of %d s leased: lease %v, hardware address %v, address %v", seg, LeaseTimeout+1, ok, ok1, ok2)
		}
		// A later, shorter ACK of another address to the same hardware
		// address cuts its leased element to that ACK's band, while the
		// first address's element keeps its own (fails closed; ASSUMPTIONS
		// ENF-shared-src-1).
		hwMoved, _ := net.ParseMAC(moved)
		ack(seg, segAddr(seg, 81), moved, LeaseTimeout)
		ack(seg, segAddr(seg, 82), moved, MinLease)
		cut, ok := element(t, LeasedSet(nftSeg(seg)), hwInt(hwMoved))
		if _, first, ok1 := leased(seg, segAddr(seg, 81), moved); !ok1 || first <= MinLease || !ok || cut > MinLease {
			t.Errorf("%s: after a shorter ACK of another address: first lease %v with %d s left, leased element %v with %d s left; want over and at most %d s", seg, ok1, first, ok, cut, MinLease)
		}
		ack(seg, "0.0.0.0", macA, LeaseTimeout)
		if _, _, ok := leased(seg, "0.0.0.0", macA); ok {
			t.Errorf("%s: an ACK with no address leased 0.0.0.0", seg)
		}
		if h.v6 {
			if !arrives(seg, seg6Addr(seg, 0), seg+" own6") || arrives(seg, seg6Addr(seg, 7), seg+" second6") {
				t.Errorf("%s: IPv6: the first address must hold and a second one of the same hardware address must not", seg)
			}
			hw, err := net.ParseMAC(h.mac(h.hosts[seg+"2"], "eth0"))
			if err != nil {
				t.Fatal(err)
			}
			run(t, "nft", "delete", "element", "inet", Table, LeasedSet(nftSeg(seg)), "{ "+hwElem(hwInt(hw))+" }")
			if arrives(seg+"2", seg6Addr(seg, 1), seg+" unleased6") {
				t.Errorf("%s: IPv6: a hardware address with no lease took a hold", seg)
			}
		}
	}

	// A renewal near a band's top refreshes the element: a lease at the
	// lowest band's top lasts the band's floor, and its renewal ACK a few
	// seconds later starts the floor again, long before the first ran out.
	near := segAddr("guest", 60)
	macG := h.mac(h.hosts["guest"], "eth0")
	low := leaseBands()[0]
	ack("guest", near, macG, uint32(low[1]))
	time.Sleep(2500 * time.Millisecond)
	_, before, _ := leased("guest", near, macG)
	ack("guest", near, macG, uint32(low[1]))
	if _, left, ok := leased("guest", near, macG); !ok || before > int64(low[0])-2 || left <= before {
		t.Errorf("a renewal near a band's top: %d s left before, %d s after (%v); want it refreshed", before, left, ok)
	}

	h.reload(d)
	h.fillSets()
	for _, seg := range segs {
		why := seg + " after a load"
		if !arrives(seg, segAddr(seg, 0), why+" own") || !arrives(seg, free[seg], why+" leased 1") {
			t.Errorf("%s: a lease was dropped", why)
		}
		if arrives(seg+"2", free[seg], why+" leased 2") {
			t.Errorf("%s: the second host's datagram from the first host's lease arrived", why)
		}
		if h.v6 && (!arrives(seg, seg6Addr(seg, 0), why+" own6") || arrives(seg, seg6Addr(seg, 7), why+" second6") || arrives(seg+"2", seg6Addr(seg, 1), why+" unleased6")) {
			t.Errorf("%s: IPv6: a hold, the per-host limit or a leased hardware address was not carried", why)
		}
	}
}

// guestDnsmasq runs the real dnsmasq as the enforcer runs it on the
// Guests segment, leasing segAddr("guest", lo) to segAddr("guest", hi),
// behind the fixture ruleset with no lease seeded, and returns the home,
// the guest host and dnsmasq's lease file.
func guestDnsmasq(t *testing.T, lo, hi int) (*home, *host, string) {
	t.Helper()
	bin, err := exec.LookPath("dnsmasq")
	if err != nil {
		if required() {
			t.Fatal("dnsmasq missing")
		}
		t.Skip("dnsmasq missing")
	}
	h := &home{t: t, hosts: map[string]*host{}, unleased: true}
	t.Cleanup(func() {
		for _, c := range h.procs {
			c.Process.Kill()
			c.Wait()
		}
	})
	l := fixtureLayout()
	run(t, "ip", "link", "set", "lo", "up")
	x := h.newHost("guest")
	h.link(x, l.Guests, enfAddr("guest")+"/24", segAddr("guest", 0)+"/24", "", "")
	text, err := Compile(fixturePolicy(), l)
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, fixturePolicy(), text))

	dir := t.TempDir()
	conf := strings.Join([]string{"port=0", "interface=" + l.Guests, "bind-interfaces", "no-ping", "dhcp-authoritative",
		"dhcp-range=" + segAddr("guest", lo) + "," + segAddr("guest", hi) + "," + strconv.Itoa(LeaseTimeout/3600) + "h",
		"dhcp-leasefile=" + dir + "/leases", "pid-file="}, "\n") + "\n"
	if err := os.WriteFile(dir+"/conf", []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-d", "-C", dir+"/conf")
	var log strings.Builder
	cmd.Stderr = &log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("dnsmasq:\n%s", log.String())
		}
	})
	time.Sleep(300 * time.Millisecond)
	return h, x, dir + "/leases"
}

// dhcpMsg is a client's DHCP message of type typ (option 53, first) from
// hardware address hw, asking for answers by broadcast, then opts.
func dhcpMsg(t *testing.T, typ byte, xid uint32, hw string, ciaddr netip.Addr, opts ...byte) []byte {
	m, err := net.ParseMAC(hw)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 240)
	b[0], b[1], b[2] = 1, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	b[10] = 0x80
	if ciaddr.IsValid() {
		copy(b[12:], ciaddr.AsSlice())
	}
	copy(b[28:], m)
	copy(b[236:], []byte{99, 130, 83, 99})
	return append(append(append(b, 53, 1, typ), opts...), 255)
}

// dhcpAsk sends msg from the guest host x, with hardware address hw, from
// UDP port 68 to the server at to (broadcast if empty), and returns the
// server's answer to msg's xid within wait, or nil.
func dhcpAsk(t *testing.T, h *home, x *host, hw string, msg []byte, to string, wait time.Duration) []byte {
	t.Helper()
	h.in(x, "ip", "link", "set", "eth0", "address", hw)
	var got []byte
	within(t, x, func() {
		lc := onDevice("eth0")
		pc, err := lc.ListenPacket(context.Background(), "udp4", "0.0.0.0:68")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		dst := &net.UDPAddr{IP: net.IPv4bcast, Port: 67}
		if to != "" {
			dst.IP = net.ParseIP(to)
		}
		if _, err := pc.WriteTo(msg, dst); err != nil {
			t.Fatal(err)
		}
		pc.SetReadDeadline(time.Now().Add(wait))
		buf := make([]byte, 1500)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if n > 243 && buf[0] == 2 && slices.Equal(buf[4:8], msg[4:8]) {
				got = slices.Clone(buf[:n])
				return
			}
		}
	})
	return got
}

// dhcpType is a DHCP message's type, when option 53 comes first.
func dhcpType(m []byte) byte {
	if len(m) > 242 && m[240] == 53 {
		return m[242]
	}
	return 0
}

// NET-3 (#5294): the snoop reads the real dnsmasq's DHCPACK. dnsmasq, run
// as the enforcer runs it on the Guests segment, leases an address to a
// host; the lease set then holds that address with the host's hardware
// address, and the leased set the hardware address. A host that asks for
// a shorter lease is granted it and leased too. Catches payload
// offsets or an option order that do not match dnsmasq's ACK, which the
// crafted ACKs of TestSharedHoldsFollowLeases would not show.
func TestSnoopReadsDnsmasqACK(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h, x, _ := guestDnsmasq(t, 98, 198)
	l := fixtureLayout()
	server := net.ParseIP(enfAddr("guest")).To4()

	// leaseOf runs a client's DISCOVER and REQUEST from the guest host
	// with hardware address hw, asking for lease seconds (0: none), and
	// returns the address the ACK leased.
	leaseOf := func(hw string, lease uint32) netip.Addr {
		t.Helper()
		var opts []byte
		if lease != 0 {
			opts = binary.BigEndian.AppendUint32([]byte{51, 4}, lease)
		}
		const xid = 0x5294
		offer := dhcpAsk(t, h, x, hw, dhcpMsg(t, 1, xid, hw, netip.Addr{}, opts...), "", 10*time.Second)
		if dhcpType(offer) != 2 {
			t.Fatalf("no DHCPOFFER to %s", hw)
		}
		req := append(append([]byte{50, 4}, offer[16:20]...), 54, 4)
		ack := dhcpAsk(t, h, x, hw, dhcpMsg(t, 3, xid, hw, netip.Addr{}, append(append(req, server...), opts...)...), "", 10*time.Second)
		if dhcpType(ack) != 5 {
			t.Fatalf("no DHCPACK to %s", hw)
		}
		return netip.AddrFrom4([4]byte(ack[16:20]))
	}
	carried := func() string {
		out, err := Reload(fixturePolicy(), l, h.List())
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	const full, short = "02:00:00:00:52:94", "02:00:00:00:52:95"
	a := leaseOf(full, 0)
	b := leaseOf(short, 3600)
	hwFull, _ := net.ParseMAC(full)
	hwShort, _ := net.ParseMAC(short)
	elem, _, leased := lease(a, hwFull)
	shortElem, _, shortLeased := lease(b, hwShort)
	got := carried()
	if !strings.Contains(got, "add element inet "+Table+" "+LeaseSet("guests")+" { "+elem+" expires ") ||
		!strings.Contains(got, "add element inet "+Table+" "+LeasedSet("guests")+" { "+leased+" expires ") {
		t.Errorf("dnsmasq leased %s to %s, and the lease sets do not hold it:\n%s", a, full, got[strings.LastIndex(got, "\n}\n")+3:])
	}
	if !strings.Contains(got, shortElem+" expires ") || !strings.Contains(got, shortLeased+" expires ") {
		t.Errorf("dnsmasq's shorter lease of %s to %s was not leased", b, short)
	}
}

// element is the seconds left of set's element key (an integer, or a
// concatenation of integers), as nft lists it, and whether the set holds
// it. An update of an element sets its time left, not the timeout nft
// lists for it.
func element(t *testing.T, set string, key ...uint64) (int64, bool) {
	t.Helper()
	var doc struct {
		Nftables []struct {
			Set *struct {
				Elem []struct {
					Elem struct {
						Val     json.RawMessage `json:"val"`
						Expires int64           `json:"expires"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(run(t, "nft", "-j", "list", "set", "inet", Table, set)), &doc); err != nil {
		t.Fatal(err)
	}
	for _, o := range doc.Nftables {
		if o.Set == nil {
			continue
		}
		for _, e := range o.Set.Elem {
			var c struct {
				Concat []uint64 `json:"concat"`
			}
			var one uint64
			if json.Unmarshal(e.Elem.Val, &c) == nil && slices.Equal(c.Concat, key) ||
				len(key) == 1 && json.Unmarshal(e.Elem.Val, &one) == nil && one == key[0] {
				return e.Elem.Expires, true
			}
		}
	}
	return 0, false
}

// addrInt is IPv4 address a as nft reads a raw address field.
func addrInt(a string) uint64 {
	b := netip.MustParseAddr(a).As4()
	return uint64(binary.BigEndian.Uint32(b[:]))
}

// NET-3, ENF-shared-src-1 (#5300): a lease the real dnsmasq ends early
// stays the old holder's in the enforcer's sets, and the server cannot give
// its address to another host until the element runs out. dnsmasq leases
// three addresses on Guests; host A leases the first and renews it, so its
// unicast messages to the server ride an established connection:
//   - A's DHCPRELEASE, byte for byte as dhcpcd 10.0.6 writes it (measured
//     against this dnsmasq: unicast flags, the message type first, then
//     the server identifier and the end, padded to 300 bytes), never
//     reaches the server: B asking for A's address is refused (NAK), and
//     nothing is held;
//   - a forged RELEASE for A's lease, from another hardware address, with
//     a pad before its message type, reaches the server, which frees the
//     address and leases it to B (its lease file), but the ACK never
//     leaves and is counted on LeaseHeld: B gets no answer and no element;
//   - C leases the second address and moves to the third (a REQUEST
//     naming it): the server frees the second and leases it to D, whose
//     ACK never leaves, while C's elements for both stay;
//   - once A's elements are gone (as if run out), B's renewed REQUEST
//     is answered and leased.
//
// Catches a RELEASE drop after the established accept or matched by
// another offset, an answer check missing or keyed by address alone, a
// snoop that adds the address but not the lease, and a held answer not
// counted.
func TestEarlyEndedLeasesStayHeld(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h, x, leases := guestDnsmasq(t, 0, 2)
	set, addrs := LeaseSet("guests"), LeaseAddrSet("guests")
	server := net.ParseIP(enfAddr("guest")).To4()
	X, Y, Z := segAddr("guest", 0), segAddr("guest", 1), segAddr("guest", 2)
	const A, B, C, D = "02:00:00:00:53:0a", "02:00:00:00:53:0b", "02:00:00:00:53:0c", "02:00:00:00:53:0d"
	none := 1500 * time.Millisecond
	wait := 10 * time.Second
	xid := uint32(0x5300)
	// take is a REQUEST from hw naming addr, as a client sends it after
	// an OFFER (or to move), and the server's answer, if any.
	take := func(hw, addr string, w time.Duration) []byte {
		xid++
		opts := append(append(append([]byte{50, 4}, net.ParseIP(addr).To4()...), 54, 4), server...)
		return dhcpAsk(t, h, x, hw, dhcpMsg(t, 3, xid, hw, netip.Addr{}, opts...), "", w)
	}
	holds := func(addr, hw string) bool {
		m, _ := net.ParseMAC(hw)
		_, ok := element(t, set, addrInt(addr), hwInt(m))
		return ok
	}
	held := func(addr string) bool {
		_, ok := element(t, addrs, addrInt(addr))
		return ok
	}
	listed := func(addr, hw string) bool {
		b, err := os.ReadFile(leases)
		return err == nil && strings.Contains(string(b), " "+hw+" "+addr+" ")
	}
	// release is a RELEASE as dhcpcd 10.0.6 writes it, unless pad puts a
	// pad option before its message type.
	release := func(from, hw, addr string, pad bool) {
		xid++
		m := dhcpMsg(t, 7, xid, hw, netip.MustParseAddr(addr), append([]byte{54, 4}, server...)...)
		m[10] = 0
		if pad {
			m = slices.Insert(m, 240, 0)
		}
		m = append(m, make([]byte, max(0, 300-len(m)))...)
		dhcpAsk(t, h, x, from, m, enfAddr("guest"), 300*time.Millisecond)
	}

	if a := take(A, X, wait); dhcpType(a) != 5 || !holds(X, A) || !held(X) {
		t.Fatalf("A was not leased %s: answer %d, element %v, address %v", X, dhcpType(a), holds(X, A), held(X))
	}
	xid++
	if a := dhcpAsk(t, h, x, A, dhcpMsg(t, 3, xid, A, netip.MustParseAddr(X)), enfAddr("guest"), wait); dhcpType(a) != 5 {
		t.Fatalf("A's renewal: answer %d", dhcpType(a))
	}

	release(A, A, X, false)
	if a := take(B, X, wait); dhcpType(a) != 6 || !listed(X, A) || h.counter(LeaseHeld) != 0 {
		t.Errorf("after A's RELEASE, B asking for %s: answer %d (want NAK), A listed %v, held %d: the RELEASE reached the server", X, dhcpType(a), listed(X, A), h.counter(LeaseHeld))
	}

	release(C, A, X, true)
	if a := take(B, X, none); a != nil || !listed(X, B) || holds(X, B) || !holds(X, A) || h.counter(LeaseHeld) != 1 {
		t.Errorf("after a padded RELEASE: B got answer %d, the server leased %s to B %v, B's element %v, A's %v, held %d; want the server to lease it and the ACK dropped and counted once", dhcpType(a), X, listed(X, B), holds(X, B), holds(X, A), h.counter(LeaseHeld))
	}

	if a := take(C, Y, wait); dhcpType(a) != 5 {
		t.Fatalf("C was not leased %s: answer %d", Y, dhcpType(a))
	}
	if a := take(C, Z, wait); dhcpType(a) != 5 || !holds(Z, C) || listed(Y, C) {
		t.Fatalf("C did not move to %s: answer %d, element %v, still listed on %s %v", Z, dhcpType(a), holds(Z, C), Y, listed(Y, C))
	}
	if a := take(D, Y, none); a != nil || !listed(Y, D) || holds(Y, D) || !holds(Y, C) || !holds(Z, C) || h.counter(LeaseHeld) != 2 {
		t.Errorf("after C moved: D got answer %d, the server leased %s to D %v, D's element %v, C's %v and %v, held %d; want the ACK dropped and counted, and C's kept", dhcpType(a), Y, listed(Y, D), holds(Y, D), holds(Y, C), holds(Z, C), h.counter(LeaseHeld))
	}
	if _, n, err := Held([]byte(run(t, "nft", "-j", "list", "table", "inet", Table))); n != 2 || err != nil {
		t.Errorf("Held reads %d, %v from the running table; want 2", n, err)
	}

	hwA, _ := net.ParseMAC(A)
	run(t, "nft", "delete", "element", "inet", Table, set, "{ "+leaseElem(uint32(addrInt(X)), hwInt(hwA))+" }")
	run(t, "nft", "delete", "element", "inet", Table, addrs, "{ "+addrElem(uint32(addrInt(X)))+" }")
	if a := take(B, X, wait); dhcpType(a) != 5 || !holds(X, B) || !held(X) {
		t.Errorf("once A's elements ran out, B asking for %s: answer %d, element %v, address %v; want it leased", X, dhcpType(a), holds(X, B), held(X))
	}
}

// NET-3 (#5294, #5295): Seed renders each lease on a shared segment's
// interface into that segment's lease set, and its hardware address into
// the leased set once, for the longest time any of its leases has left. A
// lease on another interface, of an IPv6, mapped or unspecified address,
// of a hardware address that is not Ethernet's, with no time left or more
// than LeaseTimeout, is left out. Catches a seed into the wrong segment, a
// duplicated element (nft refuses the load) and a lease that outlives the
// server's.
func TestSeedRendersLeases(t *testing.T) {
	l := fixtureLayout()
	hw := func(s string) net.HardwareAddr {
		m, err := net.ParseMAC(s)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	a := netip.MustParseAddr
	const one, ten = "02:00:00:00:00:01", "02:00:00:00:00:0a"
	got := Seed(l, []Lease{
		{l.Guests, a("10.30.0.3"), hw(one), 200},
		{l.Guests, a("10.30.0.2"), hw(one), 100},
		{l.Guests, a("10.30.0.3"), hw(ten), 300}, // an address listed with two hardware addresses
		{l.Owner, a("10.10.0.2"), hw(ten), LeaseTimeout},
		{l.Owner, a("10.10.0.3"), hw(ten), LeaseTimeout + 1},
		{l.Owner, a("10.10.0.4"), hw(ten), 0},
		{l.Household, a("fd10:20::2"), hw(ten), 100},
		{l.Household, a("::ffff:10.20.0.2"), hw(ten), 100},
		{l.Household, a("0.0.0.0"), hw(ten), 100},
		{l.Household, a("10.20.0.2"), hw("02:00:00:00:00:00:00:01"), 100},
		{l.Admin, a("10.40.0.2"), hw(ten), 100},
		{l.Trunk + ".101", a("10.101.0.2"), hw(ten), 100},
	})
	want := strings.Join([]string{
		"add element inet enforcer lease_guests_4 { 0x0a1e0002 . 0x020000000001 expires 100s, 0x0a1e0003 . 0x020000000001 expires 200s, 0x0a1e0003 . 0x02000000000a expires 300s }",
		"add element inet enforcer leaseaddr_guests_4 { 0x0a1e0002 expires 100s, 0x0a1e0003 expires 300s }",
		"add element inet enforcer leased_guests { 0x020000000001 expires 200s, 0x02000000000a expires 300s }",
		"add element inet enforcer lease_owner_4 { 0x0a0a0002 . 0x02000000000a expires 43200s }",
		"add element inet enforcer leaseaddr_owner_4 { 0x0a0a0002 expires 43200s }",
		"add element inet enforcer leased_owner { 0x02000000000a expires 43200s }",
	}, "\n") + "\n"
	if got != want {
		t.Errorf("seeded:\n%s\nwant:\n%s", got, want)
	}
	if got := Seed(l, nil); got != "" {
		t.Errorf("no leases seeded %q", got)
	}
}

// NET-3 (#5294): every lease time dnsmasq grants, MinLease to LeaseTimeout
// seconds, falls in exactly one lease band, whose floor is at most the
// lease and more than two thirds of it, so its element never outlives the
// lease and outlives half of it (the client's renewal) by a sixth.
// Catches a band gap or overlap, a floor above a lease, and a band wider
// than one and a half times its floor (a ratio of 2 would let an element
// run out as the client renews).
func TestLeaseBandsCoverEveryLease(t *testing.T) {
	bands := leaseBands()
	if bands[0][0] != MinLease || bands[len(bands)-1] != [2]int{LeaseTimeout, LeaseTimeout} {
		t.Fatalf("bands %v: want MinLease first and LeaseTimeout alone last", bands)
	}
	for l := MinLease; l <= LeaseTimeout; l++ {
		var in [][2]int
		for _, b := range bands {
			if b[0] <= l && l <= b[1] {
				in = append(in, b)
			}
		}
		if len(in) != 1 || 3*in[0][0] <= 2*l {
			t.Fatalf("a %d s lease is in bands %v; want one, floor over two thirds of it", l, in)
		}
	}
}
