package nft

// REQ: NET-2, NET-3

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
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

// free drops the hold and claim of address addr by hardware address hw on
// seg, as if its holder had sent nothing for ClaimTimeout.
func (h *home) free(seg, addr, hw string, v6 bool) {
	h.t.Helper()
	run(h.t, "nft", "delete", "element", "inet", Table, HeldSet(nftSeg(seg), v6), "{ "+addr+" }")
	run(h.t, "nft", "delete", "element", "inet", Table, ClaimSet(nftSeg(seg), v6), "{ "+addr+" . "+hw+" }")
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
//     sent nothing for ClaimTimeout): the second host now holds the
//     address, but the flow's record names the first host's hardware
//     address, so its datagram is still dropped (bound), and once the hold
//     is free again the first host's own flow goes on;
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
			h.free(seg, a, macA[seg], v6)
			h.inject(seg+"2", local, port, peer, "expired")
			if f.heard("expired") {
				t.Errorf("%s: a datagram injected into a flow after its host's hold ran out arrived", why)
			}
			h.free(seg, a, macB[seg], v6)
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

// NET-3, NET-2 Device paths (#4480): Reload carries each shared segment's
// host records, holds and claims into its own set, with the time each had
// left, and a record refreshed past its set's timeout keeps a timeout of
// its own. Each element is parsed and written again: one that is
// malformed, of the wrong family, with no time left or more than its set
// allows, or in another table, is left out, so nothing in a listing
// reaches the load as text. Catches a carry that copies a listing's text,
// that drops a segment's sets, or that writes a long record past its
// set's timeout (nft refuses the load).
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
		HostSet("household", true):                 {hostEl("7", "fd10:20::2", "fd10:20::2", hw2, 3600)},
		HeldSet("owner", true):                     {el(`"fd10:10::2"`, 50), el(`"10.10.0.2"`, 50), el(`"fe80::1%eth0"`, 50), el(`"::ffff:10.10.0.2"`, 50)},
		HeldSet("owner", false):                    {el(`"10.10.0.2"`, 21600), el(`"10.10.0.3"`, 21601)},
		ClaimSet("owner", false):                   {el(`{"concat": ["10.10.0.2", "02:00:00:00:00:0A"]}`, 60), el(`{"concat": ["10.10.0.3", "nope"]}`, 60)},
		"ip/enforcer/" + HeldSet("owner", false):   {el(`"10.10.0.7"`, 50)},
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
		"add element inet enforcer claim_owner_4 { 10.10.0.2 . 02:00:00:00:00:0a expires 60s }",
		"add element inet enforcer held_owner_4 { 10.10.0.2 expires 21600s }",
		"add element inet enforcer held_owner_6 { fd10:10::2 expires 50s }",
		"add element inet enforcer host_guests_4 { 123 . 10.30.0.2 . 10.30.0.2 . 02:00:00:00:00:01 expires 100s, 124 . 10.30.0.2 . 10.30.0.2 . 02:00:00:00:00:01 timeout 400000s expires 400000s }",
		"add element inet enforcer host_household_6 { 7 . fd10:20::2 . fd10:20::2 . 02:00:00:00:00:02 expires 3600s }",
	}, "\n") + "\n"
	if extra != want {
		t.Errorf("carried:\n%s\nwant:\n%s", extra, want)
	}
	if got, err := Reload(d, l, nil); err != nil || got != base {
		t.Errorf("first load: %v, carried %q", err, strings.TrimPrefix(got, base))
	}
}
