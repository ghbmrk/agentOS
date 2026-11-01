package nft

// REQ: NET-2, NET-3

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"
)

// segIfc is the enforcer's interface for a shared segment's stand-in host.
func segIfc(seg string) string {
	l := fixtureLayout()
	return map[string]string{"owner": l.Owner, "household": l.Household, "guest": l.Guests}[seg]
}

// segAddr is the address of host i (0, 1, ...) on segment seg, and seg6Addr
// its IPv6 one; seg6Net is the segment's IPv6 prefix, as seg6 numbers it.
func segAddr(seg string, i int) string { return segNets[seg] + "." + strconv.Itoa(2+i) }
func seg6Net(seg string) string        { return "fd10:" + strings.Split(segNets[seg], ".")[1] + "::" }
func seg6Addr(seg string, i int) string {
	return seg6Net(seg) + strconv.Itoa(2+i)
}

// share makes segment seg shared, as a Wi-Fi network with one password is:
// the enforcer's interface becomes a bridge, with seg's host and a second
// host, named seg+"2", each on its own port with its own hardware address
// and address on the segment (and IPv6 ones when the kernel has IPv6).
func (h *home) share(seg string) {
	t := h.t
	t.Helper()
	ifc := segIfc(seg)
	run(t, "ip", "link", "del", ifc) // and seg's host's end with it
	run(t, "ip", "link", "add", ifc, "type", "bridge")
	run(t, "ip", "addr", "add", enfAddr(seg)+"/24", "dev", ifc)
	if h.v6 {
		run(t, "ip", "addr", "add", seg6Net(seg)+"1/64", "dev", ifc, "nodad")
	}
	run(t, "ip", "link", "set", ifc, "up")
	for i, name := range []string{seg, seg + "2"} {
		x := h.hosts[name]
		if x == nil {
			x = h.newHost(name)
			h.listen(x)
		}
		port := fmt.Sprintf("%s.%d", ifc, i)
		run(t, "ip", "link", "add", port, "type", "veth", "peer", "name", "eth0", "netns", strconv.Itoa(x.pid))
		run(t, "ip", "link", "set", port, "master", ifc)
		run(t, "ip", "link", "set", port, "up")
		h.in(x, "ip", "addr", "add", segAddr(seg, i)+"/24", "dev", "eth0")
		h.in(x, "ip", "link", "set", "eth0", "up")
		h.in(x, "ip", "route", "add", "default", "via", enfAddr(seg))
		if h.v6 {
			h.in(x, "ip", "addr", "add", seg6Addr(seg, i)+"/64", "dev", "eth0", "nodad")
			h.in(x, "ip", "-6", "route", "add", "default", "via", seg6Net(seg)+"1")
		}
	}
}

// NET-2 Device paths, NET-3 (#4324): on a shared segment (Guests, Owner,
// Household) a related packet passes only from the host that started the
// connection it names. On each, two hosts each hold a connection to the
// internet, and on Household each also one to the printer it is paired
// with. The second host forges an ICMP error about the first host's
// connection, as the first would send it about a packet from its peer:
// once from its own address and once from the first host's (a host on a
// shared segment can take any address on it, and the reverse-path filter
// passes it). Neither arrives, though both cross the very interfaces the
// first host's connection runs on, which is all the connection mark binds
// (ENF-ct-bind-1). The first host's own error about its own connection
// arrives, and so does the second host's about its own, which shows the
// forger's channel works and the drop is the host binding. A load empties
// the host records, so after it the forgery is still dropped and the
// first host's own error on a connection opened before the load is dropped
// too (it fails closed), while one on a connection opened after the load
// arrives. When the second host also copies the first host's hardware
// address, its forgery from its own address is still dropped, and one
// from the first host's address too passes: copying both makes it that
// host to the enforcer. Catches a binding by interface alone, by address
// alone (the spoofed forgery), by hardware address alone (the copied
// one), and a learn or bound chain that is never reached.
func TestSharedSegmentRelatedBound(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d := cutPolicy()
	text, err := Compile(d, fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	h.load(text)
	h.fillSets()
	segs := []string{"guest", "owner", "household"}
	for _, seg := range segs {
		h.share(seg)
	}
	fams := []bool{false}
	if h.v6 {
		fams = append(fams, true)
	}

	// path is one kind of connection a shared host starts: to the
	// internet, or along a pair to a device.
	type path struct {
		to   string // the host that accepts it
		addr func(v6 bool) string
		why  string
	}
	internet := path{"isp", func(v6 bool) string {
		if v6 {
			return net6Other
		}
		return netOther
	}, "the internet"}
	printer := path{"105", func(v6 bool) string {
		if v6 {
			return devAddr6(105)
		}
		return devAddr(105)
	}, "the printer it is paired with"}

	type conn struct {
		seg  string
		v6   bool
		p    path
		a, b *held // the first host's and the second host's
	}
	port := 9400
	open := func(seg string, v6 bool, p path, who string) *held {
		port++
		return h.hold(fmt.Sprintf("%s %s to %s (v6 %v)", seg, who, p.why, v6), who, p.to, p.addr(v6), port)
	}
	var conns []conn
	hearing := map[string]*tags{}
	at := func(host string, v6 bool) *tags {
		k := fmt.Sprintf("%s %v", host, v6)
		if hearing[k] == nil {
			hearing[k] = h.hear(host, v6)
		}
		return hearing[k]
	}
	for _, v6 := range fams {
		for _, seg := range segs {
			ps := []path{internet}
			if seg == "household" {
				ps = append(ps, printer)
			}
			for _, p := range ps {
				at(p.to, v6)
				conns = append(conns, conn{seg: seg, v6: v6, p: p, a: open(seg, v6, p, seg), b: open(seg, v6, p, seg+"2")})
			}
		}
	}
	addrOf := func(seg string, i int, v6 bool) string {
		if v6 {
			return seg6Addr(seg, i)
		}
		return segAddr(seg, i)
	}
	// errAbout is an ICMP error about x as its starting host sees a packet
	// from the far end.
	errAbout := func(c conn, x *held, tag uint16) []byte {
		local, lport := hostPort(t, x.c.LocalAddr())
		remote, rport := hostPort(t, x.c.RemoteAddr())
		return icmpErr(c.v6, tag, remote, local, rport, lport)
	}
	// spoof gives the second host the first host's address too, so it can
	// send from it.
	for _, seg := range segs {
		h.in(h.hosts[seg+"2"], "ip", "addr", "add", segAddr(seg, 0)+"/32", "dev", "lo")
		if h.v6 {
			h.in(h.hosts[seg+"2"], "ip", "addr", "add", seg6Addr(seg, 0)+"/128", "dev", "lo", "nodad")
		}
	}

	macs := map[string]string{} // each second host's own hardware address
	for _, seg := range segs {
		macs[seg] = h.mac(h.hosts[seg+"2"], "eth0")
	}

	type sent struct {
		c    conn
		what string
	}
	var tag uint16 = 1700
	round := func(want map[string]bool, cs []conn, reopened bool) {
		t.Helper()
		got := map[uint16]sent{}
		send := func(c conn, from, bind string, x *held, what string) {
			tag++
			got[tag] = sent{c, what}
			h.sendErr(from, bind, c.p.addr(c.v6), c.v6, errAbout(c, x, tag))
		}
		for _, c := range cs {
			send(c, c.seg+"2", "", c.a, "forged")
			send(c, c.seg+"2", addrOf(c.seg, 0, c.v6), c.a, "spoofed")
			send(c, c.seg, "", c.a, "own")
			send(c, c.seg+"2", "", c.b, "other own")
		}
		time.Sleep(probeWait)
		for tg, s := range got {
			arrived := at(s.c.p.to, s.c.v6).has(tg)
			if arrived != want[s.what] {
				t.Errorf("%s to %s (v6 %v, reopened %v): the %s error arrived %v, want %v", s.c.seg, s.c.p.why, s.c.v6, reopened, s.what, arrived, want[s.what])
			}
		}
	}
	round(map[string]bool{"own": true, "other own": true}, conns, false)
	for _, c := range conns {
		h.expectOpen(true, c.a, c.b)
	}

	// The second host copies the first host's hardware address. From its
	// own address its forgery is still dropped: the record binds the
	// address too. From the first host's address as well it is that host
	// to the enforcer and its error passes (ENF-ct-bind-2's stated limit),
	// which shows the copied hardware address does reach the check.
	setMAC := func(seg, mac string) {
		x := h.hosts[seg+"2"]
		h.in(x, "ip", "link", "set", "eth0", "address", mac)
	}
	for _, seg := range segs {
		setMAC(seg, h.mac(h.hosts[seg], "eth0"))
	}
	copied := map[uint16]sent{}
	for _, c := range conns {
		for what, bind := range map[string]string{"copied hardware address": "", "copied both": addrOf(c.seg, 0, c.v6)} {
			tag++
			copied[tag] = sent{c, what}
			h.sendErr(c.seg+"2", bind, c.p.addr(c.v6), c.v6, errAbout(c, c.a, tag))
		}
	}
	time.Sleep(probeWait)
	for tg, s := range copied {
		if arrived := at(s.c.p.to, s.c.v6).has(tg); arrived != (s.what == "copied both") {
			t.Errorf("%s to %s (v6 %v): the error with the %s arrived %v", s.c.seg, s.c.p.why, s.c.v6, s.what, arrived)
		}
	}
	for _, seg := range segs {
		setMAC(seg, macs[seg])
	}
	for _, c := range conns {
		h.expectOpen(true, c.a, c.b)
	}

	// A load empties the records: the open connections go on, but their
	// hosts' own errors now fail closed; new connections are recorded.
	h.reload(d)
	h.fillSets()
	round(map[string]bool{}, conns, false)
	var fresh []conn
	for _, c := range conns {
		h.expectOpen(true, c.a, c.b)
		fresh = append(fresh, conn{seg: c.seg, v6: c.v6, p: c.p, a: open(c.seg, c.v6, c.p, c.seg), b: open(c.seg, c.v6, c.p, c.seg+"2")})
	}
	round(map[string]bool{"own": true, "other own": true}, fresh, true)
}
