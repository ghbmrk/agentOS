package mdns

// REQ: NET-3

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft"
	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
)

func heardNames(ns ...string) [][]string {
	var out [][]string
	for _, n := range ns {
		out = append(out, dn(n))
	}
	return out
}

// TestHeardOwnNames: the relay learns which names a device proves its
// own by the record filter's rule, whatever it pinned (D-266, ENF-f-m3,
// m4): a host whose address is on its own link, never the enforcer's,
// and an instance whose SRV names such a host, each of class IN and
// shown, kept as said. A name on another link's address, the enforcer's
// own address, a service on a foreign host, a hostile label, another
// class, a query's records, or a name another interface claims is not
// heard; a goodbye or the TTL ends a name; and a name a policy cannot
// pin (a dot in a label, a bare underscore service) is never offered.
func TestHeardOwnNames(t *testing.T) {
	f := NewFilter()
	f.Hear("hh0", response([]record{a("macbook.local", "10.11.0.2", 120)}, nil), t0)
	m := response([]record{
		a("Printer.local", "10.13.0.2", 120),
		a("Printer.local", "fd00:13::2", 120),
		srv("Office._ipp._tcp.local", "Printer.local", 120),
		txt("Office._ipp._tcp.local", 120),
		ptr("_ipp._tcp.local", "Office._ipp._tcp.local", 120),
		a("elsewhere.local", "10.11.0.2", 120),              // another link
		a("gateway.local", "10.13.0.1", 120),                // the enforcer's own
		srv("Fake._smb._tcp.local", "elsewhere.local", 120), // a foreign host
		a("macbook.local", "10.13.0.2", 120),                // claimed on hh0
		srv("Mac._smb._tcp.local", "macbook.local", 120),    // on that host
		a("bidi‮.local", "10.13.0.2", 120),                  // hostile
		a("dot.ted.local", "10.13.0.2", 120),                // three labels: not a host
		{name: name{"a.b", "local"}, typ: typeA, class: 1, ttl: 120, data: []byte{10, 13, 0, 2}},
		srv("Bare._._tcp.local", "Printer.local", 120),
		{name: dn("chaos.local"), typ: typeA, class: 3, ttl: 120, data: []byte{10, 13, 0, 2}},
	}, nil)
	f.Hear("ap0.105", m, t0)
	f.Prove("ap0.105", printerLink, m, t0)
	want := heardNames("Office._ipp._tcp.local", "Printer.local")
	if got := f.Heard("ap0.105", t0); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("heard %q, want %q", got, want)
	}
	// A query proves nothing, not even its known answers or probe records.
	q := &message{questions: []question{{dn("tv.local"), typeA, 1}}, answers: []record{a("tv.local", "10.13.0.2", 120)}, authority: []record{a("tv.local", "10.13.0.2", 120)}}
	f.Prove("ap0.105", printerLink, q, t0)
	if got := f.Heard("ap0.105", t0); slices.ContainsFunc(got, func(n []string) bool { return n[0] == "tv" }) {
		t.Errorf("a query proved a name: %q", got)
	}
	// Another interface claims the instance later: no longer offered.
	f.Hear("hh0", response([]record{srv("Office._ipp._tcp.local", "macbook.local", 120)}, nil), t0.Add(time.Second))
	if got, want := f.Heard("ap0.105", t0.Add(time.Second)), heardNames("Printer.local"); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("heard %q after the claim, want %q", got, want)
	}
	// A goodbye ends the host now; a live record beside it keeps it.
	f.Prove("ap0.105", printerLink, response([]record{a("Printer.local", "10.13.0.2", 0), a("Printer.local", "fd00:13::2", 120)}, nil), t0.Add(2*time.Second))
	if got := f.Heard("ap0.105", t0.Add(2*time.Second)); len(got) != 1 {
		t.Errorf("a goodbye beside a live record ended the name: %q", got)
	}
	f.Prove("ap0.105", printerLink, response([]record{a("Printer.local", "10.13.0.2", 0)}, nil), t0.Add(3*time.Second))
	if got := f.Heard("ap0.105", t0.Add(3*time.Second)); len(got) != 0 {
		t.Errorf("after the goodbye: %q", got)
	}
	// The TTL ends a name, at most ownHold after it was heard.
	f.Prove("ap0.105", printerLink, response([]record{a("long.local", "10.13.0.2", 1<<30)}, nil), t0)
	if got := f.Heard("ap0.105", t0.Add(ownHold-time.Second)); len(got) != 1 {
		t.Errorf("before ownHold: %q", got)
	}
	if got := f.Heard("ap0.105", t0.Add(ownHold)); len(got) != 0 {
		t.Errorf("past ownHold: %q", got)
	}
	// Only the interface it was heard on.
	if got := f.Heard("ap0.106", t0); len(got) != 0 {
		t.Errorf("another interface heard %q", got)
	}
}

// TestHeardBounded: a flood of names on one interface keeps at most
// maxNames there, and its labels go with the names a sweep drops.
func TestHeardBounded(t *testing.T) {
	f := NewFilter()
	for i := range 3 * maxNames {
		f.Prove("ap0.105", printerLink, response([]record{a(fmt.Sprintf("h%d.local", i), "10.13.0.2", 120)}, nil), t0)
	}
	if n, s := len(f.proved["ap0.105"]), len(f.said["ap0.105"]); n > maxNames || s != n {
		t.Errorf("%d names and %d labels kept, want at most %d each", n, s, maxNames)
	}
}

// TestHearOnlyPassesNothing: an interface the plan only hears (an
// unpaired device's VLAN, nft.Hears) is listened on, read under its own
// limit, and its sender's names are learned, but nothing heard there
// goes anywhere (D-266, acceptance 4); a paired interface still relays.
// HeardBy finds a device's names by its Wi-Fi identity.
func TestHearOnlyPassesNothing(t *testing.T) {
	hears, err := nft.Hears(fixturePolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	p := plan(t).Hearing(hears)
	if !slices.Contains(p.Ifaces(), "ap0.101") {
		t.Fatalf("the plan does not listen on the unpaired TV: %v", p.Ifaces())
	}
	r := newRelayer(p, func(string) []netip.Prefix { return printerLink }, t0)
	tv := response([]record{a("tv-answer.local", "10.13.0.2", 120), srv("Den._airplay._tcp.local", "tv-answer.local", 120)}, nil).bytes()
	legacy := response([]record{a("legacy.local", "10.13.0.2", 120)}, nil).bytes()
	for _, c := range []struct {
		port uint16
		pkt  []byte
	}{{5353, tv}, {40000, legacy}} {
		if out, outs := r.handle("ap0.101", c.port, c.pkt, t0); out != nil || outs != nil {
			t.Errorf("the unpaired TV's answer from port %d went to %v", c.port, outs)
		}
	}
	if out, outs := r.handle("ap0.101", 5353, (&message{questions: []question{{dn("x.local"), typeA, 1}}}).bytes(), t0); out != nil || outs != nil {
		t.Errorf("the unpaired TV's query went to %v", outs)
	}
	heard := HeardBy(r.f, fixtureLayout())
	// HeardBy reads the clock; names heard at t0 are long gone by now, so
	// the filter is read at t0 directly and HeardBy only for its mapping.
	// What did not come from mDNS's port proves nothing.
	if got, want := r.f.Heard("ap0.101", t0), heardNames("Den._airplay._tcp.local", "tv-answer.local"); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("heard %q, want %q", got, want)
	}
	r.f.Prove("ap0.101", printerLink, response([]record{a("now.local", "10.13.0.2", 120)}, nil), time.Now())
	if got := heard("vlan101"); !slices.EqualFunc(got, heardNames("now.local"), slices.Equal) {
		t.Errorf("HeardBy(vlan101) = %q", got)
	}
	if got := heard("vlan105"); len(got) != 0 {
		t.Errorf("HeardBy(vlan105) = %q", got)
	}
	if got := heard("not-a-vlan"); got != nil {
		t.Errorf("HeardBy(not-a-vlan) = %q", got)
	}
	// The read limit holds on a hear-only interface too.
	for range readBurst {
		r.handle("ap0.101", 5353, tv, t0)
	}
	r.handle("ap0.101", 5353, response([]record{a("late.local", "10.13.0.2", 120)}, nil).bytes(), t0)
	if slices.ContainsFunc(r.f.Heard("ap0.101", t0), func(n []string) bool { return n[0] == "late" }) {
		t.Error("the read limit did not stop the packet past its burst")
	}
	// The printer's pair still relays.
	if out, outs := r.handle("ap0.105", 5353, response([]record{a("printer-answer.local", "10.13.0.2", 120)}, nil).bytes(), t0); out == nil || !slices.Equal(outs, []string{"hh0"}) {
		t.Errorf("the printer's answer went to %v", outs)
	}
}

// TestHearOnly: real packets, through the loaded ruleset and a relay that
// also hears every device's VLAN, over IPv4 and IPv6 (D-266, acceptance
// 4): the unpaired TV's announcement and query reach no other host, the
// relay learns the TV's names, and the paired printer's answer still
// reaches Household.
func TestHearOnly(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) { hearOnly(t, v6) })
	}
}

func hearOnly(t *testing.T, v6 bool) {
	if !inNetns(t) {
		return
	}
	if v6 && !hasKernelIPv6() {
		if required() {
			t.Fatal("the kernel has no IPv6")
		}
		t.Skip("the kernel has no IPv6")
	}
	l := fixtureLayout()
	text, err := nft.Compile(fixturePolicy(), l)
	if err != nil {
		t.Fatal(err)
	}
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	if err := (load.Loader{Bin: nftBin}).Load(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	// Every interface the relay listens on, and the Owner network.
	nets := map[string]int{"own0": 10, "hh0": 11, "ap0.101": 12, "ap0.102": 13, "ap0.103": 14, "ap0.104": 15, "ap0.105": 16, "ap0.106": 17, "ap0.107": 18}
	hosts, socks := map[string]int{}, map[string]*net.UDPConn{}
	for ifc, n := range nets {
		hosts[ifc] = newHost(t, ifc, n, v6)
		socks[ifc] = mdnsSocket(t, hosts[ifc], v6, 5353)
	}
	addr := func(ifc string) string {
		if v6 {
			return fmt.Sprintf("fd00:%d::2", nets[ifc])
		}
		return fmt.Sprintf("10.%d.0.2", nets[ifc])
	}
	hears, err := nft.Hears(fixturePolicy(), l)
	if err != nil {
		t.Fatal(err)
	}
	f := NewFilter()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, plan(t).Hearing(hears), f) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	time.Sleep(200 * time.Millisecond)
	send := func(ifc string, m *message) {
		within(t, hosts[ifc], func() {
			if _, err := socks[ifc].WriteToUDP(m.bytes(), group(v6)); err != nil {
				t.Fatal(err)
			}
		})
		time.Sleep(20 * time.Millisecond)
	}
	send("ap0.101", response([]record{a("tv-answer.local", addr("ap0.101"), 120), srv("Den._airplay._tcp.local", "tv-answer.local", 120)}, nil))
	send("ap0.101", &message{questions: []question{{dn("tv-query.local"), typeA, 1}}})
	send("ap0.105", response([]record{a("printer-answer.local", addr("ap0.105"), 120)}, nil))
	heard := map[string][]string{}
	buf := make([]byte, maxPacket)
	for ifc, c := range socks {
		c.SetReadDeadline(time.Now().Add(time.Second))
		for {
			n, _, err := c.ReadFromUDP(buf)
			if err != nil {
				break
			}
			m, ok := parse(buf[:n])
			if !ok {
				t.Fatalf("%s heard a malformed packet", ifc)
			}
			for _, r := range m.answers {
				heard[ifc] = append(heard[ifc], r.name[0])
			}
			for _, q := range m.questions {
				heard[ifc] = append(heard[ifc], "?"+q.name[0])
			}
		}
	}
	if want := map[string][]string{"hh0": {"printer-answer"}}; fmt.Sprint(heard) != fmt.Sprint(want) {
		t.Errorf("heard %v, want %v", heard, want)
	}
	if got, want := f.Heard("ap0.101", time.Now()), heardNames("Den._airplay._tcp.local", "tv-answer.local"); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the relay heard the TV prove %q, want %q", got, want)
	}
}
