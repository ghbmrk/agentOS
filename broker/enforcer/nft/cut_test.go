package nft

// REQ: NET-3, NET-7, NET-2, KRN-12

import (
	"context"
	"net"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// cutPolicy is the fixture with one test port on each path class, so a
// held connection on each can be opened alongside the fixture's own
// listeners: the TV's control (the edge's path), the speaker's control (the
// core's), the camera's stream (the core's).
func cutPolicy() policy.Document {
	d := fixturePolicy()
	d.Devices = slices.Clone(d.Devices)
	for i, dev := range d.Devices {
		switch dev.ID {
		case "tv", "speaker":
			d.Devices[i].Control = append(slices.Clone(dev.Control), policy.Port{Proto: policy.ProtoTCP, Num: 9100})
		case "cam":
			d.Devices[i].Stream = append(slices.Clone(dev.Stream), policy.Port{Proto: policy.ProtoTCP, Num: 9100})
		}
	}
	return d
}

// held is one TCP connection held open across a load: c is the end that
// started it, s the end that accepted it.
type held struct {
	why  string
	c, s net.Conn
}

// hold opens a TCP connection from host from to addr:port, accepted by a
// listener in host to's namespace.
func (h *home) hold(why, from, to, addr string, port int) *held {
	t := h.t
	t.Helper()
	var ln *net.TCPListener
	within(t, h.hosts[to], func() {
		l, err := net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("%s: listen: %v", why, err)
		}
		ln = l.(*net.TCPListener)
		// A device on IPv6 says one word to its gateway first, as a real
		// one does when it joins (router solicitation, address checks),
		// which quiet() turns off here: the enforcer learns its link
		// address from that solicitation. Left silent, the enforcer's own
		// solicitation over the fixture's VLANs went unanswered in CI (its
		// neighbour entry stayed INCOMPLETE, no rule dropped anything) and
		// the dial timed out under the unchanged ruleset.
		if gw, ok := strings.CutSuffix(addr, "::2"); ok && strings.HasPrefix(addr, "fd00:") {
			if c, err := net.Dial("udp", net.JoinHostPort(gw+"::1", "9")); err == nil {
				c.Write([]byte{0})
				c.Close()
			}
		}
	})
	defer ln.Close()
	x := &held{why: why}
	var dialErr error
	within(t, h.hosts[from], func() {
		x.c, dialErr = net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), 2*time.Second)
	})
	if dialErr != nil {
		// What each side knows of the other, for a failure seen only in CI.
		t.Logf("enforcer neighbours:\n%s", run(t, "ip", "neigh", "show"))
		for _, n := range []string{from, to} {
			t.Logf("%s:\n%s%s", n, h.in(h.hosts[n], "ip", "addr", "show"), h.in(h.hosts[n], "ip", "neigh", "show"))
		}
		t.Logf("blocked: %d, spoofed: %d", h.counter(Blocked), h.counter(Spoofed))
		t.Fatalf("%s: dial: %v", why, dialErr)
	}
	ln.SetDeadline(time.Now().Add(2 * time.Second))
	var err error
	if x.s, err = ln.Accept(); err != nil {
		t.Fatalf("%s: accept: %v", why, err)
	}
	t.Cleanup(func() { x.c.Close(); x.s.Close() })
	return x
}

// passes sends one byte each way and reports whether each arrived: from
// the end that started the connection, and back from the end that
// accepted it.
func passes(a, b net.Conn) bool {
	if _, err := a.Write([]byte{1}); err != nil {
		return false
	}
	b.SetReadDeadline(time.Now().Add(probeWait))
	_, err := b.Read(make([]byte, 1))
	return err == nil
}

// expectOpen checks each held connection both ways: open when want is
// true, cut both ways otherwise.
func (h *home) expectOpen(want bool, hs ...*held) {
	h.t.Helper()
	for _, x := range hs {
		there, back := passes(x.c, x.s), passes(x.s, x.c)
		if there != want || back != want {
			h.t.Errorf("%s: there %v, back %v, want %v", x.why, there, back, want)
		}
	}
}

// NET-3, NET-7, A18: a load that removes a path also ends the connections
// already open along it, both ways, and a load leaves the connections on
// the paths it keeps open, the internet ones included (their names stay
// listed, so Reload keeps their answers). Catches a "stop" the owner signed that the
// firewall applies to new connections only, while the old ones flow on
// until they idle out.
func TestCutPathEndsOpenConnections(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	base, err := Compile(cutPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	noPairs := cutPolicy()
	noPairs.Pairs = nil
	frozen := cutPolicy()
	frozen.Holds = frozenPolicy().Holds
	narrowed := cutPolicy()
	for i, dev := range narrowed.Devices {
		switch dev.ID {
		case "speaker":
			narrowed.Devices[i].Control = dev.Control[:len(dev.Control)-1] // its test port dropped
		case "tv":
			narrowed.Devices[i].VendorCloud = false // off the internet, so the edge's path goes too
		case "cam":
			narrowed.Devices[i].Isolated = true
		}
	}
	for _, c := range []struct {
		name string
		doc  policy.Document
		cut  []string
	}{
		{name: "the pairs removed", doc: noPairs, cut: []string{"pair", "household pair", "pair v6"}},
		{name: "both pairs frozen at one end", doc: frozen, cut: []string{"pair", "household pair", "pair v6"}},
		{name: "a port, a vendor cloud and a camera cut", doc: narrowed, cut: []string{"core control", "edge control", "tv internet", "tv internet v6", "core stream"}},
	} {
		t.Logf("case: %s", c.name)
		h.load(withDrops(t, cutPolicy(), base))
		h.fillSets()
		hs := map[string]*held{
			"pair":           h.hold("a device pair", "106", "107", devAddr(107), 9301),
			"household pair": h.hold("Household's pair", "household", "105", devAddr(105), 9302),
			"core control":   h.hold("the core to an offline device", "core", "102", devAddr(102), 9100),
			"edge control":   h.hold("the edge to an online device", "edge", "101", devAddr(101), 9100),
			"core stream":    h.hold("the core to a camera's stream", "core", "104", devAddr(104), 9100),
			"tv internet":    h.hold("a device to its allow list", "101", "isp", netAllow, 9201),
			"core internet":  h.hold("the core to its list", "core", "isp", netCore, 9202),
			"owner internet": h.hold("Owner to the internet", "owner", "isp", netOther, 9203),
			"guest internet": h.hold("a guest to the internet", "guest", "isp", netOther, 9204),
		}
		if h.v6 {
			hs["pair v6"] = h.hold("a device pair over IPv6", "106", "107", devAddr6(107), 9305)
			hs["tv internet v6"] = h.hold("a device to its allow list over IPv6", "101", "isp", net6Allow, 9205)
		}
		var all []*held
		for _, x := range hs {
			all = append(all, x)
		}
		h.expectOpen(true, all...)
		h.reload(c.doc)
		for name, x := range hs {
			x.why = c.name + ": " + x.why
			h.expectOpen(!slices.Contains(c.cut, name), x)
		}
	}
}

// fillSets puts the fixture's resolved addresses in the allow sets and
// their names' sets, as slice f's resolver would after a load.
func (h *home) fillSets() {
	d := fixturePolicy()
	h.answer(d, DeviceSet(101, false), "tv.example", netAllow)
	h.answer(d, CoreSet(false), "core.example", netCore)
	if h.v6 {
		h.answer(d, DeviceSet(101, true), "tv.example", net6Allow)
	}
}

// NET-3 (#4367, ENF-ct-bind-1): a connection open when this ruleset is
// first loaded fails closed. One that conntrack already tracked, under an
// earlier ruleset that set no mark, has mark 0, so the load cuts it, both
// ways, and it stays cut; the cut happens once, since the same paths open
// again for new connections, which the ruleset marks. One that conntrack
// never saw (no ruleset used it) is picked up at its next packet as a new
// connection and judged by the ruleset like any other: on an allowed path
// it goes on, bound to that path, and on none it is refused and counted.
func TestFirstLoadCutsOnce(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	text, err := Compile(cutPolicy(), fixtureLayout())
	if err != nil {
		t.Fatal(err)
	}
	load := func() {
		h.load(withDrops(t, cutPolicy(), text))
		h.fillSets()
	}

	h.load("flush ruleset\ntable inet before {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tct state established,related accept\n\t}\n}\n")
	tracked := []*held{
		h.hold("a device pair, tracked before the first load", "106", "107", devAddr(107), 9321),
		h.hold("the edge to an online device, tracked before the first load", "edge", "101", devAddr(101), 9100),
	}
	h.expectOpen(true, tracked...)
	load()
	h.expectOpen(false, tracked...)
	h.expectOpen(true,
		h.hold("a device pair, after the first load", "106", "107", devAddr(107), 9322),
		h.hold("the edge to an online device, after the first load", "edge", "101", devAddr(101), 9100),
	)
	h.expectOpen(false, tracked...)

	run(t, "nft", "flush", "ruleset")
	allowed := h.hold("a device pair, untracked before the load", "106", "107", devAddr(107), 9323)
	none := h.hold("a device to a device on no path, untracked before the load", "102", "103", devAddr(103), 9324)
	h.expectOpen(true, allowed, none)
	load()
	before := h.counter(Blocked)
	h.expectOpen(true, allowed)
	h.expectOpen(false, none)
	if h.counter(Blocked) == before {
		t.Error("the connection on no path was not counted as refused")
	}
}

// NET-2 Byte caps, KRN-12 (#5014): a cut edge reaches nothing through the
// enforcer. The drop's text on its own cuts the edge's open connections,
// to a device and to the internet, both ways, and refuses new ones, while
// the core's go on; a full load that carries the cut (a restart) keeps
// it; a text without it lifts it, and the edge's paths open again. #5282: the kernel cuts the edge itself at the first
// byte past its cap, with no write of the daemon's (TripSet); a full load
// whose count is past the cap starts cut; the owner's lift on the day
// (Drop.EdgeHold) opens the edge's device paths while its quota still
// holds the internet; the next day's quota starts it uncut.
func TestEdgeCutEndsEveryEdgePath(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	d, l := cutPolicy(), fixtureLayout()
	text, err := Compile(d, l)
	if err != nil {
		t.Fatal(err)
	}
	h.load(withDrops(t, d, text))
	h.fillSets()
	nftBin, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	loader := load.Loader{Bin: nftBin}
	drop := func(cut bool) Drop { p := fresh(d); p.EdgeCut = cut; return p }
	apply := func(p Drop) {
		t.Helper()
		running, err := loader.List(context.Background(), Table)
		if err != nil {
			t.Fatal(err)
		}
		u, err := Drops(d, l, running, p)
		if err != nil {
			t.Fatal(err)
		}
		if err := loader.Update(context.Background(), u); err != nil {
			t.Fatal(err)
		}
	}
	update := func(cut bool) { t.Helper(); apply(drop(cut)) }
	// refused: a new connection from the edge gets no answer.
	refused := func(why, to, addr string, port int) {
		t.Helper()
		var ln net.Listener
		within(t, h.hosts[to], func() {
			if ln, err = net.Listen("tcp", net.JoinHostPort(addr, strconv.Itoa(port))); err != nil {
				t.Fatalf("%s: listen: %v", why, err)
			}
		})
		defer ln.Close()
		within(t, h.hosts["edge"], func() {
			if c, err := net.DialTimeout("tcp", net.JoinHostPort(addr, strconv.Itoa(port)), probeWait); err == nil {
				c.Close()
				t.Errorf("%s: a new connection passed while the edge is cut", why)
			}
		})
	}
	// edgeHolds are the edge's held connections to a device and to the
	// internet, over IPv4 (its segment's only family, ENF-e-6), on ports
	// from port.
	devices := func(why string) []*held {
		return []*held{h.hold("the edge to an online device"+why, "edge", "101", devAddr(101), 9100)}
	}
	edgeHolds := func(why string, port int) (device, internet []*held) {
		return devices(why), []*held{h.hold("the edge to the internet"+why, "edge", "isp", netOther, port)}
	}
	// A hostile edge's IPv6 (ENF-e-6: the segment is IPv4 only, and the
	// enforcer answers no neighbour discovery there): it gives itself an
	// address and a static neighbour entry for the enforcer, so its
	// datagrams reach the enforcer's port without any discovery. None is
	// forwarded, cut or not: no route leads back to the edge's segment for
	// its address, so the reverse-path check drops each as spoofed before
	// the forward chain.
	var edge6 func(why string)
	if h.v6 {
		x := h.hosts["edge"]
		h.in(x, "ip", "addr", "add", "fd10:60::2/64", "dev", "eth0", "nodad")
		h.in(x, "ip", "-6", "route", "add", "default", "dev", "eth0")
		f := strings.Fields(run(t, "ip", "-o", "link", "show", "dev", l.Edge))
		i := slices.Index(f, "link/ether")
		if i < 0 || i+1 >= len(f) {
			t.Fatalf("the enforcer's %s has no hardware address: %q", l.Edge, f)
		}
		h.in(x, "ip", "-6", "neigh", "replace", net6Other, "lladdr", f[i+1], "dev", "eth0", "nud", "permanent")
		edge6 = func(why string) {
			t.Helper()
			var pc net.PacketConn
			within(t, h.hosts["isp"], func() {
				if pc, err = net.ListenPacket("udp", net.JoinHostPort(net6Other, "9270")); err != nil {
					t.Fatalf("%s: listen: %v", why, err)
				}
			})
			defer pc.Close()
			spoofed := h.counter(Spoofed)
			within(t, x, func() {
				c, err := net.Dial("udp", net.JoinHostPort(net6Other, "9270"))
				if err != nil {
					t.Fatalf("%s: dial: %v", why, err)
				}
				defer c.Close()
				for range 3 {
					c.Write([]byte("edge6"))
				}
			})
			pc.SetReadDeadline(time.Now().Add(probeWait))
			if _, _, err := pc.ReadFrom(make([]byte, 16)); err == nil {
				t.Errorf("%s: the edge's IPv6 was forwarded to the internet", why)
			}
			if h.counter(Spoofed) == spoofed {
				t.Errorf("%s: the edge's IPv6 was not dropped as spoofed", why)
			}
		}
		edge6("the edge's IPv6, not cut")
	}
	device, internet := edgeHolds("", 9210)
	core := h.hold("the core to its list", "core", "isp", netCore, 9220)
	h.expectOpen(true, append(append(device, internet...), core)...)

	update(true)
	before := h.counter(EdgeCut)
	h.expectOpen(false, append(device, internet...)...)
	h.expectOpen(true, core)
	if h.counter(EdgeCut) == before {
		t.Error("the cut dropped nothing it counted")
	}
	refused("a new connection to a device", "101", devAddr(101), 9100)
	refused("a new connection to the internet", "isp", netOther, 9212)
	if edge6 != nil {
		edge6("the edge's IPv6, cut")
	}

	// A restart's first load carries the cut in the same transaction.
	u, err := Drops(d, l, nil, drop(true))
	if err != nil {
		t.Fatal(err)
	}
	h.load(text + u)
	h.fillSets()
	h.expectOpen(false, append(device, internet...)...)
	refused("a new connection to a device, after a full load", "101", devAddr(101), 9100)

	update(false)
	device, internet = edgeHolds(", lifted", 9230)
	h.expectOpen(true, append(device, internet...)...)

	// The kernel's own cut (#5282). A new cap starts a new quota and empties
	// TripSet; the edge then sends past it on its internet connection.
	const edgeCap = 4096
	capped := func(day uint32, count uint64, hold bool) Drop {
		p := drop(false)
		p.Day, p.EdgeCap, p.EdgeCount, p.EdgeHold = day, edgeCap, count, hold
		return p
	}
	apply(capped(20000, 0, false))
	device, internet = edgeHolds(", within its cap", 9240)
	h.expectOpen(true, append(device, internet...)...)
	before, drops := h.counter(EdgeCut), h.counter(CapDrop)
	if _, err := internet[0].c.Write(make([]byte, 2*edgeCap)); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(5 * time.Second); h.counter(CapDrop) == drops && time.Now().Before(end); {
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.Contains(run(t, "nft", "list", "set", "inet", Table, TripSet), `"`+l.Edge+`"`) {
		t.Error("the quota stopped a byte and TripSet does not hold the edge")
	}
	h.expectOpen(false, append(device, internet...)...)
	h.expectOpen(true, core)
	if h.counter(EdgeCut) == before {
		t.Error("the kernel's cut dropped nothing it counted")
	}
	refused("a new connection to a device, past the cap", "101", devAddr(101), 9100)

	// A full load whose count is past the cap starts cut, before the record
	// says so or the edge sends again: no path opens across it. The edge's
	// internet connections are reset at both ends first, so it sends
	// nothing after the load that could pass the new quota.
	for _, x := range internet {
		for _, c := range []net.Conn{x.s, x.c} {
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}
	u, err = Drops(d, l, nil, capped(20000, 2*edgeCap, false))
	if err != nil {
		t.Fatal(err)
	}
	h.load(text + u)
	h.fillSets()
	h.expectOpen(false, device...)
	refused("a new connection to a device, after a full load past the cap", "101", devAddr(101), 9100)

	// The owner's lift on the day: the device paths open, the quota still
	// holds the internet.
	apply(capped(20000, 2*edgeCap, true))
	h.expectOpen(true, devices(", lifted on the day")...)
	refused("a new connection to the internet, lifted on the day", "isp", netOther, 9252)

	// The next day's quota starts the edge uncut.
	apply(capped(20001, 0, false))
	device, internet = edgeHolds(", the next day", 9260)
	h.expectOpen(true, append(device, internet...)...)
}
