package nft

// REQ: NET-3, NET-7

import (
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

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
// the paths it keeps open, the internet ones included although the load
// empties the allow sets. Catches a "stop" the owner signed that the
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
		h.load(base)
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
		text, err := Compile(c.doc, fixtureLayout())
		if err != nil {
			t.Fatal(err)
		}
		h.load(text)
		for name, x := range hs {
			x.why = c.name + ": " + x.why
			h.expectOpen(!slices.Contains(c.cut, name), x)
		}
	}
}

// fillSets puts the fixture's resolved addresses in the allow sets, as
// slice f's resolver would after a load.
func (h *home) fillSets() {
	run(h.t, "nft", "add", "element", "inet", Table, DeviceSet(101, false), "{ "+netAllow+" }")
	run(h.t, "nft", "add", "element", "inet", Table, CoreSet(false), "{ "+netCore+" }")
	if h.v6 {
		run(h.t, "nft", "add", "element", "inet", Table, DeviceSet(101, true), "{ "+net6Allow+" }")
	}
}
