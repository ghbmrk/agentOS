package nft

// REQ: NET-3, NET-2, NET-1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/nft/load"
)

// TestNetnsSegments runs A18's Segments sentences that need no DNS (the
// allow sets are filled directly; slice f fills them from its resolver)
// against the fixture home. Catches a reachable segment.
func TestNetnsSegments(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	tv, spk, plug, cam, printer, sa, sb, old := "101", "102", "103", "104", "105", "106", "107", "108"
	corePage, page := 443, 8443
	before := map[string]int{}
	for _, c := range counters {
		before[c] = h.counter(c)
	}
	h.expect(
		// A declared device reaches only its allow-listed destinations; an
		// unknown destination is blocked.
		probe{from: tv, addr: netAllow, port: 80, want: connected, why: "allow list"},
		probe{from: tv, addr: netOther, port: 80, why: "unknown destination"},
		probe{from: tv, addr: net6Allow, port: 80, want: connected, why: "allow list, IPv6"},
		probe{from: tv, addr: net6Other, port: 80, why: "unknown destination, IPv6"},
		probe{from: plug, addr: netAllow, port: 80, want: connected, why: "a safety-list device reaches its allow list"},
		probe{from: plug, addr: netOther, port: 80, why: "and nothing else"},
		// Outside DNS and a known encrypted-DNS resolver are blocked, even
		// at an address in the device's allow set.
		probe{from: tv, addr: netDoH, port: 443, why: "outside DoH resolver"},
		// Port 53 to anywhere is answered by the enforcer itself (slice
		// f's redirect; the dns_redirect counter shows it), never outside.
		probe{from: tv, addr: netAllow, port: 53, udp: true, want: connected, why: "outside DNS, redirected to the enforcer"},
		probe{from: tv, addr: netOther, port: 53, want: connected, why: "outside DNS over TCP, redirected to the enforcer"},
		probe{from: tv, addr: netAllow, port: 853, why: "outside DNS over TLS"},
		// A camera and an offline everyday device get no internet; an
		// isolated device gets nothing, its allow list and pairs included.
		probe{from: cam, addr: netAllow, port: 80, why: "camera without cloud"},
		probe{from: spk, addr: netAllow, port: 80, why: "offline everyday device"},
		probe{from: old, addr: netAllow, port: 80, why: "isolated"},
		probe{from: "household", addr: devAddr(108), port: 80, why: "isolated device's pair"},
		// Device to device only on a signed pair, both ways for two
		// devices, from the Household side only for a person's device.
		probe{from: sa, addr: devAddr(107), port: 80, want: connected, why: "signed pair"},
		probe{from: sb, addr: devAddr(106), port: 80, want: connected, why: "signed pair, other way"},
		probe{from: tv, addr: devAddr(102), port: 80, why: "no pair"},
		probe{from: sa, addr: devAddr(103), port: 80, why: "no pair"},
		probe{from: "household", addr: devAddr(105), port: 80, want: connected, why: "Household casts to its paired device"},
		probe{from: printer, addr: segNets["household"] + ".2", port: 80, why: "the device does not start the pair"},
		probe{from: "household", addr: devAddr(102), port: 80, why: "Household device not paired"},
		// Household reaches neither box's admin or control pages; Owner
		// reaches both.
		probe{from: "household", addr: segNets["core"] + ".2", port: corePage, why: "core page from Household"},
		probe{from: "household", addr: enfAddr("household"), port: page, why: "enforcer page from Household"},
		probe{from: "owner", addr: segNets["core"] + ".2", port: corePage, want: connected, why: "core page from Owner"},
		probe{from: "owner", addr: enfAddr("owner"), port: page, want: connected, why: "enforcer page from Owner"},
		probe{from: "admin", addr: enfAddr("admin"), port: page, want: connected, why: "enforcer page from the admin port"},
		probe{from: "owner", addr: segNets["core"] + ".2", port: 22, why: "only the core's page port"},
		probe{from: tv, addr: enfAddr("owner"), port: page, why: "enforcer page from Devices"},
		probe{from: "core", addr: enfAddr("core"), port: page, why: "enforcer page from the core"},
		probe{from: "core", addr: enfAddr("core"), port: 7443, want: connected, why: "the channel"},
		probe{from: tv, addr: enfAddr("core"), port: 7443, why: "the channel from a device"},
		// A guest reaches the internet but neither box, the enforcer, the
		// access point's admin, the ISP router nor any home device.
		probe{from: "guest", addr: netOther, port: 80, want: connected, why: "guest internet"},
		probe{from: "guest", addr: segNets["core"] + ".2", port: corePage, why: "guest to core"},
		probe{from: "guest", addr: segNets["edge"] + ".2", port: 80, why: "guest to edge"},
		probe{from: "guest", addr: enfAddr("guest"), port: page, why: "guest to enforcer page"},
		probe{from: "guest", addr: "10.70.0.2", port: 80, why: "guest to AP admin"},
		probe{from: "guest", addr: ispRouter, port: 80, why: "guest to ISP router"},
		probe{from: "guest", addr: devAddr(101), port: 80, why: "guest to a device"},
		// The access point's admin only from the admin port.
		probe{from: "admin", addr: "10.70.0.2", port: 80, want: connected, why: "AP admin from the admin port"},
		probe{from: "owner", addr: "10.70.0.2", port: 80, why: "AP admin from Owner"},
		probe{from: "core", addr: "10.70.0.2", port: 80, why: "AP admin from the core"},
		probe{from: "edge", addr: "10.70.0.2", port: 80, why: "AP admin from the edge"},
		probe{from: tv, addr: "10.70.0.2", port: 80, why: "AP admin from Devices"},
		// No segment reaches the ISP router's admin or LAN.
		probe{from: "owner", addr: ispRouter, port: 80, why: "ISP router from Owner"},
		probe{from: "core", addr: ispRouter, port: 80, why: "ISP router from the core"},
		probe{from: "edge", addr: ispRouter, port: 80, why: "ISP router from the edge"},
		probe{from: tv, addr: ispRouter, port: 80, why: "ISP router from Devices"},
		probe{from: tv, addr: "2001:db8:1::1", port: 80, why: "ISP router from Devices, IPv6"},
		// The core reaches only its signed list, offline everyday devices'
		// control ports, an offline camera's stream port and no other port
		// of a safety-list device.
		probe{from: "core", addr: netCore, port: 443, want: connected, why: "core's list"},
		probe{from: "core", addr: netOther, port: 443, why: "not on the core's list"},
		probe{from: "core", addr: devAddr(102), port: 80, want: connected, why: "offline everyday device's control port"},
		probe{from: "core", addr: devAddr(102), port: 123, udp: true, want: connected, why: "offline everyday device's UDP control port"},
		probe{from: "core", addr: devAddr(102), port: 443, why: "not its control port"},
		probe{from: "core", addr: devAddr(102), port: 123, why: "its control port on the other protocol"},
		probe{from: "core", addr: devAddr(105), port: 80, why: "an everyday device with no control port"},
		probe{from: "core", addr: devAddr(104), port: 554, want: connected, why: "offline camera's stream port"},
		probe{from: "edge", addr: devAddr(104), port: 554, why: "camera stream from the edge"},
		probe{from: cam, addr: segNets["core"] + ".2", port: 80, why: "the camera does not start it"},
		probe{from: "core", addr: devAddr(101), port: 80, why: "online device: the edge's path"},
		probe{from: "core", addr: devAddr(103), port: 80, why: "safety-list plug"},
		probe{from: "core", addr: devAddr(104), port: 80, why: "safety-list camera"},
		probe{from: spk, addr: segNets["core"] + ".2", port: 80, why: "the device does not start it"},
		// The edge reaches the internet and the online devices it relays,
		// on connections it starts, and nothing else; core and edge
		// segments drop each other both ways.
		probe{from: "edge", addr: netOther, port: 80, want: connected, why: "edge internet"},
		probe{from: "edge", addr: devAddr(101), port: 80, want: connected, why: "online everyday device's control port"},
		probe{from: "edge", addr: devAddr(101), port: 443, why: "not its control port"},
		probe{from: "edge", addr: devAddr(102), port: 80, why: "offline device"},
		probe{from: "edge", addr: devAddr(103), port: 80, why: "safety-list device"},
		probe{from: tv, addr: segNets["edge"] + ".2", port: 80, why: "the device does not start it"},
		probe{from: "edge", addr: segNets["core"] + ".2", port: 80, why: "edge to core segment"},
		probe{from: "core", addr: segNets["edge"] + ".2", port: 80, why: "core to edge segment"},
		probe{from: "edge", addr: segNets["owner"] + ".2", port: 80, why: "edge to Owner"},
		probe{from: "edge", addr: segNets["household"] + ".2", port: 80, why: "edge to Household"},
		probe{from: "edge", addr: segNets["guest"] + ".2", port: 80, why: "edge to Guests"},
		// No inbound connection from the internet, to a device or to the
		// enforcer, which opens no inbound port.
		probe{from: "isp", addr: devAddr(101), port: 80, why: "inbound to a device"},
		probe{from: "isp", addr: devAddr6(101), port: 80, why: "inbound to a device, IPv6"},
		probe{from: "isp", addr: segNets["core"] + ".2", port: 443, why: "inbound to the core"},
		probe{from: "isp", addr: segNets["guest"] + ".2", port: 80, why: "inbound to a guest"},
	)
	var wan []probe
	for _, p := range listenPorts {
		wan = append(wan, probe{from: "isp", addr: enfWAN, port: p, why: "enforcer port from the internet"},
			probe{from: "isp", addr: enfWAN, port: p, udp: true, why: "enforcer port from the internet"})
	}
	h.expect(wan...)

	// A device's router advertisement is dropped at the enforcer.
	if h.v6 {
		ra := h.counter(RADropped)
		sendRA(t, h.hosts[tv], "eth0")
		if h.counter(RADropped) <= ra {
			t.Error("a device's router advertisement was not dropped by the ra_dropped rule")
		}
	}

	after := map[string]int{}
	for _, c := range counters {
		after[c] = h.counter(c)
	}
	for _, c := range []string{Inbound, Blocked, CoreDevice, CoreStream, EdgeDevice, DNSOutside, DNSRedirect, APAdminDrop, ISPDrop, CoreEdge, GuestsOut, GuestsIn, GuestsConns, RADropped} {
		if c == RADropped && !h.v6 {
			continue
		}
		if after[c] <= before[c] {
			t.Errorf("counter %s did not move (%d)", c, after[c])
		}
	}

	// Guests are counted only as a whole: guest traffic that is refused
	// moves no other counter and writes no log line.
	before = after
	h.expect(probe{from: "guest", addr: devAddr(101), port: 80, why: "guest to a device"},
		probe{from: "guest", addr: ispRouter, port: 80, why: "guest to the ISP router"},
		probe{from: "guest", addr: "10.70.0.2", port: 80, why: "guest to AP admin"})
	for _, c := range counters {
		if n := h.counter(c); n != before[c] && !strings.HasPrefix(c, "guests_") {
			t.Errorf("guest traffic moved counter %s", c)
		}
	}
}

// TestCopiedMACGetsOwnList: a device that joins on its own VLAN with
// another device's hardware address gets its own
// (here empty) allow list, not the other device's, and keeps what its own
// policy allows, so the silent probes cannot pass because the copy cut
// the impostor off. Catches identity by hardware address.
func TestCopiedMACGetsOwnList(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	plugMAC := h.mac(h.hosts["103"], "eth0")
	impostor := h.hosts["102"] // the offline speaker: no internet of its own
	if got := h.mac(impostor, "eth0"); got == plugMAC {
		t.Fatalf("before the copy the impostor already has %s, the plug's address, so the copy would change nothing", got)
	}
	h.in(impostor, "ip", "link", "set", "eth0", "down")
	h.in(impostor, "ip", "link", "set", "eth0", "address", plugMAC)
	h.in(impostor, "ip", "link", "set", "eth0", "up")
	if got := h.mac(impostor, "eth0"); got != plugMAC {
		t.Fatalf("the impostor has %s, want the copied %s", got, plugMAC)
	}
	h.in(impostor, "ip", "route", "replace", "default", "via", "10.102.0.1")
	h.expect(
		probe{from: "102", addr: netAllow, port: 80, why: "the copied MAC's allow list"},
		probe{from: "102", addr: devAddr(103), port: 80, why: "the copied device itself"},
		probe{from: "103", addr: netAllow, port: 80, want: connected, why: "the real device keeps its list"},
		// Controls: the impostor's own reach still works with the copied
		// address, out (its DNS, which the enforcer answers) and in (the
		// core to its control port).
		probe{from: "102", addr: netAllow, port: 53, want: connected, why: "control: the impostor's own DNS"},
		probe{from: "core", addr: devAddr(102), port: 80, want: connected, why: "control: the core to the impostor's control port"},
	)
	text, _ := Compile(fixturePolicy(), fixtureLayout())
	// The only hardware address the ruleset reads is in a shared segment's
	// host record (#4324), which no device's traffic reaches.
	text = strings.ReplaceAll(strings.ReplaceAll(text, hostKey(false), ""), hostKey(true), "")
	for _, s := range []string{"ether", "saddr 10.", "saddr fd"} {
		if strings.Contains(text, s) {
			t.Errorf("the ruleset identifies a device by %q", s)
		}
	}
}

// TestEdgeSegmentSilent: the edge's segment gets no reply to DHCP,
// DHCPv6, router solicitation, DNS, NTP or mDNS, no router advertisement
// the enforcer sends, no ARP reply for any address but the gateway's, and
// a scan of every enforcer address finds no open or closed port, while the
// same probes from the core are answered. Catches a listener on the edge's
// segment.
func TestEdgeSegmentSilent(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	gw := enfAddr("edge")
	var ps []probe
	for _, p := range []int{53, 67, 123, 547, 5353} {
		ps = append(ps, probe{from: "edge", addr: gw, port: p, udp: true, why: "service on the edge's gateway"})
	}
	for _, p := range []int{53, 67, 547} {
		ps = append(ps, probe{from: "core", addr: enfAddr("core"), port: p, udp: true, want: connected, why: "control: the probe works"})
	}
	ps = append(ps, probe{from: "edge", addr: "10.60.0.255", port: 67, udp: true, why: "DHCP broadcast"})
	h.expect(ps...)
	if h.v6 {
		h.settled(nil)
		h.settled(h.hosts["core"])
		h.settled(h.hosts["edge"])
	}
	if h.v6 && !dhcpv6(t, h.hosts["core"]) {
		t.Fatal("control: a DHCPv6 solicit from the core's segment was not answered")
	}
	if h.v6 && dhcpv6(t, h.hosts["edge"]) {
		t.Error("a DHCPv6 solicit from the edge's segment was answered")
	}

	// A scan of the enforcer's addresses from the edge: no port answers,
	// not even with a reset.
	var addrs []string
	for _, seg := range []string{"edge", "owner", "household", "guest", "admin", "core", "apm"} {
		addrs = append(addrs, enfAddr(seg))
	}
	addrs = append(addrs, enfWAN)
	var scan []probe
	for p := 1; p <= 1024; p++ {
		scan = append(scan, probe{from: "edge", addr: gw, port: p, why: "scan of the gateway"})
	}
	for _, a := range addrs {
		for _, p := range listenPorts {
			scan = append(scan, probe{from: "edge", addr: a, port: p, why: "scan"},
				probe{from: "edge", addr: a, port: p, udp: true, why: "scan"})
		}
	}
	h.expect(scan...)

	// ARP: the gateway resolves, every other enforcer address does not.
	edge := h.hosts["edge"]
	owner := enfAddr("owner")
	h.in(edge, "ip", "route", "add", owner+"/32", "dev", "eth0")
	h.expect(probe{from: "edge", addr: owner, port: 80, why: "on-link probe"}, probe{from: "edge", addr: gw, port: 80, why: "gateway probe"})
	time.Sleep(3 * time.Second) // the kernel's ARP retries
	if out := h.in(edge, "ip", "neigh", "show", gw); !strings.Contains(out, "lladdr") {
		t.Errorf("the gateway did not answer ARP: %q", out)
	}
	if out := h.in(edge, "ip", "neigh", "show", owner); strings.Contains(out, "lladdr") {
		t.Errorf("the enforcer answered ARP for %s on the edge's segment: %q", owner, out)
	}

	// The edge still reaches the internet and its relayed device.
	h.expect(probe{from: "edge", addr: netOther, port: 443, want: connected, why: "edge internet"},
		probe{from: "edge", addr: devAddr(101), port: 80, want: connected, why: "relayed device"})

	// Router advertisements and solicitations: the enforcer sends none
	// onto the edge's segment, though the same send reaches Owner.
	if !h.v6 {
		return
	}
	if !hearsRA(t, h.hosts["owner"], func() { sendRA(t, nil, "own0") }) {
		t.Fatal("control: an RA sent onto Owner was not heard")
	}
	// The output chain drops the enforcer's own RA onto the edge's
	// segment, which the sender sees as EPERM.
	if hearsRA(t, edge, func() {
		if err := sendICMP6(t, nil, "edge0", "ff02::1", 134); err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatal(err)
		}
	}) {
		t.Error("an RA reached the edge's segment")
	}
	rs := h.counter(EdgeIn)
	sendRS(t, edge)
	if h.counter(EdgeIn) <= rs {
		t.Error("a router solicitation from the edge was not dropped on arrival")
	}
}

// TestLoadFailureKeepsPrevious: a ruleset that fails to load, however far
// into it the error is, leaves the previous ruleset and its set contents
// in force, so a bad update opens no window. Catches an open window on a
// bad update.
func TestLoadFailureKeepsPrevious(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	nftBin, _ := exec.LookPath("nft")
	listing := func() string { return run(t, "nft", "-s", "list", "ruleset") } // -s: without counter values
	was := listing()
	good, _ := Compile(fixturePolicy(), fixtureLayout())
	open := strings.Replace(good, "policy drop;", "policy accept;", -1)
	bad := []string{
		open + "table inet broken {\n\tchain c {\n\t\tbogus\n\t}\n}\n",                            // fails at the end
		strings.Replace(open, "counter name \"blocked\" drop", "counter name \"nosuch\" drop", 1), // a reference that does not resolve
		strings.Replace(good, "flush ruleset\n", "", 1),                                           // would merge, not replace
	}
	l := load.Loader{Bin: nftBin}
	for i, b := range bad {
		if err := l.Load(context.Background(), b); !errors.Is(err, load.ErrLoad) {
			t.Errorf("bad ruleset %d loaded (err %v)", i, err)
		}
		if listing() != was {
			t.Fatalf("bad ruleset %d changed the running ruleset", i)
		}
	}
	if err := (load.Loader{Bin: "nft"}).Load(context.Background(), good); !errors.Is(err, load.ErrLoad) {
		t.Error("a relative nft path was run")
	}
	if err := (load.Loader{Bin: "/nonexistent/nft"}).Load(context.Background(), good); !errors.Is(err, load.ErrLoad) {
		t.Error("a missing nft binary reported success")
	}
	if listing() != was {
		t.Fatal("a failed run changed the running ruleset")
	}
	h.expect(probe{from: "101", addr: netOther, port: 80, why: "still default deny"},
		probe{from: "101", addr: netAllow, port: 80, want: connected, why: "allow set kept"},
		probe{from: "guest", addr: devAddr(101), port: 80, why: "still isolated"})

	// A good load replaces the whole ruleset in one transaction: probes
	// running across it never see an open window.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	leaked := make(chan string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if h.tcp("101", netOther, 80) != silent {
				select {
				case leaked <- "the TV reached an unknown destination during a reload":
				default:
				}
			}
		}
	}()
	for i := 0; i < 20; i++ {
		if err := l.Load(context.Background(), good); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	select {
	case msg := <-leaked:
		t.Error(msg)
	default:
	}
}

// ICMPv6 helpers. A router advertisement is type 134, a solicitation 133;
// both go to all-nodes or all-routers with hop limit 255.
func sendRA(t *testing.T, x *host, ifc string) { must(t, sendICMP6(t, x, ifc, "ff02::1", 134)) }
func sendRS(t *testing.T, x *host)             { must(t, sendICMP6(t, x, "eth0", "ff02::2", 133)) }

func must(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func sendICMP6(t *testing.T, x *host, ifc, dst string, typ byte) error {
	var serr error
	within(t, x, func() {
		c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
		if err != nil {
			t.Fatalf("icmpv6 socket: %v", err)
		}
		defer c.Close()
		msg := []byte{typ, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0}
		if typ == 133 {
			msg = msg[:8]
		}
		if _, err := c.WriteTo(msg, &net.IPAddr{IP: net.ParseIP(dst), Zone: ifc}); err != nil {
			serr = fmt.Errorf("send icmpv6 %d on %s: %w", typ, ifc, err)
		}
	})
	time.Sleep(200 * time.Millisecond)
	return serr
}

func hearsRA(t *testing.T, x *host, send func()) bool {
	var heard bool
	ready := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		within(t, x, func() {
			c, err := net.ListenPacket("ip6:ipv6-icmp", "::")
			if err != nil {
				t.Errorf("icmpv6 socket: %v", err)
				close(ready)
				return
			}
			defer c.Close()
			close(ready)
			c.SetDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1500)
			for {
				n, _, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				if n > 0 && buf[0] == 134 {
					heard = true
					return
				}
			}
		})
	}()
	<-ready
	send()
	<-done
	return heard
}

// dhcpv6 sends a Solicit to all DHCP servers on x's link and reports
// whether anything answered.
func dhcpv6(t *testing.T, x *host) bool {
	var answered bool
	within(t, x, func() {
		c, err := net.ListenUDP("udp6", &net.UDPAddr{Port: 546})
		if err != nil {
			t.Fatalf("dhcpv6 client: %v", err)
		}
		defer c.Close()
		c.WriteTo([]byte{1, 0, 0, 1}, &net.UDPAddr{IP: net.ParseIP("ff02::1:2"), Port: 547, Zone: "eth0"})
		c.SetDeadline(time.Now().Add(probeWait))
		_, _, err = c.ReadFrom(make([]byte, 64))
		answered = err == nil
	})
	return answered
}

// TestSpoofedSourceDropped: a packet whose source address is not routed
// back out of the interface it came in on is dropped, so a rooted core
// cannot answer the enforcer's own upstream DNS query in the resolver's
// name (the answer would fill an allow set), and a device cannot pose as
// the core. The real answer still arrives. Catches a forged answer that
// fills an allow set (NET-2 The core's list, A18 Segments).
func TestSpoofedSourceDropped(t *testing.T) {
	if !inNetns(t) {
		return
	}
	h := build(t)
	before := h.counter(Spoofed)
	// The enforcer asks an "upstream" (an echo at netAllow:5300) from a
	// fixed port, so conntrack holds the flow a forged answer would ride.
	within(t, h.hosts["isp"], func() {
		up, err := net.ListenPacket("udp4", netAllow+":5300")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { up.Close() })
		go func() {
			b := make([]byte, 64)
			for {
				n, from, err := up.ReadFrom(b)
				if err != nil {
					return
				}
				up.WriteTo(b[:n], from)
			}
		}()
	})
	local := &net.UDPAddr{IP: net.ParseIP(enfWAN), Port: 40053}
	pc, err := net.ListenUDP("udp4", local)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if _, err := pc.WriteToUDP([]byte("query"), &net.UDPAddr{IP: net.ParseIP(netAllow), Port: 5300}); err != nil {
		t.Fatal(err)
	}
	// The core forges the answer from the upstream's address and port.
	spoof := func(from, src, dst string, sport, dport int, payload string) {
		x := h.hosts[from]
		h.in(x, "ip", "addr", "add", src+"/32", "dev", "lo")
		within(t, x, func() {
			c, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(src), Port: sport}, &net.UDPAddr{IP: net.ParseIP(dst), Port: dport})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for range 3 {
				c.Write([]byte(payload))
			}
		})
	}
	time.Sleep(100 * time.Millisecond)
	spoof("core", netAllow, enfWAN, 5300, 40053, "forged")
	// A device poses as the core to the enforcer's resolver port.
	spoof("101", "10.50.0.2", enfAddr("core"), 5300, 53, "as-core")
	var got []string
	pc.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	for {
		n, from, err := pc.ReadFromUDP(buf)
		if err != nil {
			break
		}
		got = append(got, from.String()+" "+string(buf[:n]))
	}
	if !slices.Equal(got, []string{netAllow + ":5300 query"}) {
		t.Errorf("the enforcer's upstream socket read %q, want only the real answer", got)
	}
	if n := h.counter(Spoofed) - before; n < 6 {
		t.Errorf("spoofed counter moved %d, want at least 6", n)
	}
}
