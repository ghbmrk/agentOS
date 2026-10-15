package netguard

// REQ: DEV-2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"testing"
)

func TestGateway4(t *testing.T) {
	tbl := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\n" +
		"wlan0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n" +
		"eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n"
	if g := Gateway4(tbl); g != netip.MustParseAddr("192.168.0.1") {
		t.Fatalf("lowest metric gateway: %v", g)
	}
	if Gateway4("eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\n").IsValid() {
		t.Fatal("a connected route is not a gateway")
	}
}

func TestGateway6(t *testing.T) {
	z := "00000000000000000000000000000000"
	tbl := z + " 00 " + z + " 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n" +
		"20010db8000000000000000000000000 40 " + z + " 00 " + z + " 00000100 00000001 00000000 00000001 eth0\n"
	if g := Gateway6(tbl); g != netip.MustParseAddr("fe80::1") {
		t.Fatalf("gateway: %v", g)
	}
	if g, dev := gateway6(tbl); g != netip.MustParseAddr("fe80::1") || dev != "eth0" {
		t.Fatalf("gateway6: %v %q", g, dev)
	}
}

func TestNameserver(t *testing.T) {
	cases := map[string]string{
		"# c\nnameserver 0.0.0.0\nnameserver 192.168.1.53\n": "192.168.1.53",
		"nameserver fe80::1%eth0\nnameserver 192.168.1.1\n":  "192.168.1.1",
		"nameserver fe80::1%eth0\n":                          "",
		"nameserver 127.0.0.53\n":                            "",
		"nameserver ::1\nnameserver 10.0.0.2\n":              "10.0.0.2",
		"nameserver ::ffff:192.168.1.9\n":                    "192.168.1.9",
		"search home\n":                                      "",
	}
	for in, want := range cases {
		got := Nameserver(in)
		if (want == "" && got.IsValid()) || (want != "" && got != netip.MustParseAddr(want)) {
			t.Fatalf("%q: %v", in, got)
		}
	}
}

func TestPrefixesMaskAndSkipLoopback(t *testing.T) {
	as := []net.Addr{
		&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("fd00::5"), Mask: net.CIDRMask(64, 128)},
		&net.IPAddr{IP: net.ParseIP("10.0.0.1")},
	}
	got := Prefixes(as)
	if len(got) != 2 || got[0] != netip.MustParsePrefix("192.168.1.0/24") || got[1] != netip.MustParsePrefix("fd00::/64") {
		t.Fatalf("%v", got)
	}
}

func TestSourcesReadLearnsAndKeepsExternalOnFailure(t *testing.T) {
	files := map[string]string{
		"/proc/net/route": "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
			"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n",
		"/etc/resolv.conf": "nameserver 192.168.1.53\n",
	}
	ext := netip.MustParseAddr("198.51.100.7")
	fail := false
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) {
			if fail {
				return netip.Addr{}, errors.New("no answer")
			}
			return ext, nil
		},
	}
	n, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if n.Gateway != netip.MustParseAddr("192.168.1.1") || n.Resolver != netip.MustParseAddr("192.168.1.53") || n.External != ext || len(n.Prefixes) != 1 {
		t.Fatalf("%+v", n)
	}
	fail = true
	if n, _ = s.Read(); n.External != ext {
		t.Fatalf("external lost while the gateway is unchanged: %v", n.External)
	}
	files["/proc/net/route"] = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0201A8C0\t0003\t0\t0\t100\t00000000\n"
	if n, _ = s.Read(); n.External.IsValid() {
		t.Fatalf("external kept across a gateway change: %v", n.External)
	}
	s.Addrs = func() ([]net.Addr, error) { return nil, errors.New("no netlink") }
	if _, err := s.Read(); err == nil {
		t.Fatal("a read with no interfaces must fail so the last learned set stays")
	}
}

// REQ: DEV-2
func TestReadFailsWithoutAnInterfacePrefix(t *testing.T) {
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)}}, nil
		},
		ReadFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("a loopback-only list must not replace the learned set")
	}
}

// REQ: DEV-2
func TestStubResolverIsNotLearned(t *testing.T) {
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.7"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(f string) ([]byte, error) {
			switch f {
			case "/run/systemd/resolve/resolv.conf":
				return []byte("# No DNS servers known.\n"), nil
			case "/etc/resolv.conf":
				return []byte("nameserver 127.0.0.53\n"), nil
			}
			return nil, os.ErrNotExist
		},
	}
	n, err := s.Read()
	if err != nil || n.Resolver.IsValid() {
		t.Fatalf("%v %v", n.Resolver, err)
	}
	p := New(Config{})
	p.Learn(Network{Resolver: netip.MustParseAddr("127.0.0.53")})
	if p.Check(WithPurpose(context.Background(), PurposeDNS), netip.MustParseAddr("127.0.0.53"), 53, "udp") == nil {
		t.Fatal("loopback DNS allowed")
	}
}

// ReadLocal reads the same network as Read without asking the router, and
// keeps the last external address while the gateway is unchanged.
func TestReadLocalSkipsTheRouterAndKeepsTheLastExternal(t *testing.T) {
	asked := 0
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(24, 32)}}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if p == "/proc/net/route" {
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) {
			asked++
			return netip.MustParseAddr("8.8.8.8"), nil
		},
	}
	n, err := s.ReadLocal()
	if err != nil || asked != 0 || n.External.IsValid() {
		t.Fatalf("local read: %+v %v asked=%d", n, err, asked)
	}
	if _, err := s.Read(); err != nil || asked != 1 {
		t.Fatalf("full read: %v asked=%d", err, asked)
	}
	n, _ = s.ReadLocal()
	if n.External != netip.MustParseAddr("8.8.8.8") || asked != 1 {
		t.Fatalf("external not kept: %+v asked=%d", n, asked)
	}
}

// The router's external address is kept per gateway: a return to a gateway
// read before gets that gateway's own address from the quick read, and keeps
// it when that router does not answer; a never-seen gateway gets none. The
// table is bounded, the least recently read gateway going first (#1517).
func TestSourcesKeepExternalPerGateway(t *testing.T) {
	gw := "0101A8C0"
	var answer netip.Addr
	s := &Sources{
		Addrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.168.1.77"), Mask: net.CIDRMask(16, 32)}}, nil
		},
		ReadFile: func(p string) ([]byte, error) {
			if p == "/proc/net/route" {
				return []byte("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t" + gw + "\t0003\t0\t0\t100\t00000000\n"), nil
			}
			return nil, errors.New("absent")
		},
		External: func(context.Context, netip.Addr) (netip.Addr, error) {
			if !answer.IsValid() {
				return netip.Addr{}, errors.New("no answer")
			}
			return answer, nil
		},
	}
	e1, e2 := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	answer = e1
	if n, _ := s.Read(); n.External != e1 {
		t.Fatalf("G1 read: %v", n.External)
	}
	gw, answer = "0102A8C0", e2
	if n, _ := s.Read(); n.External != e2 {
		t.Fatalf("G2 read: %v", n.External)
	}
	gw, answer = "0101A8C0", netip.Addr{} // back to G1, whose router is silent
	if n, _ := s.ReadLocal(); n.External != e1 {
		t.Fatalf("quick read back on G1: %v, want G1's %v", n.External, e1)
	}
	if n, _ := s.Read(); n.External != e1 {
		t.Fatalf("full read back on silent G1: %v, want G1's %v", n.External, e1)
	}
	gw = "0103A8C0"
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("a never-seen gateway got %v", n.External)
	}
	// Fill the table past its bound with other gateways; G1 and G2 are the
	// oldest and are forgotten.
	for i := 0; i < maxGatewayExternals; i++ {
		gw, answer = fmt.Sprintf("%02X01A8C0", 0x10+i), netip.AddrFrom4([4]byte{203, 0, 113, byte(i + 1)})
		if _, err := s.Read(); err != nil {
			t.Fatal(err)
		}
	}
	if len(s.exts) > maxGatewayExternals {
		t.Fatalf("table holds %d gateways, bound %d", len(s.exts), maxGatewayExternals)
	}
	gw = "0101A8C0"
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("an evicted gateway kept %v", n.External)
	}
}

// The neighbour table gives the gateway's MAC: a complete entry on the
// default route's interface, never an incomplete one or another interface's.
func TestGatewayMAC(t *testing.T) {
	arp := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         02:00:00:00:00:AA     *        wlan0\n" +
		"192.168.1.1      0x1         0x2         02:00:00:00:00:bb     *        eth0\n" +
		"192.168.1.2      0x1         0x0         02:00:00:00:00:cc     *        eth0\n" +
		"192.168.1.3      0x1         0x2         00:00:00:00:00:00     *        eth0\n"
	gw := netip.MustParseAddr("192.168.1.1")
	if m := NeighbourMAC(arp, gw, "eth0"); m != "02:00:00:00:00:bb" {
		t.Fatalf("eth0 entry: %q", m)
	}
	if m := NeighbourMAC(arp, gw, "wlan0"); m != "02:00:00:00:00:aa" {
		t.Fatalf("wlan0 entry, normalised: %q", m)
	}
	if m := NeighbourMAC(arp, netip.MustParseAddr("192.168.1.2"), "eth0"); m != "" {
		t.Fatalf("an incomplete entry gave %q", m)
	}
	if m := NeighbourMAC(arp, netip.MustParseAddr("192.168.1.3"), "eth0"); m != "" {
		t.Fatalf("an all-zero MAC gave %q", m)
	}
	if m := NeighbourMAC(arp, gw, "eth1"); m != "" {
		t.Fatalf("another interface's entry gave %q", m)
	}
	if gw, dev := gateway4("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\neth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"); gw != netip.MustParseAddr("192.168.1.1") || dev != "eth0" {
		t.Fatalf("gateway4: %v %q", gw, dev)
	}
}

// A different router behind the same gateway address does not get the
// previous router's external address: not from the quick read, and not from
// its own silent full read. Each router keeps its own (#1536).
func TestSourcesTellRoutersApartBehindOneGatewayAddress(t *testing.T) {
	g := &gwSources{}
	var answer netip.Addr
	g.ext = func(context.Context) (netip.Addr, error) {
		if !answer.IsValid() {
			return netip.Addr{}, errors.New("no answer")
		}
		return answer, nil
	}
	g.gw.Store("0101A8C0")
	g.mac.Store("02:00:00:00:00:0a")
	s := g.sources()
	eA := netip.MustParseAddr("8.8.8.8")
	answer = eA
	if n, _ := s.Read(); n.External != eA {
		t.Fatalf("router A read: %+v", n)
	}
	g.mac.Store("02:00:00:00:00:0b")
	answer = netip.Addr{} // router B is silent
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("router B's quick read got %v", n.External)
	}
	if n, _ := s.Read(); n.External.IsValid() {
		t.Fatalf("router B's silent full read got %v", n.External)
	}
	g.mac.Store("") // a link flap flushed the neighbour entry
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("a quick read with no neighbour entry got %v", n.External)
	}
	g.mac.Store("02:00:00:00:00:0a")
	if n, _ := s.ReadLocal(); n.External != eA {
		t.Fatalf("back on router A: %v, want %v", n.External, eA)
	}
	// The NAT-PMP request itself resolves the neighbour entry: an answer read
	// with no entry at the start is filed under the MAC seen after it.
	eC := netip.MustParseAddr("9.9.9.9")
	g.gw.Store("0103A8C0")
	g.mac.Store("")
	g.ext = func(context.Context) (netip.Addr, error) {
		g.mac.Store("02:00:00:00:00:0c")
		return eC, nil
	}
	if n, _ := s.Read(); n.External != eC {
		t.Fatalf("answer with the entry resolved during the read: %+v", n)
	}
	if n, _ := s.ReadLocal(); n.External != eC {
		t.Fatalf("router C's answer not kept: %v", n.External)
	}
}

// A NAT-PMP answer is the router's at the gateway the request went to. If
// the gateway changes while the request is in flight (another address, or
// the same address with another router's MAC), that answer is dropped:
// neither returned nor filed under either gateway. The read asks the
// gateway it ended on instead, and returns that router's answer, or none if
// it is silent; a second change returns ErrGatewayMoved (#1536).
func TestGatewayChangeDuringNATPMPAsksTheEndGateway(t *testing.T) {
	x, y := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	for _, tc := range []struct{ name, gw2, mac2 string }{
		{"new address", "0102A8C0", "02:00:00:00:00:0b"},
		{"same address, new router", "0101A8C0", "02:00:00:00:00:0b"},
	} {
		for _, end := range []string{"answers", "silent", "moves again"} {
			t.Run(tc.name+", end router "+end, func(t *testing.T) {
				g := &gwSources{}
				g.gw.Store("0101A8C0")
				g.mac.Store("02:00:00:00:00:0a")
				calls := 0
				g.ext = func(context.Context) (netip.Addr, error) {
					calls++
					switch {
					case calls == 1:
						g.gw.Store(tc.gw2) // the move lands during the wait
						g.mac.Store(tc.mac2)
						return x, nil
					case end == "answers":
						return y, nil
					case end == "moves again":
						g.gw.Store("0103A8C0")
						return y, nil
					}
					return netip.Addr{}, errors.New("no answer")
				}
				s := g.sources()
				n, err := s.Read()
				if end == "moves again" {
					if !errors.Is(err, ErrGatewayMoved) || n.Gateway != netip.MustParseAddr("192.168.3.1") || n.External.IsValid() {
						t.Fatalf("a read moved under twice: %+v, %v", n, err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if calls != 2 {
					t.Fatalf("router asked %d times, want 2", calls)
				}
				want := netip.Addr{}
				if end == "answers" {
					want = y
				}
				if end != "moves again" && n.External != want {
					t.Fatalf("read across the move: %v, want the end router's %v", n.External, want)
				}
				g.ext = func(context.Context) (netip.Addr, error) { return netip.Addr{}, errors.New("no answer") }
				for _, k := range []struct{ gw, mac string }{{tc.gw2, tc.mac2}, {"0103A8C0", tc.mac2}, {"0101A8C0", "02:00:00:00:00:0a"}} {
					g.gw.Store(k.gw)
					g.mac.Store(k.mac)
					got, _ := s.ReadLocal()
					if got.External == x || (got.External.IsValid() && got.External != want) {
						t.Fatalf("gateway %s %s has %v filed", k.gw, k.mac, got.External)
					}
				}
			})
		}
	}
}

// A first request that times out while the gateway changes is followed by
// one to the gateway it ended on.
func TestTimedOutNATPMPAcrossAMoveAsksTheEndGateway(t *testing.T) {
	y := netip.MustParseAddr("9.9.9.9")
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	calls := 0
	g.ext = func(ctx context.Context) (netip.Addr, error) {
		calls++
		if calls == 1 {
			g.gw.Store("0102A8C0")
			return netip.Addr{}, context.DeadlineExceeded
		}
		return y, nil
	}
	n, err := g.sources().Read()
	if err != nil || n.External != y || calls != 2 {
		t.Fatalf("read: %+v, %v after %d requests", n, err, calls)
	}
}

// When the host read after the router's answer fails, Read returns that
// failure and files nothing.
func TestFailedReadAfterNATPMPFilesNothing(t *testing.T) {
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	g.ext = func(context.Context) (netip.Addr, error) {
		g.down.Store(true)
		return netip.MustParseAddr("8.8.8.8"), nil
	}
	s := g.sources()
	if _, err := s.Read(); err == nil {
		t.Fatal("Read hid the failed host read")
	}
	g.down.Store(false)
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("filed %v across a failed host read", n.External)
	}
}

// Two routers that both answer at one gateway address keep their own
// external addresses: filing B's does not evict A's.
func TestTwoAnsweringRoutersAtOneAddressKeepTheirOwn(t *testing.T) {
	eA, eB := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	g := &gwSources{}
	answer := eA
	g.ext = func(context.Context) (netip.Addr, error) { return answer, nil }
	g.gw.Store("0101A8C0")
	g.mac.Store("02:00:00:00:00:0a")
	s := g.sources()
	if n, _ := s.Read(); n.External != eA {
		t.Fatalf("router A: %v", n.External)
	}
	g.mac.Store("02:00:00:00:00:0b")
	answer = eB
	if n, _ := s.Read(); n.External != eB {
		t.Fatalf("router B: %v", n.External)
	}
	g.mac.Store("02:00:00:00:00:0a")
	if n, _ := s.ReadLocal(); n.External != eA {
		t.Fatalf("back on router A: %v, want %v", n.External, eA)
	}
}

// The gateway's interface is part of its key: a point-to-point gateway with
// no neighbour entry does not lend its router's address to the same gateway
// address on another interface that has no entry yet.
func TestGatewayKeyedByInterface(t *testing.T) {
	g := &gwSources{}
	g.ext = func(context.Context) (netip.Addr, error) { return netip.MustParseAddr("8.8.8.8"), nil }
	g.gw.Store("0101A8C0")
	g.dev.Store("ppp0")
	s := g.sources()
	if n, _ := s.Read(); n.GatewayDev != "ppp0" || !n.External.IsValid() {
		t.Fatalf("ppp0 read: %+v", n)
	}
	g.dev.Store("eth0")
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("eth0 at the same address got ppp0's %v", n.External)
	}
}

// A read whose gateway moves to another interface at the same address (no
// neighbour entry on either side) during the router request drops that
// answer and asks the gateway it ended on; nothing is filed under the
// interface it started on.
func TestInterfaceMoveDuringNATPMPAsksTheEndGateway(t *testing.T) {
	x, y := netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("9.9.9.9")
	g := &gwSources{}
	g.gw.Store("0101A8C0")
	g.dev.Store("ppp0")
	calls := 0
	g.ext = func(context.Context) (netip.Addr, error) {
		calls++
		if calls == 1 {
			g.dev.Store("wlan0") // the move lands during the wait
			return x, nil
		}
		return y, nil
	}
	s := g.sources()
	n, err := s.Read()
	if err != nil || calls != 2 || n.GatewayDev != "wlan0" || n.External != y {
		t.Fatalf("read across the interface move: %+v, %v after %d requests; want wlan0's router %v", n, err, calls, y)
	}
	g.dev.Store("ppp0")
	if n, _ := s.ReadLocal(); n.External.IsValid() {
		t.Fatalf("ppp0 has %v filed from a request whose gateway moved", n.External)
	}
}

// The default route's interface is the chosen row's, not the last default
// row's.
func TestGateway4InterfaceIsTheChosenRoutes(t *testing.T) {
	tbl := "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n" +
		"wlan0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\n" +
		"eth0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\n"
	if g, dev := gateway4(tbl); g != netip.MustParseAddr("192.168.0.1") || dev != "wlan0" {
		t.Fatalf("gateway4: %v %q, want 192.168.0.1 on wlan0", g, dev)
	}
}
