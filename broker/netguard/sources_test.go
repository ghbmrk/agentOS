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
