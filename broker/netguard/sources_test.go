package netguard

// REQ: DEV-2

import (
	"context"
	"errors"
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
