package devslot_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// REQ: DEV-2, DEV-3, DEV-8

// tcpDecl is the fixture's declaration on a TCP link.
func tcpDecl() devslot.Declaration {
	d := fixture.Declaration()
	d.Link = devslot.TCP
	d.Channels = []devslot.Channel{{Name: "control", Port: 8443}}
	d.Shapes = d.Shapes[:1]
	d.Shapes[0].Kind = devslot.TCPFrame
	d.Operations[0].Shapes = []string{d.Shapes[0].Name}
	return d
}

func TestHomeAddr(t *testing.T) {
	home := netip.MustParsePrefix("2a02:1234:5678:ab00::/56")
	cases := []struct {
		host string
		home netip.Prefix
		ok   bool
	}{
		{"10.0.0.255", netip.Prefix{}, false},
		{"192.168.1.255", netip.Prefix{}, false},
		{"172.16.255.255", netip.Prefix{}, false},
		{"169.254.255.255", netip.Prefix{}, false},
		{"::ffff:10.0.0.255", netip.Prefix{}, false},
		{"100.64.1.2", netip.Prefix{}, true},
		{"100.127.255.254", netip.Prefix{}, true},
		{"100.128.0.1", netip.Prefix{}, false},
		{"192.168.1.20", netip.Prefix{}, true},
		{"fd00::20", netip.Prefix{}, true},
		{"2a02:1234:5678:abcd::5", home, true},
		{"2a02:1234:5678:abcd::5", netip.Prefix{}, false},
		{"2a02:1234:5679::5", home, false},
		{"2a02:1234:5678:abcd::5", netip.MustParsePrefix("2a02:1234::/32"), false},
		{"::ffff:8.8.8.8", netip.MustParsePrefix("::ffff:0:0/56"), false},
		{"ff02::1", home, false},
		{"::1", home, false},
		{"0.0.0.0", netip.Prefix{}, false},
	}
	for _, c := range cases {
		p := devslot.Pin{Host: netip.MustParseAddr(c.host), Key: [32]byte{9}}
		if err := devslot.Check(tcpDecl(), p, c.home); (err == nil) != c.ok {
			t.Errorf("%s in %v: %v, want accepted %v", c.host, c.home, err, c.ok)
		}
	}
}

func TestCanonicalIgnoresEmptyLists(t *testing.T) {
	a := fixture.Declaration()
	b := fixture.Declaration()
	a.Operations[0].Shapes = append(a.Operations[0].Shapes[:0:0], a.Operations[0].Shapes...)
	b.Readings = append([]string{}, b.Readings...)
	ca, _ := devslot.Canonical(a)
	cb, _ := devslot.Canonical(b)
	if !bytes.Equal(ca, cb) {
		t.Fatalf("one declaration, two canonical forms")
	}
	c := fixture.Declaration()
	c.Shapes[0].Prefix = []byte{}
	c.Shapes[0].Min = 1
	d := c
	d.Shapes = append([]devslot.Shape(nil), c.Shapes...)
	d.Shapes[0].Prefix = nil
	cc, _ := devslot.Canonical(c)
	cd, _ := devslot.Canonical(d)
	if !bytes.Equal(cc, cd) {
		t.Fatalf("an empty and a missing prefix read differently")
	}
}

func FuzzWire(f *testing.F) {
	for _, m := range []devslot.Msg{
		{T: devslot.MsgDeclare, B: []byte("{}")},
		devslot.PinMsg("read-temperature", devslot.Pin{Host: netip.MustParseAddr("fd00::1"), Key: [32]byte{1}},
			netip.MustParsePrefix("2a02:1234:5678:ab00::/56")),
		{T: devslot.MsgWrite, Ch: "control", B: []byte{1, 2, 3}},
		{T: devslot.MsgReading, Kind: "temperature", Value: -5, Exp: -2, Time: "2026-10-27T10:00:00Z"},
		{T: devslot.MsgDone, Err: devslot.Failed},
	} {
		var b bytes.Buffer
		devslot.WriteMsg(&b, m)
		f.Add(b.Bytes())
	}
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := devslot.ReadMsg(bytes.NewReader(b))
		if len(b) >= 4 {
			if n := binary.BigEndian.Uint32(b); (n == 0 || n > devslot.MaxMsg) && !errors.Is(err, devslot.ErrWire) {
				t.Fatalf("a length of %d was read: %v", n, err)
			}
		}
		if err != nil {
			return
		}
		var out bytes.Buffer
		if err := devslot.WriteMsg(&out, m); err != nil {
			t.Fatalf("a decoded message does not encode: %v", err)
		}
		enc := bytes.Clone(out.Bytes())
		back, err := devslot.ReadMsg(&out)
		var again bytes.Buffer
		devslot.WriteMsg(&again, back)
		if err != nil || !bytes.Equal(again.Bytes(), enc) {
			t.Fatalf("round trip: %+v, %v; want %+v", back, err, m)
		}
	})
}
