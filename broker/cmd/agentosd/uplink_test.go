package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/localapi"
)

// REQ: ONB-4

const (
	v4Head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
	v4AP   = "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
)

// P2-2w c4: only an up, non-reject default route on an interface other
// than lo counts as an uplink; the access point's subnet does not.
func TestDefaultRoute(t *testing.T) {
	v6lo := "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
	v6local := "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001     eth0\n"
	for _, c := range []struct {
		name   string
		v4, v6 string
		want   bool
	}{
		{"v4 default on wlan1", v4Head + v4AP + "wlan1\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n", v6lo, true},
		{"v6 default on eth0", v4Head + v4AP, v6lo + "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003     eth0\n", true},
		{"lo reject default and a link route", v4Head + v4AP, v6lo + v6local, false},
		{"a down v4 default", v4Head + v4AP + "wlan1\t00000000\t0101A8C0\t0002\t0\t0\t600\t00000000\t0\t0\t0\n", "", false},
		{"a v4 reject default", v4Head + "eth0\t00000000\t00000000\t0201\t0\t0\t0\t00000000\t0\t0\t0\n", "", false},
		{"a v4 default on lo", v4Head + "lo\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n", "", false},
		{"empty", "", "", false},
	} {
		if got := defaultRoute(c.v4, c.v6); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// Progress is ready with an uplink and offline without. The uplink is
// the core's cable to the enforcer (D-178): there is no join to wait on.
func TestUplinkProgress(t *testing.T) {
	on := false
	progress := progressOf(func() bool { return on })
	if p := progress(); p != (localapi.SetupProgress{Phase: "offline"}) {
		t.Fatalf("offline gave %+v", p)
	}
	on = true
	if p := progress(); p != (localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}) {
		t.Fatalf("online gave %+v", p)
	}
}
