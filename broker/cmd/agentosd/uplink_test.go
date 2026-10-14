package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/localapi"
	"github.com/ghbmrk/agentos/broker/netjoin"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// REQ: ONB-4, ONB-3, CH-12

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

// Progress is ready with an uplink and offline without; a saved join
// with no uplink for 90 s since is never_online, which an uplink or a
// joined answer clears. The joiner reports each code.
func TestUplinkProgress(t *testing.T) {
	on := false
	now := time.Unix(1_000_000, 0)
	u := &uplink{online: func() bool { return on }, now: func() time.Time { return now }}
	if p := u.progress(); p != (localapi.SetupProgress{Phase: "offline"}) {
		t.Fatalf("offline gave %+v", p)
	}
	on = true
	if p := u.progress(); p != (localapi.SetupProgress{Phase: "ready", Updated: true, Online: true}) {
		t.Fatalf("online gave %+v", p)
	}
	on = false

	var code netjoin.Code = netjoin.Saved
	dir := filepath.Join(t.TempDir(), "run")
	srv := &sockets.Server{Dir: dir}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); srv.Wait() }()
	if err := srv.Start(ctx, sockets.Endpoint{Name: netjoin.Socket, Peer: sockets.Peer{Kind: "agentosd"},
		Ops: map[string]sockets.Handler{netjoin.OpJoin: func(context.Context, sockets.Peer, json.RawMessage) (any, error) {
			return netjoin.Answer{Code: code}, nil
		}}}); err != nil {
		t.Fatal(err)
	}
	join := joiner(filepath.Join(dir, netjoin.Socket), u.seen)
	if err := join(context.Background(), "home", joinCanary); err != nil {
		t.Fatal(err)
	}
	now = now.Add(neverOnlineAfter - time.Second)
	if u.progress().NeverOnline {
		t.Fatal("never online at 89 s")
	}
	now = now.Add(time.Second)
	if p := u.progress(); p != (localapi.SetupProgress{Phase: "offline", NeverOnline: true}) {
		t.Fatalf("at 90 s gave %+v", p)
	}
	// A refused join leaves the wait as it was.
	code = netjoin.Refused
	if join(context.Background(), "home", joinCanary) == nil || !u.progress().NeverOnline {
		t.Fatal("a refusal cleared never online")
	}
	code = netjoin.Joined
	if err := join(context.Background(), "home", joinCanary); err != nil || u.progress().NeverOnline {
		t.Fatalf("joined left never online (%v)", err)
	}
	// Saved again, then an uplink clears it for good.
	u.seen(netjoin.Saved)
	now = now.Add(2 * neverOnlineAfter)
	on = true
	if u.progress().NeverOnline {
		t.Fatal("online and never online")
	}
	on = false
	if u.progress().NeverOnline {
		t.Fatal("an uplink did not clear never online")
	}
	var nilUp *uplink
	nilUp.seen(netjoin.Saved)
}
