package netguard

// REQ: KRN-12

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

// A core service with no planner session whose connection resolves or
// redirects to a decoy address, in plain, IPv4-mapped or NAT64 form, or that
// probes the metadata address, has that call refused and reported as a
// decoy, and nothing else stops: the next call to a public address connects
// (KRN-12 Trips). Catches untrusted DNS or a redirect stopping the box.
func TestRedirectToDecoyStopsCallOnly(t *testing.T) {
	decoys := map[netip.Addr]bool{netip.MustParseAddr("169.254.169.254"): true, netip.MustParseAddr("10.9.8.7"): true}
	var events []DenyEvent
	p, dialed := guarded(&seqResolver{answers: [][]string{{"8.8.8.8", "10.9.8.7"}, {"8.8.4.4"}}}, &events)
	p.decoy = func(a netip.Addr) bool { return decoys[a] }
	ctx := context.Background()
	for _, addr := range []string{"169.254.169.254:80", "[::ffff:10.9.8.7]:443", "[64:ff9b::a09:807]:443", "rebound.example:443"} {
		if _, err := p.DialContext(ctx, "tcp", addr); !errors.Is(err, ErrDenied) {
			t.Fatalf("%s: %v", addr, err)
		}
	}
	req, _ := http.NewRequest("GET", "http://169.254.169.254/latest/meta-data/", nil)
	if err := p.CheckRedirect(req, []*http.Request{req}); !errors.Is(err, ErrDenied) {
		t.Fatalf("redirect: %v", err)
	}
	if len(events) != 5 || len(*dialed) != 0 {
		t.Fatalf("%d refusals, %d connects: want 5 and none", len(events), len(*dialed))
	}
	for _, e := range events {
		if !e.Decoy || e.Reason != ReasonDecoy {
			t.Fatalf("refusal %+v is not a decoy's", e)
		}
	}
	if _, err := p.DialContext(ctx, "tcp", "fine.example:443"); err != nil || len(*dialed) != 1 {
		t.Fatalf("the next call stopped: %v", err)
	}
	if err := p.Check(ctx, netip.MustParseAddr("192.0.2.1"), 80, "tcp"); err == nil || events[len(events)-1].Decoy {
		t.Fatal("an ordinary refusal reads as a decoy")
	}
}
