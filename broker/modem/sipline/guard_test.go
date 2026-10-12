package sipline_test

// REQ: DEV-2, REV-5, ADP-12

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/netguard"
)

type denials struct {
	mu sync.Mutex
	ev []netguard.DenyEvent
}

func (d *denials) add(e netguard.DenyEvent) {
	d.mu.Lock()
	d.ev = append(d.ev, e)
	d.mu.Unlock()
}

func (d *denials) all() []netguard.DenyEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]netguard.DenyEvent(nil), d.ev...)
}

// A SIP dial to a private address is refused by the guard and journaled,
// and the provider sees no connection. The simulated provider listens on
// loopback, so the line's own dial is the one refused.
func TestSIPDialToAPrivateAddressIsRefusedAndJournaled(t *testing.T) {
	p := provider(t)
	var d denials
	g := netguard.New(netguard.Config{OnDeny: d.add})
	cfg := config(p, vault(p))
	cfg.Guard = g
	if _, err := sipline.Open(context.Background(), cfg); err == nil {
		t.Fatal("the line opened over a refused address")
	}
	if p.Registered(user) != 0 {
		t.Fatal("the provider saw a registration")
	}
	found := false
	for _, e := range d.all() {
		if e.Addr == netip.MustParseAddr("127.0.0.1") {
			found = true
		}
	}
	if !found {
		t.Fatalf("the refusal was not journaled: %+v", d.all())
	}
}

// A provider name resolves only through the learned resolver: with none
// learned, the name is refused and journaled, never sent to the system
// resolver.
func TestSIPProviderNameResolvesOnlyThroughTheGuard(t *testing.T) {
	p := provider(t)
	var d denials
	g := netguard.New(netguard.Config{OnDeny: d.add})
	cfg := config(p, vault(p))
	cfg.Server = "sip.provider.example.test:5061"
	cfg.Guard = g
	if _, err := sipline.Open(context.Background(), cfg); err == nil {
		t.Fatal("the line opened without a resolver")
	}
	dns := false
	for _, e := range d.all() {
		if e.Purpose == netguard.PurposeDNS {
			dns = true
		}
	}
	if !dns {
		t.Fatalf("the name lookup bypassed the guard: %+v", d.all())
	}
}
