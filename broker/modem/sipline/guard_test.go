package sipline_test

// REQ: DEV-2, REV-5, ADP-12

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modem/sipline"
	"github.com/ghbmrk/agentos/broker/modem/sipsim"
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

// A line opened without a guard is refused before anything is dialed:
// there is no unguarded mode for a test or a caller to fall into.
func TestOpenWithoutAGuardIsRefused(t *testing.T) {
	p := provider(t)
	cfg := config(p, vault(p))
	cfg.Guard = nil
	if l, err := sipline.Open(context.Background(), cfg); !errors.Is(err, sipline.ErrNoGuard) {
		if l != nil {
			_ = l.Close()
		}
		t.Fatalf("opened without a guard: %v", err)
	}
	if p.Registered(user) != 0 {
		t.Fatal("the provider saw a registration")
	}
}

// An answer whose Contact names UDP, WS or WSS does not move the call off
// its verified TLS connection: the ACK and BYE go back over TLS, and
// nothing reaches the address the hostile Contact names.
func TestAnAnswerNamingAnotherTransportIsNotDialed(t *testing.T) {
	p := provider(t)
	l := open(t, p, config(p, vault(p)))
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	up, tp := udp.LocalAddr().(*net.UDPAddr).Port, tcp.Addr().(*net.TCPAddr).Port
	for _, contact := range []string{
		fmt.Sprintf("<sip:far@127.0.0.1:%d;transport=udp>", up),
		fmt.Sprintf("<sip:far@127.0.0.1:%d;transport=ws>", tp),
		fmt.Sprintf("<sip:far@127.0.0.1:%d;transport=wss>", tp),
	} {
		ctx := context.Background()
		c, err := l.Dial(ctx, shopNum)
		if err != nil {
			t.Fatal(err)
		}
		far := <-p.Calls()
		if err := far.AnswerWith(sipline.PCMU, sipsim.Answer{Headers: []string{"Contact: " + contact}}); err != nil {
			t.Fatalf("%s: %v", contact, err)
		}
		select {
		case <-c.Active():
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the call did not go active", contact)
		}
		if err := c.Hangup(ctx); err != nil {
			t.Fatalf("%s: hangup: %v", contact, err)
		}
		select {
		case <-far.Done():
		case <-time.After(3 * time.Second):
			t.Fatalf("%s: the BYE did not reach the provider over TLS", contact)
		}
	}
	_ = udp.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, _, err := udp.ReadFromUDP(make([]byte, 1500)); err == nil {
		t.Fatalf("a %d-byte datagram reached the Contact's UDP address", n)
	}
	_ = tcp.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if conn, err := tcp.Accept(); err == nil {
		conn.Close()
		t.Fatal("a connection reached the Contact's WS address")
	}
}

// A provider that aims a call's audio at a home-network address (here a
// global IPv6 address inside the learned uplink prefix) gets the call hung
// up before a word, with the refusal journaled: RTP goes through the guard
// as signaling does.
func TestCallAudioAimedAtTheHomeNetworkIsRefusedAndJournaled(t *testing.T) {
	home := netip.MustParseAddr("2a02:aaaa:bbbb:cc00::5")
	p := provider(t)
	var d denials
	g := netguard.New(netguard.Config{OnDeny: d.add})
	g.Learn(netguard.Network{Prefixes: []netip.Prefix{netip.MustParsePrefix("2a02:aaaa:bbbb:cc00::/64")}})
	cfg := config(p, vault(p))
	cfg.Guard = sipline.ReachLoopback(g)
	l := open(t, p, cfg)
	c, err := l.Dial(context.Background(), shopNum)
	if err != nil {
		t.Fatal(err)
	}
	far := <-p.Calls()
	if err := far.AnswerWith(sipline.PCMU, sipsim.Answer{Media: home.String()}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Ended():
	case <-time.After(3 * time.Second):
		t.Fatal("call not ended")
	}
	select {
	case <-c.Active():
		t.Fatal("a call aimed at the home network went active")
	default:
	}
	if e, ok := c.(interface{ Err() error }); !ok || !errors.Is(e.Err(), netguard.ErrDenied) {
		t.Fatalf("ended with %v", c)
	}
	journaled := func(from int) bool {
		for _, e := range d.all()[from:] {
			if e.Addr == home {
				return true
			}
		}
		return false
	}
	if !journaled(0) {
		t.Fatalf("the refusal was not journaled: %+v", d.all())
	}

	// A caller's offer aimed at the same address is declined.
	_ = l.Close()
	from := len(d.all())
	in := withClip(p, 2)
	in.Guard = cfg.Guard
	open(t, p, in)
	rc, err := p.RingLine(context.Background(), shopNum, user, sipsim.Ring{Addr: home.String(), Silent: true})
	if err != nil || rc.Status != 603 {
		t.Fatalf("an offer aimed at the home network: %v %v", rc, err)
	}
	if !journaled(from) {
		t.Fatalf("the offer's refusal was not journaled: %+v", d.all())
	}
}
