package netguard

// REQ: DEV-2, REV-5, ARC-6, CAP-2, CAP-13

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// seqResolver answers each lookup of a name with the next entry; the last
// entry repeats.
type seqResolver struct {
	mu      sync.Mutex
	answers [][]string
	calls   int
}

func (s *seqResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := s.calls
	if i >= len(s.answers) {
		i = len(s.answers) - 1
	}
	s.calls++
	var out []netip.Addr
	for _, a := range s.answers[i] {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, nil
}

type fakeConn struct{ net.Conn }

// guarded returns a policy whose connect seam records the addresses it is
// asked to connect to instead of touching the network.
func guarded(res Resolver, events *[]DenyEvent) (*Policy, *[]string) {
	var dialed []string
	p := New(Config{Resolver: res, OnDeny: func(e DenyEvent) {
		if events != nil {
			*events = append(*events, e)
		}
	}})
	p.connect = func(_ context.Context, _, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		return fakeConn{}, nil
	}
	return p, &dialed
}

// Acceptance 1: a rebinding answer is refused on the second answer.
func TestRebindingRefusedOnSecondAnswer(t *testing.T) {
	res := &seqResolver{answers: [][]string{{"8.8.8.8"}, {"10.0.0.5"}}}
	p, dialed := guarded(res, nil)
	ctx := context.Background()
	if _, err := p.DialContext(ctx, "tcp", "rebind.example:443"); err != nil {
		t.Fatalf("first answer is public and must pass: %v", err)
	}
	_, err := p.DialContext(ctx, "tcp", "rebind.example:443")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("second answer 10.0.0.5 must be refused, got %v", err)
	}
	if len(*dialed) != 1 {
		t.Fatalf("only the first dial may connect, got %v", *dialed)
	}
}

func TestOneRefusedAnswerRefusesTheWholeDial(t *testing.T) {
	res := &seqResolver{answers: [][]string{{"8.8.8.8", "192.168.1.9"}}}
	p, dialed := guarded(res, nil)
	if _, err := p.DialContext(context.Background(), "tcp", "mixed.example:443"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if len(*dialed) != 0 {
		t.Fatalf("no connect may happen, got %v", *dialed)
	}
}

// Acceptance 2: every IANA special-purpose range, v4-mapped, NAT64-embedded
// and the uplink /56 are refused.
func TestSpecialPurposeRangesRefused(t *testing.T) {
	refused := []string{
		"0.1.2.3", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.169.254",
		"172.16.0.1", "172.31.255.255", "192.0.0.9", "192.0.2.1", "192.31.196.1",
		"192.52.193.1", "192.88.99.1", "192.168.0.1", "192.175.48.1", "198.18.0.1",
		"198.19.255.255", "198.51.100.1", "203.0.113.1", "224.0.0.1", "239.1.1.1",
		"240.0.0.1", "255.255.255.255",
		"::", "::1", "100::1", "2001::1", "2001:db8::1", "2002:0a00:0001::1",
		"2620:4f:8000::1", "3fff::1", "5f00::1", "fc00::1", "fd12:3456::1",
		"fe80::1", "fec0::1", "ff02::1", "64:ff9b:1::1",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:192.168.1.1",
		"64:ff9b::a00:1", "64:ff9b::c0a8:101", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
		"2002:c0a8:0101::1", "fe80::5efe:c0a8:101",
	}
	p, _ := guarded(&seqResolver{answers: [][]string{{"8.8.8.8"}}}, nil)
	for _, s := range refused {
		a := netip.MustParseAddr(s)
		if err := p.Check(context.Background(), a, 443, "tcp"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s must be refused, got %v", s, err)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111", "2a00:1450:4001::1", "64:ff9b::808:808"}
	for _, s := range allowed {
		if err := p.Check(context.Background(), netip.MustParseAddr(s), 443, "tcp"); err != nil {
			t.Errorf("%s is global and must pass: %v", s, err)
		}
	}
}

func TestLearnedNetworkRefused(t *testing.T) {
	p, _ := guarded(&seqResolver{answers: [][]string{{"8.8.8.8"}}}, nil)
	p.Learn(Network{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("2a02:aaaa:bbbb:cc00::/64"), netip.MustParsePrefix("203.0.113.0/24")},
		Gateway:  netip.MustParseAddr("9.9.9.1"),
		External: netip.MustParseAddr("9.9.9.2"),
	})
	for _, s := range []string{
		"2a02:aaaa:bbbb:cc00::1",
		"2a02:aaaa:bbbb:cc7f:1:2:3:4", // elsewhere in the uplink /56
		"9.9.9.1", "9.9.9.2", "::ffff:9.9.9.1", "64:ff9b::909:902",
	} {
		if err := p.Check(context.Background(), netip.MustParseAddr(s), 443, "tcp"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s must be refused, got %v", s, err)
		}
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("2a02:aaaa:bbbb:cd00::1"), 443, "tcp"); err != nil {
		t.Errorf("the next /56 is not the uplink: %v", err)
	}
	// A refresh replaces the learned set.
	p.Learn(Network{})
	if err := p.Check(context.Background(), netip.MustParseAddr("9.9.9.1"), 443, "tcp"); err != nil {
		t.Errorf("a replaced network no longer refuses its old gateway: %v", err)
	}
}

func TestRefreshKeepsOldOnFailure(t *testing.T) {
	fail := false
	p := New(Config{Source: func() (Network, error) {
		if fail {
			return Network{}, errors.New("netlink down")
		}
		return Network{Gateway: netip.MustParseAddr("9.9.9.1")}, nil
	}})
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	fail = true
	if err := p.Refresh(); err == nil {
		t.Fatal("failed read must report")
	}
	if err := p.Check(context.Background(), netip.MustParseAddr("9.9.9.1"), 443, "tcp"); !errors.Is(err, ErrDenied) {
		t.Fatalf("gateway must stay learned: %v", err)
	}
	ev := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Watch(ctx, ev); close(done) }()
	fail = false
	ev <- struct{}{}
	cancel()
	<-done
}

// The hook itself: a real dial to a loopback listener is refused by the
// address actually connected, with no connect.
func TestDialerControlRefusesLoopback(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer l.Close()
	var accepted atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	p := New(Config{})
	if _, err := p.Dialer().DialContext(context.Background(), "tcp", l.Addr().String()); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if _, err := p.DialContext(context.Background(), "tcp", l.Addr().String()); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	if accepted.Load() != 0 {
		t.Fatal("a refused dial must not reach the listener")
	}
}

// Acceptance 4: exactly four exceptions, each only as stated.
func TestFourExceptionsEachAsStated(t *testing.T) {
	var events []DenyEvent
	res := &seqResolver{answers: [][]string{{"192.168.1.20"}}}
	p, dialed := guarded(res, &events)
	p.Learn(Network{
		Prefixes: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
		Gateway:  netip.MustParseAddr("192.168.1.1"),
		Resolver: netip.MustParseAddr("192.168.1.2"),
	})
	key := [32]byte{1}
	if err := p.SetPins([]Pin{
		{Kind: PinCompute, Name: "gpu.home.example", Addr: netip.MustParseAddrPort("192.168.1.20:8443"), Key: key},
		{Kind: PinHosted, Name: "hosted.home.example", Key: key},
		{Kind: PinDevice, Addr: netip.MustParseAddrPort("192.168.1.30:443"), Key: key},
		{Kind: PinBackup, Addr: netip.MustParseAddrPort("192.168.1.40:22"), Key: key},
	}); err != nil {
		t.Fatal(err)
	}
	chk := func(pu Purpose, ip string, port uint16, proto string) error {
		return p.Check(WithPurpose(context.Background(), pu), netip.MustParseAddr(ip), port, proto)
	}
	// 1. The assigned resolver, port 53, DNS purpose only.
	for _, proto := range []string{"udp", "tcp"} {
		if err := chk(PurposeDNS, "192.168.1.2", 53, proto); err != nil {
			t.Errorf("resolver %s/53: %v", proto, err)
		}
	}
	for name, err := range map[string]error{
		"resolver on 853":         chk(PurposeDNS, "192.168.1.2", 853, "tcp"),
		"resolver, no purpose":    chk(PurposeNone, "192.168.1.2", 53, "udp"),
		"resolver, model call":    chk(PurposeModelCall, "192.168.1.2", 53, "udp"),
		"gateway for DNS purpose": chk(PurposeDNS, "192.168.1.1", 53, "udp"),
		"another host for DNS":    chk(PurposeDNS, "192.168.1.9", 53, "udp"),
		"dns purpose to a pin":    chk(PurposeDNS, "192.168.1.20", 8443, "tcp"),
		"backup pin, no purpose":  chk(PurposeNone, "192.168.1.40", 22, "tcp"),
		"backup pin, model call":  chk(PurposeModelCall, "192.168.1.40", 22, "tcp"),
		"device pin, model call":  chk(PurposeModelCall, "192.168.1.30", 443, "tcp"),
		"compute pin, no purpose": chk(PurposeNone, "192.168.1.20", 8443, "tcp"),
		"compute pin, device":     chk(PurposeDevice, "192.168.1.20", 8443, "tcp"),
		"compute pin, other port": chk(PurposeModelCall, "192.168.1.20", 9999, "tcp"),
		"device pin, other port":  chk(PurposeDevice, "192.168.1.30", 80, "tcp"),
		"other host, device":      chk(PurposeDevice, "192.168.1.31", 443, "tcp"),
		"backup pin, device":      chk(PurposeDevice, "192.168.1.40", 22, "tcp"),
		"v6 form of compute pin":  chk(PurposeNone, "64:ff9b::c0a8:114", 8443, "tcp"),
	} {
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s must be refused, got %v", name, err)
		}
	}
	// 2 to 4: the pins, by their own purpose.
	for name, err := range map[string]error{
		"compute":   chk(PurposeModelCall, "192.168.1.20", 8443, "tcp"),
		"device":    chk(PurposeDevice, "192.168.1.30", 443, "tcp"),
		"backup":    chk(PurposeBackup, "192.168.1.40", 22, "tcp"),
		"v4-mapped": chk(PurposeModelCall, "::ffff:192.168.1.20", 8443, "tcp"),
	} {
		if err != nil {
			t.Errorf("%s pin: %v", name, err)
		}
	}
	// A pin by name: a hosted route resolved to a private address passes the
	// address check by name, for a model call only.
	hosted := &seqResolver{answers: [][]string{{"192.168.1.77"}}}
	p.res = hosted
	if _, err := p.DialContext(WithPurpose(context.Background(), PurposeModelCall), "tcp", "hosted.home.example:443"); err != nil {
		t.Errorf("hosted pin by name: %v", err)
	}
	if _, err := p.DialContext(context.Background(), "tcp", "hosted.home.example:443"); !errors.Is(err, ErrDenied) {
		t.Errorf("hosted pin without a model-call purpose: %v", err)
	}
	if _, err := p.DialContext(WithPurpose(context.Background(), PurposeModelCall), "tcp", "other.home.example:443"); !errors.Is(err, ErrDenied) {
		t.Errorf("an unpinned name resolving private: %v", err)
	}
	if len(*dialed) != 1 {
		t.Errorf("connects: %v", *dialed)
	}
	if len(events) == 0 {
		t.Error("refusals must reach OnDeny")
	}
}

// A rogue resolver's private answer is refused, whatever the resolver is.
func TestRogueResolverPrivateAnswerRefused(t *testing.T) {
	res := &seqResolver{answers: [][]string{{"10.9.9.9"}}}
	p, dialed := guarded(res, nil)
	p.Learn(Network{Resolver: netip.MustParseAddr("8.8.4.4")}) // a rogue RA names a public resolver
	if _, err := p.DialContext(context.Background(), "tcp", "bank.example:443"); !errors.Is(err, ErrDenied) {
		t.Fatalf("got %v", err)
	}
	if len(*dialed) != 0 {
		t.Fatal("must not connect")
	}
}

func TestPinValidation(t *testing.T) {
	p := New(Config{})
	for _, bad := range []Pin{
		{Kind: 0, Name: "a", Key: [32]byte{1}},
		{Kind: PinCompute, Key: [32]byte{1}},
		{Kind: PinCompute, Name: "a"},
	} {
		if p.SetPins([]Pin{bad}) == nil {
			t.Errorf("pin %+v must be rejected", bad)
		}
	}
}

// NAT-PMP: opcode 0 only, and the answer is the router's external address.
func TestNATPMPExternalAddr(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer pc.Close()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 64)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		got <- append([]byte(nil), buf[:n]...)
		pc.WriteTo([]byte{0, 128, 0, 0, 0, 0, 0, 1, 9, 9, 9, 2}, from)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	a, err := externalAddr(ctx, netip.MustParseAddrPort(pc.LocalAddr().String()))
	if err != nil {
		t.Fatal(err)
	}
	if a != netip.MustParseAddr("9.9.9.2") {
		t.Fatalf("got %s", a)
	}
	if req := <-got; len(req) != 2 || req[0] != 0 || req[1] != 0 {
		t.Fatalf("only the opcode 0 request may be sent, got %v", req)
	}
}

func TestNATPMPBadAnswer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback")
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 64)
		_, from, _ := pc.ReadFrom(buf)
		pc.WriteTo([]byte{0, 128, 0, 3, 0, 0, 0, 1, 9, 9, 9, 2}, from) // result 3: network failure
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := externalAddr(ctx, netip.MustParseAddrPort(pc.LocalAddr().String())); err == nil {
		t.Fatal("a non-zero result code is an error")
	}
}

// Redirects: a literal private target is refused before any dial.
func TestCheckRedirect(t *testing.T) {
	p, _ := guarded(&seqResolver{answers: [][]string{{"8.8.8.8"}}}, nil)
	mk := func(u string) *http.Request {
		r, _ := http.NewRequest("GET", u, nil)
		return r
	}
	for _, u := range []string{"http://127.0.0.1/", "http://10.0.0.1:8080/x", "https://[::ffff:192.168.0.1]/", "http://[64:ff9b::a00:1]/", "ftp://example.com/", "file:///etc/passwd"} {
		if err := p.CheckRedirect(mk(u), nil); !errors.Is(err, ErrDenied) {
			t.Errorf("%s must be refused, got %v", u, err)
		}
	}
	if err := p.CheckRedirect(mk("https://example.com/"), nil); err != nil {
		t.Errorf("a public name passes here and is checked at dial: %v", err)
	}
	if err := p.CheckRedirect(mk("https://8.8.8.8/"), nil); err != nil {
		t.Errorf("public literal: %v", err)
	}
	if err := p.CheckRedirect(mk("https://example.com/"), make([]*http.Request, 10)); err == nil {
		t.Error("redirect loop must stop")
	}
}

// Acceptance 4 (last clause): a rebound pinned name fails at the handshake
// with no request bytes sent.
func TestPinnedNameReboundFailsAtHandshake(t *testing.T) {
	var served atomic.Int32
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { served.Add(1); w.Write([]byte("ok")) })
	real := httptest.NewTLSServer(h)
	defer real.Close()
	rogue := httptest.NewUnstartedServer(h)
	rogue.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t)}}
	rogue.StartTLS()
	defer rogue.Close()

	p := New(Config{})
	if err := p.SetPins([]Pin{{Kind: PinCompute, Name: "gpu.home.example", Key: KeyHash(real.Certificate())}}); err != nil {
		t.Fatal(err)
	}
	target := real.Listener.Addr().String()
	client := func() *http.Client {
		return &http.Client{Transport: &http.Transport{
			TLSClientConfig: p.TLSConfig(nil),
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, target)
			},
		}}
	}
	resp, err := client().Get("https://gpu.home.example/")
	if err != nil {
		t.Fatalf("the pinned key must pass: %v", err)
	}
	resp.Body.Close()
	if served.Load() != 1 {
		t.Fatalf("served %d", served.Load())
	}

	target = rogue.Listener.Addr().String() // the name now answers at another host
	_, err = client().Get("https://gpu.home.example/")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("a rebound pinned name must fail the handshake with a denial, got %v", err)
	}
	if served.Load() != 1 {
		t.Fatal("no request byte may reach the rebound host")
	}

	// A name with no pin gets ordinary verification, which a self-signed
	// test certificate fails.
	if _, err := client().Get("https://other.home.example/"); err == nil {
		t.Fatal("an unpinned name must be verified against the roots")
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "gpu.home.example"},
		DNSNames:  []string{"gpu.home.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// A learned address in v4-mapped form must refuse the plain v4 address Check sees.
func TestLearnUnmapsGatewayExternalResolver(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    Network
		addr string
	}{
		{"gateway", Network{Gateway: netip.MustParseAddr("::ffff:85.1.1.1")}, "85.1.1.1"},
		{"external", Network{External: netip.MustParseAddr("::ffff:85.1.1.2")}, "85.1.1.2"},
		{"resolver", Network{Resolver: netip.MustParseAddr("::ffff:85.1.1.3")}, "85.1.1.3"},
	} {
		p, _ := guarded(&seqResolver{answers: [][]string{{"8.8.8.8"}}}, nil)
		p.Learn(tc.n)
		if err := p.Check(context.Background(), netip.MustParseAddr(tc.addr), 443, "tcp"); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: %s must be refused, got %v", tc.name, tc.addr, err)
		}
	}
}

// heldPolicy is a policy whose gateway has just changed to one with no known
// external address, so a public destination is held, and whose refusals are
// journalled into the returned list.
func heldPolicy(t *testing.T) (*Policy, func() []DenyEvent) {
	t.Helper()
	var mu sync.Mutex
	var journal []DenyEvent
	g := &gwSources{answer: make(chan netip.Addr, 1)}
	g.gw.Store("0101A8C0")
	s := g.sources()
	p := New(Config{Source: s.Read, Quick: s.ReadLocal, OnDeny: func(e DenyEvent) {
		mu.Lock()
		defer mu.Unlock()
		journal = append(journal, e)
	}})
	g.answer <- netip.MustParseAddr("8.8.8.8")
	if err := p.Refresh(); err != nil {
		t.Fatal(err)
	}
	g.gw.Store("0103A8C0")
	p.quickLearn()
	return p, func() []DenyEvent {
		mu.Lock()
		defer mu.Unlock()
		return append([]DenyEvent(nil), journal...)
	}
}

// A held dial whose own context ends first (cancelled, or its deadline
// passed) is the caller's ending, not a netguard refusal: it fails with the
// context's error, still matches ErrDenied (nothing is dialled), and is not
// journalled. The hold bound's own expiry is still journalled (#1540).
func TestHeldDialEndedByCallerIsNotJournalled(t *testing.T) {
	old := externalHold
	t.Cleanup(func() { externalHold = old })
	externalHold = time.Hour
	public := netip.MustParseAddr("1.1.1.1")

	p, journal := heldPolicy(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Check(ctx, public, 443, "tcp")
	if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrDenied) {
		t.Fatalf("cancelled held dial: %v, want context.Canceled and ErrDenied", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = p.Check(ctx, public, 443, "tcp")
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrDenied) {
		t.Fatalf("held dial past its deadline: %v, want context.DeadlineExceeded and ErrDenied", err)
	}
	if j := journal(); len(j) != 0 {
		t.Fatalf("the caller's own ending was journalled as a refusal: %+v", j)
	}

	externalHold = 30 * time.Millisecond
	err = p.Check(context.Background(), public, 443, "tcp")
	if !errors.Is(err, ErrDenied) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hold bound expiry: %v, want a netguard refusal", err)
	}
	if j := journal(); len(j) != 1 || j[0].Addr != public {
		t.Fatalf("hold bound expiry journal: %+v, want one refusal of %v", j, public)
	}
}

// The hold refusal names this network's router, not "this gateway": since a
// gateway is its address, interface and router MAC, the hold also fires when
// the address is unchanged and only the router behind it is new (#1555).
func TestHoldRefusalNamesTheNetworksRouter(t *testing.T) {
	old := externalHold
	t.Cleanup(func() { externalHold = old })
	public := netip.MustParseAddr("1.1.1.1")
	p, journal := heldPolicy(t)

	externalHold = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cancelled := p.Check(ctx, public, 443, "tcp")
	externalHold = 30 * time.Millisecond
	expired := p.Check(context.Background(), public, 443, "tcp")
	j := journal()
	if len(j) != 1 {
		t.Fatalf("journal: %+v, want the expiry alone", j)
	}
	for name, msg := range map[string]string{"cancelled": cancelled.Error(), "expired": expired.Error(), "journal": j[0].Reason} {
		if !strings.Contains(msg, "this network's router") || strings.Contains(msg, "on this gateway") {
			t.Errorf("%s hold refusal reads %q, want it to name this network's router", name, msg)
		}
	}
}
