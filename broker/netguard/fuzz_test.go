package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// REQ: DEV-2

// fuzzBytes hands out a fuzz input a byte at a time; past the end it gives
// zeros, so every input decodes to some sequence of operations.
type fuzzBytes struct {
	b []byte
	i int
}

func (f *fuzzBytes) more() bool { return f.i < len(f.b) }

func (f *fuzzBytes) next() byte {
	if f.i >= len(f.b) {
		return 0
	}
	f.i++
	return f.b[f.i-1]
}

// fuzzMaxOps bounds the operations one input drives.
const fuzzMaxOps = 64

// fuzzT is the part of testing.T the oracles report through, so a test can
// hand them a recorder and show that a planted defect is reported.
type fuzzT interface {
	Helper()
	Fatalf(format string, args ...any)
}

// stopRun is what a recorder panics with, so Fatalf ends the run as it does
// on a testing.T.
type stopRun struct{}

// recorder collects the failures an oracle reports.
type recorder struct{ msgs []string }

func (r *recorder) Helper() {}

func (r *recorder) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, fmt.Sprintf(format, args...))
	panic(stopRun{})
}

// run runs f and returns what it reported.
func (r *recorder) run(f func(fuzzT)) (msgs []string) {
	defer func() {
		if p := recover(); p != nil {
			if _, ok := p.(stopRun); !ok {
				panic(p)
			}
		}
		msgs = r.msgs
	}()
	f(r)
	return r.msgs
}

// fuzzPlant switches a defect on in what an oracle drives: nil fields run
// the real code, and lie makes the router's answers go unrecorded.
type fuzzPlant struct {
	lie     bool
	read    func(*Sources) (Network, error)
	refresh func(*Policy) error
	check   func(*Policy, context.Context, netip.Addr, uint16, string) error
}

func (pl fuzzPlant) doRead(s *Sources) (Network, error) {
	if pl.read != nil {
		return pl.read(s)
	}
	return s.Read()
}

func (pl fuzzPlant) doRefresh(p *Policy) error {
	if pl.refresh != nil {
		return pl.refresh(p)
	}
	return p.Refresh()
}

func (pl fuzzPlant) doCheck(p *Policy, ctx context.Context, a netip.Addr, port uint16, proto string) error {
	if pl.check != nil {
		return pl.check(p, ctx, a, port, proto)
	}
	return p.Check(ctx, a, port, proto)
}

// fuzzRouter is one router the host may be attached to.
type fuzzRouter struct {
	gwHex string // the default route's gateway in /proc/net/route
	gw    netip.Addr
	dev   string
	mac   string     // its MAC; the neighbour entry shows it only when shown
	shown bool       // the neighbour table has a complete entry for it
	ext   netip.Addr // what it answers to NAT-PMP; invalid when silent
}

func (r fuzzRouter) key() gatewayKey {
	k := gatewayKey{gw: r.gw, dev: r.dev}
	if r.shown {
		k.mac = r.mac
	}
	return k
}

// fuzzHost is a host whose router changes as a fuzz input says, including
// while a NAT-PMP request is in flight. Every answer a router gives is
// recorded under the gateway key the host saw for that router.
type fuzzHost struct {
	in       *fuzzBytes
	pool     []fuzzRouter
	at       int // index into pool, or -1 when no default route
	answered map[gatewayKey]map[netip.Addr]bool
	lie      bool  // answers go unrecorded: a planted defect
	calls    []int // per router request since the last reset: 0 same gateway key, 1 another gateway, 2 none
}

// newFuzzHost decodes a pool of routers with distinct gateway keys: more
// than maxGatewayExternals of them, so the cache bound is reached.
func newFuzzHost(in *fuzzBytes) *fuzzHost {
	h := &fuzzHost{in: in, at: -1, answered: map[gatewayKey]map[netip.Addr]bool{}}
	n := 1 + int(in.next())%12
	seen := map[gatewayKey]bool{}
	for i := 0; i < n; i++ {
		b := in.next()
		g := 1 + b%3
		r := fuzzRouter{
			gwHex: fmt.Sprintf("%02X01A8C0", g),
			gw:    netip.AddrFrom4([4]byte{192, 168, 1, g}),
			dev:   []string{"eth0", "wlan0"}[(b>>2)&1],
			mac:   fmt.Sprintf("02:00:00:00:00:%02x", i+1),
			shown: b&0x08 == 0,
		}
		if b&0x30 != 0x30 {
			r.ext = netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)})
		}
		if seen[r.key()] {
			continue
		}
		seen[r.key()] = true
		h.pool = append(h.pool, r)
	}
	return h
}

// attach moves the host to the router b names, or off every router.
func (h *fuzzHost) attach(b byte) {
	h.at = int(b)%(len(h.pool)+1) - 1
}

// gatewayKey is the key of the router attached now, zero when none is.
func (h *fuzzHost) gatewayKey() gatewayKey {
	if r, ok := h.router(); ok {
		return r.key()
	}
	return gatewayKey{}
}

func (h *fuzzHost) router() (fuzzRouter, bool) {
	if h.at < 0 {
		return fuzzRouter{}, false
	}
	return h.pool[h.at], true
}

func (h *fuzzHost) readFile(name string) ([]byte, error) {
	r, ok := h.router()
	switch name {
	case "/proc/net/route":
		out := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
		if ok {
			out += r.dev + "\t00000000\t" + r.gwHex + "\t0003\t0\t0\t100\t00000000\n"
		}
		return []byte(out), nil
	case "/proc/net/arp":
		out := "IP address       HW type     Flags       HW address            Mask     Device\n"
		if ok {
			flags, mac := "0x2", r.mac
			if !r.shown {
				flags, mac = "0x0", "00:00:00:00:00:00"
			}
			out += r.gw.String() + " 0x1 " + flags + " " + mac + " * " + r.dev + "\n"
		}
		return []byte(out), nil
	}
	return nil, errors.New("not found")
}

func (h *fuzzHost) addrs() ([]net.Addr, error) {
	return []net.Addr{&net.IPNet{IP: net.IPv4(192, 168, 1, 50), Mask: net.CIDRMask(24, 32)}}, nil
}

// external answers one NAT-PMP request as the input plans it: the router
// answers, the host moves before the answer (the router now attached
// answers only if it is at the address asked), the host moves after it, or
// nothing answers.
func (h *fuzzHost) external(_ context.Context, gw netip.Addr) (netip.Addr, error) {
	start := h.gatewayKey()
	defer func() {
		switch end := h.gatewayKey(); {
		case end == start:
			h.calls = append(h.calls, 0)
		case !end.gw.IsValid():
			h.calls = append(h.calls, 2)
		default:
			h.calls = append(h.calls, 1)
		}
	}()
	plan := h.in.next()
	if plan%4 == 1 {
		h.attach(h.in.next())
	}
	r, ok := h.router()
	var a netip.Addr
	if ok && plan%4 != 3 && r.gw == gw && r.ext.IsValid() {
		a = r.ext
		if h.answered[r.key()] == nil {
			h.answered[r.key()] = map[netip.Addr]bool{}
		}
		if !h.lie {
			h.answered[r.key()][a] = true
		}
	}
	if plan%4 == 2 {
		h.attach(h.in.next())
	}
	if !a.IsValid() {
		return netip.Addr{}, errors.New("no answer")
	}
	return a, nil
}

func (h *fuzzHost) sources() *Sources {
	return &Sources{Addrs: h.addrs, ReadFile: h.readFile, External: h.external}
}

// movedTwice says the gateway moved to another router during each of the
// last read's two router requests, the one case Read returns ErrGatewayMoved.
func (h *fuzzHost) movedTwice() bool {
	return len(h.calls) == 2 && h.calls[0] == 1 && h.calls[1] == 1
}

// checkRead checks one Read or ReadLocal result and the cache after it.
func (h *fuzzHost) checkRead(t fuzzT, s *Sources, op string, m Network, err error) {
	t.Helper()
	if op == "Read" && errors.Is(err, ErrGatewayMoved) != h.movedTwice() {
		t.Fatalf("Read: error %v after router requests %v, ErrGatewayMoved only when the gateway moved during both", err, h.calls)
	}
	if err == nil && len(m.Prefixes) == 0 {
		t.Fatalf("%s: no error and no prefixes: %+v", op, m)
	}
	if m.External.IsValid() {
		if !m.Gateway.IsValid() {
			t.Fatalf("%s: an external address with no gateway: %+v", op, m)
		}
		if !h.answered[keyOf(m)][m.External] {
			t.Fatalf("%s: external %v was never answered on gateway %+v", op, m.External, keyOf(m))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.exts) > maxGatewayExternals {
		t.Fatalf("%s: %d gateways cached, bound %d", op, len(s.exts), maxGatewayExternals)
	}
	for _, e := range s.exts {
		if !h.answered[e.key][e.ext] {
			t.Fatalf("%s: cached %v on gateway %+v, which never answered it", op, e.ext, e.key)
		}
	}
}

// fuzzSeeds are hand-picked inputs: answers, moves before and after the
// answer, silent routers, and enough routers to pass the cache bound.
var fuzzSeeds = [][]byte{
	{3, 0x00, 0x09, 0x16, 0, 1, 1, 0, 2, 0, 0, 2, 1, 1, 0},
	{2, 0x00, 0x08, 0, 1, 1, 1, 2, 1, 1, 0, 2},
	{4, 0x00, 0x01, 0x04, 0x30, 0, 1, 1, 1, 2, 0, 3, 1, 2, 2, 0, 4, 1, 0, 1, 1},
	{12, 0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 0, 1, 1, 0, 0, 2, 1, 0, 0, 3, 1, 0, 0, 4, 1, 0, 0, 5, 1, 0, 0, 6, 1, 0, 0, 7, 1, 0, 0, 8, 1, 0, 0, 9, 1, 0, 0, 10, 1, 0, 0, 11, 1, 0, 0, 1, 2},
	// the gateway moves during both router requests of one read
	{2, 0, 1, 2, 0, 1, 1, 1, 2, 1, 3},
	// a read, then a refresh, of one answering router
	{2, 0, 1, 2, 0, 1, 1, 0, 2, 0},
}

// Seeds the controls drive: a router answers once; the gateway moves during
// both requests of a refresh; a refresh is answered.
var (
	seedAnswered   = []byte{2, 0, 1, 2, 0, 1, 1, 0}
	seedMovedTwice = []byte{2, 0, 1, 2, 0, 1, 2, 1, 2, 1, 3}
	seedRefreshed  = []byte{2, 0, 1, 2, 0, 1, 2, 0}
)

// FuzzSourcesRead (FUZZ-1): over any sequence of router moves, before or
// after a router's answer, Read and ReadLocal return only an external
// address the gateway they ended on gave, the cache holds only such
// addresses and at most maxGatewayExternals of them, and a nil error has
// prefixes.
func FuzzSourcesRead(f *testing.F) {
	for _, b := range fuzzSeeds {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzSourcesRead(t, b, fuzzPlant{}) })
}

func fuzzSourcesRead(t fuzzT, b []byte, pl fuzzPlant) {
	in := &fuzzBytes{b: b}
	h := newFuzzHost(in)
	h.lie = pl.lie
	s := h.sources()
	for n := 0; n < fuzzMaxOps && in.more(); n++ {
		switch in.next() % 3 {
		case 0:
			h.attach(in.next())
		case 1:
			h.calls = nil
			m, err := pl.doRead(s)
			h.checkRead(t, s, "Read", m, err)
		case 2:
			m, err := s.ReadLocal()
			h.checkRead(t, s, "ReadLocal", m, err)
		}
	}
}

// FuzzGatewayPolicy (FUZZ-1): over any sequence of router moves, quick
// reads and full refreshes, while the policy's learned gateway is one whose
// router's external address was filed, that address is denied.
func FuzzGatewayPolicy(f *testing.F) {
	for _, b := range fuzzSeeds {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzGatewayPolicy(t, b, fuzzPlant{}) })
}

func fuzzGatewayPolicy(t fuzzT, b []byte, pl fuzzPlant) {
	in := &fuzzBytes{b: b}
	h := newFuzzHost(in)
	s := h.sources()
	filed := map[gatewayKey]netip.Addr{}
	read := func() (Network, error) {
		m, err := s.Read()
		if m.External.IsValid() {
			filed[keyOf(m)] = m.External
		}
		return m, err
	}
	p := New(Config{Source: read, Quick: s.ReadLocal})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // a held destination is refused at once
	for n := 0; n < fuzzMaxOps && in.more(); n++ {
		op := ""
		switch in.next() % 3 {
		case 0:
			h.attach(in.next())
			continue
		case 1:
			op = "quick read"
			p.quickLearn()
		case 2:
			op = "refresh"
			h.calls = nil
			err := pl.doRefresh(p)
			if errors.Is(err, ErrGatewayMoved) != h.movedTwice() {
				t.Fatalf("refresh: error %v after router requests %v, ErrGatewayMoved only when the gateway moved during both", err, h.calls)
			}
		}
		p.mu.RLock()
		k := keyOf(p.net)
		p.mu.RUnlock()
		ext, ok := filed[k]
		if !k.gw.IsValid() || !ok {
			continue
		}
		if err := pl.doCheck(p, ctx, ext, 443, "tcp"); !errors.Is(err, ErrDenied) {
			t.Fatalf("after a %s on gateway %+v, its router's external %v: %v", op, k, ext, err)
		}
	}
}

// fuzzAddrs are candidate addresses: private, public, loopback, mapped,
// 6to4, NAT64 and ISATAP forms of each, link-local with a zone, and the
// zero Addr. Bytes past the list build a raw address.
var fuzzAddrs = []netip.Addr{
	{},
	netip.MustParseAddr("192.168.1.1"),
	netip.MustParseAddr("10.0.0.1"),
	netip.MustParseAddr("8.8.8.8"),
	netip.MustParseAddr("9.9.9.9"),
	netip.MustParseAddr("1.1.1.1"),
	netip.MustParseAddr("100.64.0.1"),
	netip.MustParseAddr("127.0.0.1"),
	netip.MustParseAddr("0.0.0.0"),
	netip.MustParseAddr("::ffff:8.8.8.8"),
	netip.MustParseAddr("::ffff:192.168.1.1"),
	netip.MustParseAddr("2002:808:808::1"),
	netip.MustParseAddr("2002:c0a8:101::1"),
	netip.MustParseAddr("64:ff9b::808:808"),
	netip.MustParseAddr("64:ff9b::c0a8:101"),
	netip.MustParseAddr("2606:4700::5efe:808:808"),
	netip.MustParseAddr("2606:4700::200:5efe:c0a8:101"),
	netip.MustParseAddr("2606:4700::1111"),
	netip.MustParseAddr("2606:4700:0:1::1"),
	netip.MustParseAddr("2a00:1450::1"),
	netip.MustParseAddr("2001:db8::1"),
	netip.MustParseAddr("fd00::1"),
	netip.MustParseAddr("fe80::1%eth0"),
	netip.MustParseAddr("ff02::1"),
	netip.MustParseAddr("::1"),
}

func (f *fuzzBytes) addr() netip.Addr {
	b := f.next()
	if int(b) < len(fuzzAddrs) {
		return fuzzAddrs[b]
	}
	if b&1 == 0 {
		return netip.AddrFrom4([4]byte{f.next(), f.next(), f.next(), f.next()})
	}
	var a [16]byte
	for i := range a {
		a[i] = f.next()
	}
	return netip.AddrFrom16(a)
}

func (f *fuzzBytes) prefix() netip.Prefix {
	a := f.addr()
	if !a.IsValid() {
		return netip.Prefix{}
	}
	return netip.PrefixFrom(a.WithZone(""), int(f.next())%(a.BitLen()+1))
}

// fuzzNames are pin names and request names: case and a trailing dot
// differ, so only the policy's normalisation makes them match.
var fuzzNames = []string{"", "hosted.example", "Hosted.Example.", "dev.example", "backup.example"}

func pinPurpose(k PinKind) Purpose {
	switch k {
	case PinCompute, PinHosted:
		return PurposeModelCall
	case PinDevice:
		return PurposeDevice
	case PinBackup:
		return PurposeBackup
	}
	return -1
}

// embedded is a and every IPv4 address it carries: mapped, NAT64, 6to4
// and ISATAP.
func embedded(a netip.Addr) []netip.Addr {
	a = a.WithZone("")
	out := []netip.Addr{a.Unmap()}
	if !a.Is6() || a.Is4In6() {
		return out
	}
	b := a.As16()
	v4 := func(o int) netip.Addr { return netip.AddrFrom4([4]byte{b[o], b[o+1], b[o+2], b[o+3]}) }
	if netip.MustParsePrefix("64:ff9b::/96").Contains(a) {
		out = append(out, v4(12))
	}
	if b[0] == 0x20 && b[1] == 0x02 {
		out = append(out, v4(2))
	}
	if (b[8]|2) == 2 && b[9] == 0 && b[10] == 0x5e && b[11] == 0xfe {
		out = append(out, v4(12))
	}
	return out
}

// homeOrSpecial says why a policy that allowed f with no exception was
// wrong: f is not global unicast by the standard library or by the IANA
// registries, or is in a learned prefix or a learned router address.
func homeOrSpecial(f netip.Addr, raw Network) string {
	if why, bad := Special(f); bad {
		return why
	}
	if f.IsLoopback() || f.IsPrivate() || f.IsLinkLocalUnicast() || f.IsLinkLocalMulticast() ||
		f.IsInterfaceLocalMulticast() || f.IsMulticast() || f.IsUnspecified() {
		return "not global unicast"
	}
	for _, pf := range raw.Prefixes {
		// A mapped prefix is the IPv4 prefix it carries; a native IPv6
		// prefix holds no IPv4 address.
		in := pf.Contains(f)
		if a := pf.Addr(); a.Is4In6() && pf.Bits() >= 96 {
			in = netip.PrefixFrom(a.Unmap(), pf.Bits()-96).Contains(f)
		}
		if in {
			return "prefix " + pf.String()
		}
	}
	for _, a := range []netip.Addr{raw.Gateway, raw.External, raw.Resolver} {
		if a.IsValid() && a.WithZone("").Unmap() == f {
			return "learned router address"
		}
	}
	return ""
}

var fuzzCheckSeeds = [][]byte{
	{0, 3, 1, 1, 24, 0, 2, 1, 3, 4, 1, 53, 0},
	{0, 1, 3, 1, 1, 24, 2, 3, 10, 2, 4, 1, 12, 0, 2, 3, 2, 3, 1, 1, 2},
	{0, 2, 18, 96, 2, 1, 1, 3, 17, 1, 0, 1, 0, 2, 11, 0, 0, 2, 13, 0, 0, 2, 15, 0, 0, 2, 16, 0, 0},
	{1, 3, 2, 2, 3, 3, 1, 2, 4, 1, 0, 2, 9, 0, 0, 2, 3, 4, 1, 0, 2, 3, 1, 2},
}

// FuzzCheck (extra, not in the brief): for any learned network, pins, destination, port,
// protocol, purpose and name, an allow is sound (DNS only to the resolver
// on port 53 over tcp or udp; a pin only for its purpose; anything else
// only outside every special range, learned prefix and router address),
// the resolver and a matching pin are allowed, and OnDeny runs once for a
// denial and never for an allow.
func FuzzCheck(f *testing.F) {
	for _, b := range fuzzCheckSeeds {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzCheck(t, b, fuzzPlant{}) })
}

func fuzzCheck(t fuzzT, b []byte, pl fuzzPlant) {
	in := &fuzzBytes{b: b}
	denies := 0
	p := New(Config{OnDeny: func(DenyEvent) { denies++ }})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var raw Network
	var pins []Pin
	for n := 0; n < fuzzMaxOps && in.more(); n++ {
		switch in.next() % 3 {
		case 0: // learn a network
			raw = Network{}
			for i := int(in.next() % 4); i > 0; i-- {
				if pf := in.prefix(); pf.IsValid() {
					raw.Prefixes = append(raw.Prefixes, pf)
				}
			}
			raw.Gateway, raw.External, raw.Resolver = in.addr(), in.addr(), in.addr()
			p.Learn(raw)
		case 1: // set pins
			var next []Pin
			for i := int(in.next() % 3); i > 0; i-- {
				pin := Pin{Kind: PinKind(in.next() % 6), Name: fuzzNames[int(in.next())%len(fuzzNames)]}
				if a := in.addr(); a.IsValid() {
					pin.Addr = netip.AddrPortFrom(a.WithZone(""), uint16(in.next()))
				}
				pin.Key[0] = in.next() % 2
				next = append(next, pin)
			}
			if err := p.SetPins(next); err == nil {
				pins = next
			}
		case 2: // check a destination
			pu := Purpose(in.next() % 6)
			name := fuzzNames[int(in.next())%len(fuzzNames)]
			a := in.addr()
			port := []uint16{53, 443, 80, uint16(in.next())}[in.next()%4]
			proto := []string{"tcp", "udp", "icmp", ""}[in.next()%4]
			denies = 0
			err := pl.doCheck(p, withName(WithPurpose(ctx, pu), name), a, port, proto)
			what := fmt.Sprintf("%v port %d/%s purpose %d name %q on %+v pins %+v", a, port, proto, pu, name, raw, pins)
			if err != nil && !errors.Is(err, ErrDenied) {
				t.Fatalf("%s: error %v is not ErrDenied", what, err)
			}
			if want := 0; err != nil && denies != 1 || err == nil && denies != want {
				t.Fatalf("%s: err %v, OnDeny ran %d times", what, err, denies)
			}
			checkVerdict(t, what, err == nil, raw, pins, pu, name, a, port, proto)
		}
	}
}

func checkVerdict(t fuzzT, what string, allowed bool, raw Network, pins []Pin, pu Purpose, name string, a netip.Addr, port uint16, proto string) {
	t.Helper()
	a = a.WithZone("").Unmap()
	if pu == PurposeDNS {
		res := raw.Resolver.WithZone("").Unmap()
		want := (proto == "tcp" || proto == "udp") && port == 53 && res.IsValid() &&
			!res.IsLoopback() && !res.IsUnspecified() && a == res
		if allowed != want {
			t.Fatalf("%s: DNS allowed %v, want %v", what, allowed, want)
		}
		return
	}
	pinned := false
	for _, pin := range pins {
		if pinPurpose(pin.Kind) != pu {
			continue
		}
		pn := strings.ToLower(strings.TrimSuffix(pin.Name, "."))
		pa := pin.Addr
		if pa.IsValid() {
			pa = netip.AddrPortFrom(pa.Addr().Unmap(), pa.Port())
		}
		if (pn != "" && pn == name) || (pa.IsValid() && pa == netip.AddrPortFrom(a, port)) {
			pinned = true
		}
	}
	if pinned && a.IsValid() {
		if !allowed {
			t.Fatalf("%s: a matching pin was denied", what)
		}
		return
	}
	if !allowed {
		return
	}
	if !a.IsValid() {
		t.Fatalf("%s: an invalid address was allowed", what)
	}
	for _, f := range embedded(a) {
		if why := homeOrSpecial(f, raw); why != "" {
			t.Fatalf("%s: allowed, but form %v is %s", what, f, why)
		}
	}
}

// Each control plants a defect in what the target drives and shows its
// oracle reports it, then shows the real code passes the same input.
func TestFuzzSourcesReadReportsAPlantedDefect(t *testing.T) {
	swallow := func(s *Sources) (Network, error) {
		m, err := s.Read()
		if errors.Is(err, ErrGatewayMoved) {
			err = nil
		}
		return m, err
	}
	for name, c := range map[string]struct {
		in []byte
		pl fuzzPlant
	}{
		"unrecorded answer":     {[]byte{2, 0, 1, 2, 0, 1, 1, 0}, fuzzPlant{lie: true}},
		"swallowed second move": {[]byte{2, 0, 1, 2, 0, 1, 1, 1, 2, 1, 3}, fuzzPlant{read: swallow}},
	} {
		var rec recorder
		if len(rec.run(func(ft fuzzT) { fuzzSourcesRead(ft, c.in, c.pl) })) == 0 {
			t.Errorf("%s: the oracle did not report the planted defect", name)
		}
		rec = recorder{}
		if msgs := rec.run(func(ft fuzzT) { fuzzSourcesRead(ft, c.in, fuzzPlant{}) }); len(msgs) != 0 {
			t.Errorf("%s: the real code reported: %v", name, msgs)
		}
	}
}

func TestFuzzGatewayPolicyReportsAPlantedDefect(t *testing.T) {
	swallow := func(p *Policy) error {
		if err := p.Refresh(); !errors.Is(err, ErrGatewayMoved) {
			return err
		}
		return nil
	}
	allowAll := func(*Policy, context.Context, netip.Addr, uint16, string) error { return nil }
	for name, c := range map[string]struct {
		in []byte
		pl fuzzPlant
	}{
		"swallowed second move": {seedMovedTwice, fuzzPlant{refresh: swallow}},
		"allowed external":      {seedRefreshed, fuzzPlant{check: allowAll}},
	} {
		var rec recorder
		if len(rec.run(func(ft fuzzT) { fuzzGatewayPolicy(ft, c.in, c.pl) })) == 0 {
			t.Errorf("%s: the oracle did not report the planted defect", name)
		}
		rec = recorder{}
		if msgs := rec.run(func(ft fuzzT) { fuzzGatewayPolicy(ft, c.in, fuzzPlant{}) }); len(msgs) != 0 {
			t.Errorf("%s: the real code reported: %v", name, msgs)
		}
	}
}

func TestFuzzCheckReportsAPlantedDefect(t *testing.T) {
	allowAll := func(*Policy, context.Context, netip.Addr, uint16, string) error { return nil }
	wrongError := func(p *Policy, ctx context.Context, a netip.Addr, port uint16, proto string) error {
		if err := p.Check(ctx, a, port, proto); err != nil {
			return errors.New("denied")
		}
		return nil
	}
	for name, pl := range map[string]fuzzPlant{
		"allows every destination": {check: allowAll},
		"denies without ErrDenied": {check: wrongError},
	} {
		reported := false
		for _, in := range fuzzCheckSeeds {
			var rec recorder
			if len(rec.run(func(ft fuzzT) { fuzzCheck(ft, in, pl) })) != 0 {
				reported = true
			}
		}
		if !reported {
			t.Errorf("%s: the oracle did not report the planted defect on any seed", name)
		}
	}
	for _, in := range fuzzCheckSeeds {
		var rec recorder
		if msgs := rec.run(func(ft fuzzT) { fuzzCheck(ft, in, fuzzPlant{}) }); len(msgs) != 0 {
			t.Errorf("the real policy reported: %v", msgs)
		}
	}
}
