package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ErrDenied is wrapped by every refusal.
var ErrDenied = errors.New("netguard: destination refused")

// DeniedError says which address was refused and why. It carries no name
// resolved from a guest request beyond what the caller already holds.
type DeniedError struct {
	Addr   netip.Addr
	Reason string
}

func (e *DeniedError) Error() string {
	return fmt.Sprintf("netguard: destination refused: %s (%s)", e.Addr, e.Reason)
}

func (e *DeniedError) Is(target error) bool { return target == ErrDenied }

// Purpose says why a dial is made. The zero value gets no exception: it is
// what every agent request and every ordinary component dial carries.
type Purpose int

const (
	// PurposeNone has no exception.
	PurposeNone Purpose = iota
	// PurposeDNS is the broker's resolver talking to the currently
	// assigned resolver (DEV-2 exception 1).
	PurposeDNS
	// PurposeModelCall is a routed model call to a declared inference
	// operation (CAP-13, and a pinned private hosted route, CAP-9). It
	// reaches only compute and hosted pins.
	PurposeModelCall
	// PurposeDevice is a device executor reaching its own devices (DEV-1).
	// A hook only: no device executor exists yet.
	PurposeDevice
	// PurposeBackup is the owner-pinned backup target (BAK-1). A hook only.
	PurposeBackup
)

// PinKind says which exception a pin serves.
type PinKind int

const (
	PinCompute PinKind = iota + 1 // a compute host's declared endpoint (CAP-13)
	PinHosted                     // an owner-pinned private hosted route (CAP-9)
	PinDevice                     // a device executor's own device (DEV-1)
	PinBackup                     // an owner-pinned backup target (BAK-1)
)

func (k PinKind) purpose() Purpose {
	switch k {
	case PinCompute, PinHosted:
		return PurposeModelCall
	case PinDevice:
		return PurposeDevice
	case PinBackup:
		return PurposeBackup
	}
	return PurposeNone
}

// Pin is one allowed exception: a destination matched on its pinned
// address or its name, and always on the SHA-256 of its TLS public key
// (SubjectPublicKeyInfo). A rebound name passes the address check and then
// fails the handshake, before any request byte is sent.
type Pin struct {
	Kind PinKind
	Name string         // host name, matched case-insensitively; may be empty
	Addr netip.AddrPort // pinned address; may be the zero value
	Key  [32]byte       // required
}

func (p Pin) validate() error {
	if p.Kind < PinCompute || p.Kind > PinBackup {
		return errors.New("netguard: pin kind unknown")
	}
	if p.Name == "" && !p.Addr.IsValid() {
		return errors.New("netguard: pin needs a name or an address")
	}
	if p.Key == ([32]byte{}) {
		return errors.New("netguard: pin needs a key hash")
	}
	return nil
}

// Network is what the broker has learned about the home network. Learn
// replaces the whole set.
type Network struct {
	// Prefixes are the uplink's and the access point's prefixes. A global
	// IPv6 prefix longer than /56 is widened to its enclosing /56.
	Prefixes []netip.Prefix
	// Gateway is the learned default gateway.
	Gateway netip.Addr
	// GatewayDev is the default route's interface.
	GatewayDev string
	// GatewayMAC is the gateway's MAC from the neighbour table, empty when
	// none is known. Together with Gateway and GatewayDev it tells routers
	// behind one gateway address apart (#1536).
	GatewayMAC string
	// External is the router's external address, where NAT-PMP or PCP
	// reports it.
	External netip.Addr
	// Resolver is the currently assigned resolver (DHCP or RDNSS). Learned,
	// not pinned: a rogue DHCP or RA can move it, which is why every answer
	// is still checked at connect time.
	Resolver netip.Addr
}

// DenyEvent is one refusal, for the caller's journal.
type DenyEvent struct {
	Addr    netip.Addr
	Port    uint16
	Purpose Purpose
	Reason  string
}

// Resolver is the part of *net.Resolver the policy uses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Config configures New. The zero value is a working policy with only the
// IANA registries.
type Config struct {
	// Resolver resolves names; nil means the policy's own resolver
	// (Policy.Resolver), which asks only the learned resolver (DEV-2), so
	// the system resolver is never used.
	Resolver Resolver
	// Source, when set, is read by Refresh to learn the network.
	Source func() (Network, error)
	// Quick, when set, is a read that never waits on the network (for
	// example Sources.ReadLocal). Watch applies it at once on each event,
	// before the full Source read, so a new prefix is refused within the
	// event and not after a slow router lookup.
	Quick func() (Network, error)
	// OnDeny, when set, is called for each refusal.
	OnDeny func(DenyEvent)
	// Connect, when set, replaces the final connect to a checked literal
	// address. It is a test seam: production leaves it nil.
	Connect func(ctx context.Context, network, addr string) (net.Conn, error)
	// Timeout bounds one connect; zero means 30 seconds.
	Timeout time.Duration
}

// Policy is the address policy. It is safe for concurrent use.
type Policy struct {
	res     Resolver
	source  func() (Network, error)
	quick   func() (Network, error)
	onDeny  func(DenyEvent)
	timeout time.Duration

	// connect dials a checked literal address; tests replace it.
	connect func(ctx context.Context, network, addr string) (net.Conn, error)

	mu   sync.RWMutex
	net  Network
	gen  uint64 // bumped by each Learn; a full read older than this is stale
	pins []Pin
	// hold, while non-nil, is closed when the learned gateway's external
	// address is known: a quick read moved to a gateway with none read yet,
	// and public destinations wait for that gateway's full read (#1517).
	hold chan struct{}

	quickMu sync.Mutex // one quick read-and-learn at a time
}

// New returns a policy.
func New(cfg Config) *Policy {
	p := &Policy{res: cfg.Resolver, source: cfg.Source, quick: cfg.Quick, onDeny: cfg.OnDeny, timeout: cfg.Timeout}
	if p.res == nil {
		p.res = p.Resolver()
	}
	if p.timeout <= 0 {
		p.timeout = 30 * time.Second
	}
	p.connect = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return p.Dialer().DialContext(ctx, network, addr)
	}
	if cfg.Connect != nil {
		p.connect = cfg.Connect
	}
	return p
}

// Learn replaces the learned network.
func (p *Policy) Learn(n Network) {
	out := normalise(n)
	p.mu.Lock()
	p.learnLocked(out)
	p.releaseLocked()
	p.mu.Unlock()
}

// externalHold bounds how long a public destination waits for a new
// gateway's full read: past the NAT-PMP timeout of a full read already in
// flight and of the one queued behind it. A test shortens it.
var externalHold = 7 * time.Second

// releaseLocked ends the hold, if any; p.mu is held for writing.
func (p *Policy) releaseLocked() {
	if p.hold != nil {
		close(p.hold)
		p.hold = nil
	}
}

// learnLocked stores a normalised network and bumps the generation; p.mu is
// held for writing.
func (p *Policy) learnLocked(out Network) {
	p.net = out
	p.gen++
}

// mappedBase is ::ffff:0.0.0.0, the start of the IPv4-mapped range.
var mappedBase = netip.AddrFrom16([16]byte{10: 0xff, 11: 0xff})

// normalise drops zones, unmaps, and caps IPv6 prefixes at /56. A mapped
// prefix of /96 or longer is the IPv4 prefix it carries; a shorter one stays
// an IPv6 prefix, and any IPv6 prefix that then holds the whole mapped range
// adds 0.0.0.0/0, so no prefix length is dropped or allows less than it
// covers.
func normalise(n Network) Network {
	out := Network{Gateway: n.Gateway.WithZone("").Unmap(), GatewayDev: n.GatewayDev, GatewayMAC: n.GatewayMAC, External: n.External.WithZone("").Unmap(), Resolver: n.Resolver.WithZone("").Unmap()}
	if out.Resolver.IsLoopback() || out.Resolver.IsUnspecified() {
		out.Resolver = netip.Addr{}
	}
	for _, pf := range n.Prefixes {
		if !pf.IsValid() {
			continue
		}
		a := pf.Addr().WithZone("")
		bits := pf.Bits()
		if a.Is4In6() && bits >= 96 {
			a, bits = a.Unmap(), bits-96
		}
		if a.Is6() && bits > 56 {
			bits = 56
		}
		pf = netip.PrefixFrom(a, bits).Masked()
		out.Prefixes = append(out.Prefixes, pf)
		// Check unmaps a mapped destination, so an IPv6 prefix that holds
		// the mapped range holds every IPv4 address.
		if pf.Contains(mappedBase) {
			out.Prefixes = append(out.Prefixes, netip.PrefixFrom(netip.IPv4Unspecified(), 0))
		}
	}
	return out
}

// Refresh reads Config.Source and learns the result. A failed read keeps
// what was learned before. A read that began before a later Learn (a quick
// read on an event, or another refresh) is stale: it never replaces the
// newer set, and only its external address is kept, while the gateway is the
// one now learned. A read that returns ErrGatewayMoved asked no router on
// the gateway it ended on: that gateway is learned as a quick read learns
// it (a new one is held), and the error is returned.
func (p *Policy) Refresh() error {
	if p.source == nil {
		return errors.New("netguard: no source")
	}
	p.mu.RLock()
	gen := p.gen
	p.mu.RUnlock()
	n, err := p.source()
	moved := errors.Is(err, ErrGatewayMoved)
	if err != nil && !moved {
		return err
	}
	out := normalise(n)
	if refreshGapHook != nil {
		refreshGapHook()
	}
	// The generation check and the store are one critical section, so a
	// Learn can never land between them.
	// A full read of the learned gateway ends the hold whether or not the
	// router answered: a silent router has no address to learn.
	p.mu.Lock()
	defer p.mu.Unlock()
	if moved {
		if p.gen == gen {
			p.applyQuickLocked(out)
		}
		return err
	}
	if p.gen != gen {
		if sameGateway(out, p.net) {
			if out.External.IsValid() {
				p.net.External = out.External
			}
			p.releaseLocked()
		}
		return nil
	}
	p.learnLocked(out)
	p.releaseLocked()
	return nil
}

// refreshGapHook, when set by a test, runs after a full read returns and
// before Refresh takes the lock to check the generation and store.
var refreshGapHook func()

// Watch refreshes on each event until ctx ends: the broker sends one on
// every address or route change. Each event applies the quick read at once;
// the full read (which may wait on the router) runs single-flight on its own
// goroutine, so a later event is never queued behind it. When ctx ends,
// Watch returns only after that goroutine has, so no full read outlives it.
func (p *Policy) Watch(ctx context.Context, events <-chan struct{}) {
	kick := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-kick:
				// A read the gateway moved under is followed at once by
				// one on the gateway it ended on.
				if errors.Is(p.Refresh(), ErrGatewayMoved) {
					select {
					case kick <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			<-done
			return
		case _, ok := <-events:
			if !ok {
				return
			}
			p.quickLearn()
			select {
			case kick <- struct{}{}:
			default:
			}
		}
	}
}

// quickLearn applies the Quick read, if there is one. A failed read keeps
// what was learned before. While the gateway is unchanged the router's
// external address is always the one learned, never the quick read's copy
// (which may predate a newer full read), and the resolver stays when the
// quick read has none. On a new gateway the quick read's own external
// address (the last one read on that gateway) applies; with none, public
// destinations are held until that gateway's full read stores (fail closed,
// bounded by externalHold).
func (p *Policy) quickLearn() {
	if p.quick == nil {
		return
	}
	p.quickMu.Lock()
	defer p.quickMu.Unlock()
	n, err := p.quick()
	if err != nil {
		return
	}
	if quickGapHook != nil {
		quickGapHook()
	}
	// The merge with what is learned and the store are one critical section,
	// so a full read can never store a newer external address between them.
	p.mu.Lock()
	defer p.mu.Unlock()
	if quickLockedHook != nil {
		quickLockedHook()
	}
	p.applyQuickLocked(normalise(n))
}

// applyQuickLocked learns out, a read that asked no router, merged with what
// is learned as quickLearn describes; p.mu is held for writing.
func (p *Policy) applyQuickLocked(out Network) {
	old := p.net
	if out.Gateway.IsValid() && sameGateway(out, old) {
		out.External = old.External
		if !out.Resolver.IsValid() {
			out.Resolver = old.Resolver
		}
	} else if out.Gateway.IsValid() && !out.External.IsValid() && p.source != nil {
		if p.hold == nil {
			p.hold = make(chan struct{})
		}
	} else {
		p.releaseLocked()
	}
	p.learnLocked(out)
}

// sameGateway reports whether a and b learned the same gateway: the same
// address, interface and MAC. A MAC known on one side only is a different
// gateway, since a link flap that brings another router flushes the entry.
func sameGateway(a, b Network) bool {
	return a.Gateway == b.Gateway && a.GatewayDev == b.GatewayDev && a.GatewayMAC == b.GatewayMAC
}

// quickGapHook, when set by a test, runs after a quick read returns and
// before quickLearn takes the lock to merge and store.
var quickGapHook func()

// quickLockedHook, when set by a test, runs inside quickLearn's critical
// section, right after it reads what is learned.
var quickLockedHook func()

// SetPins replaces the pinned exceptions.
func (p *Policy) SetPins(pins []Pin) error {
	cp := make([]Pin, len(pins))
	for i, pin := range pins {
		if err := pin.validate(); err != nil {
			return err
		}
		pin.Name = strings.ToLower(strings.TrimSuffix(pin.Name, "."))
		if pin.Addr.IsValid() {
			pin.Addr = netip.AddrPortFrom(pin.Addr.Addr().Unmap().WithZone(""), pin.Addr.Port())
		}
		cp[i] = pin
	}
	p.mu.Lock()
	p.pins = cp
	p.mu.Unlock()
	return nil
}

type reqKey struct{}

type request struct {
	purpose Purpose
	name    string
}

// WithPurpose says why the dials made with ctx are made.
func WithPurpose(ctx context.Context, pu Purpose) context.Context {
	r, _ := ctx.Value(reqKey{}).(request)
	r.purpose = pu
	return context.WithValue(ctx, reqKey{}, r)
}

func withName(ctx context.Context, name string) context.Context {
	r, _ := ctx.Value(reqKey{}).(request)
	r.name = name
	return context.WithValue(ctx, reqKey{}, r)
}

func requestOf(ctx context.Context) request {
	r, _ := ctx.Value(reqKey{}).(request)
	return r
}

// Check decides one connection. proto is "tcp" or "udp".
//
// The four exceptions (DEV-2), each only as stated:
//  1. PurposeDNS: the currently assigned resolver, port 53, tcp or udp.
//  2. a compute host's declared endpoint (PinCompute), reached by a routed
//     model call;
//  3. a device executor's own device (PinDevice), by PurposeDevice;
//  4. an owner-pinned backup target (PinBackup, PurposeBackup) or private
//     hosted route (PinHosted, a routed model call).
//
// A pin matches on its address or its name; the key pin is checked at the
// handshake (TLSConfig). No other purpose, and no agent request that is not
// a routed model call, reaches any of them.
func (p *Policy) Check(ctx context.Context, a netip.Addr, port uint16, proto string) error {
	r := requestOf(ctx)
	a = a.WithZone("")
	if a.Is4In6() {
		a = a.Unmap()
	}
	err := p.check(ctx, r, a, port, proto)
	if err != nil && p.onDeny != nil {
		var de *DeniedError
		reason := err.Error()
		if errors.As(err, &de) {
			reason = de.Reason
		}
		p.onDeny(DenyEvent{Addr: a, Port: port, Purpose: r.purpose, Reason: reason})
	}
	return err
}

func (p *Policy) check(ctx context.Context, r request, a netip.Addr, port uint16, proto string) error {
	var deadline <-chan time.Time
	for {
		hold, err := p.checkOnce(r, a, port, proto)
		if hold == nil {
			return err
		}
		if deadline == nil {
			t := time.NewTimer(externalHold)
			defer t.Stop()
			deadline = t.C
		}
		select {
		case <-hold:
		case <-ctx.Done():
			return &DeniedError{a, "the router's external address on this gateway is not learned yet"}
		case <-deadline:
			return &DeniedError{a, "the router's external address on this gateway is not learned yet"}
		}
	}
}

// checkOnce decides a against what is learned now. A destination every
// rule allows while a hold is on is not decided: checkOnce returns the hold
// to wait on, since it may be the router's not-yet-learned external address.
func (p *Policy) checkOnce(r request, a netip.Addr, port uint16, proto string) (chan struct{}, error) {
	if !a.IsValid() {
		return nil, &DeniedError{a, "unparsable address"}
	}
	p.mu.RLock()
	n, pins, hold := p.net, p.pins, p.hold
	p.mu.RUnlock()

	if r.purpose == PurposeDNS {
		// Exception 1 is the only DNS destination: a name resolves through
		// the assigned resolver or not at all, so another port-53 address
		// (public ones included) is refused here, not left to the deny list.
		if (proto == "tcp" || proto == "udp") && port == 53 && n.Resolver.IsValid() && a == n.Resolver {
			return nil, nil
		}
		return nil, &DeniedError{a, "names resolve only through the assigned resolver on port 53"}
	} else {
		for _, pin := range pins {
			if pin.Kind.purpose() != r.purpose {
				continue
			}
			if (pin.Name != "" && pin.Name == r.name) || (pin.Addr.IsValid() && pin.Addr == netip.AddrPortFrom(a, port)) {
				return nil, nil
			}
		}
	}

	for _, f := range forms(a) {
		if why, bad := Special(f); bad {
			return nil, &DeniedError{a, why}
		}
		for _, pf := range n.Prefixes {
			if pf.Contains(f) {
				return nil, &DeniedError{a, "home network prefix " + pf.String()}
			}
		}
		if n.Gateway.IsValid() && f == n.Gateway {
			return nil, &DeniedError{a, "gateway"}
		}
		if n.External.IsValid() && f == n.External {
			return nil, &DeniedError{a, "router external address"}
		}
		if n.Resolver.IsValid() && f == n.Resolver {
			return nil, &DeniedError{a, "the learned resolver is reachable only for names (port 53)"}
		}
	}
	return hold, nil
}

func protoOf(network string) string {
	switch {
	case strings.HasPrefix(network, "tcp"):
		return "tcp"
	case strings.HasPrefix(network, "udp"):
		return "udp"
	}
	return network
}

// control is the net.Dialer hook: it checks the address actually being
// connected.
func (p *Policy) control(ctx context.Context, network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return &DeniedError{netip.Addr{}, "unparsable address"}
	}
	return p.Check(ctx, ap.Addr(), ap.Port(), protoOf(network))
}

// Dialer returns a net.Dialer whose ControlContext hook is the policy.
func (p *Policy) Dialer() *net.Dialer {
	return &net.Dialer{Timeout: p.timeout, ControlContext: p.control}
}

// DialContext is the dial function every outbound transport uses (an
// http.Transport's DialContext, a TLS or SMTP client's dial). It resolves
// the name, refuses the dial if any answer is refused, then connects to a
// literal address through Dialer, so the check runs on the address
// actually connected. Nothing is cached: a name that answers differently
// the next time is checked again.
func (p *Policy) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	pn, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("netguard: port %q is not a number", port)
	}
	proto := protoOf(network)
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ctx = withName(ctx, strings.ToLower(strings.TrimSuffix(host, ".")))
		lookup := "ip"
		if strings.HasSuffix(network, "4") {
			lookup = "ip4"
		} else if strings.HasSuffix(network, "6") {
			lookup = "ip6"
		}
		if ips, err = p.res.LookupNetIP(ctx, lookup, host); err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("netguard: %s resolved to nothing", host)
	}
	for _, ip := range ips {
		if err := p.Check(ctx, ip, uint16(pn), proto); err != nil {
			return nil, err
		}
	}
	var last error
	for _, ip := range ips {
		c, err := p.connect(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// CheckRedirect is an http.Client's CheckRedirect: a redirect to a literal
// private address, or off http(s), is refused before any dial. A redirect
// to a name is checked when it is dialed.
func (p *Policy) CheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("netguard: too many redirects")
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		return &DeniedError{netip.Addr{}, "redirect off http"}
	}
	if ip, err := netip.ParseAddr(req.URL.Hostname()); err == nil {
		port := uint16(80)
		if req.URL.Scheme == "https" {
			port = 443
		}
		if n, err := strconv.ParseUint(req.URL.Port(), 10, 16); err == nil {
			port = uint16(n)
		}
		return p.Check(req.Context(), ip, port, "tcp")
	}
	return nil
}
