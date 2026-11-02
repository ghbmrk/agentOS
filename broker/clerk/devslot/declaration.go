// Package devslot is the public device-driver slot (DEVSLOT-drivers, D-189).
// A driver is one vendor's protocol code kept outside this repository: it
// declares its operations, frames bytes and parses replies, and nothing else.
// The slot is the only code that touches the link, the sealed store and the
// bus: it checks the declaration before the driver runs (DEV-1, DEV-4), lets
// the driver write only declared shapes to its pinned device (DEV-2, DEV-3),
// lends it only its own device/ slot (CLK-1, D-184), and turns its readings
// into typed, private events (DEV-8). The conformance package is the suite
// every driver passes.
package devslot

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"regexp"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// LinkKind is how the slot reaches the device.
type LinkKind string

// The closed list of link kinds.
const (
	// GATT is Bluetooth LE GATT through the enforcer's generic relay (NET-2):
	// one pinned address, declared characteristics, writes and notifications.
	GATT LinkKind = "gatt"
	// TCP is one stream to a pinned home-network endpoint whose key the host
	// checks (DEV-3).
	TCP LinkKind = "tcp"
)

// ShapeKind is a wire shape's kind; each link kind has exactly one.
type ShapeKind string

// The closed list of wire-shape kinds.
const (
	GATTWrite ShapeKind = "gatt-write"
	TCPFrame  ShapeKind = "tcp-frame"
)

var shapeOf = map[LinkKind]ShapeKind{GATT: GATTWrite, TCP: TCPFrame}

// Channel is one place on the device a frame goes to or comes from: a GATT
// characteristic, or the TCP stream on its port.
type Channel struct {
	Name    string
	Service string // GATT only: a 16-bit or 128-bit UUID
	Char    string // GATT only
	Port    uint16 // TCP only
}

// Shape is one frame the driver may write (DEV-4: the clerk sends nothing
// else): a frame on Channel that starts with Prefix and is Min to Max bytes
// long. A fixed frame has Min = Max = len(Prefix).
type Shape struct {
	Name    string
	Channel string
	Kind    ShapeKind
	Prefix  []byte
	Min     int
	Max     int
}

// Operation is one declared device operation, its verb (DEV-4), the
// shapes it may write and MaxWrites, how many frames one run of it may
// write in all, so one approval of the operation covers that many writes
// and no more (#3506). An operation with shapes declares at least one write;
// one without declares none. A Subscribe operation is a read that stays up and
// reports each reading as it arrives, through Link.Report, until the host
// ends it (DEVSLOT-subscribe-1).
type Operation struct {
	Name      string
	Verb      key.Verb
	Shapes    []string
	MaxWrites int  `json:",omitempty"`
	Subscribe bool `json:",omitempty"`
}

// Declaration is a driver's DEV-1 declaration, as data. It names no address:
// the host pins the device at connection (Pin).
type Declaration struct {
	Device     string
	Link       LinkKind
	Channels   []Channel
	Shapes     []Shape
	Operations []Operation
	// Readings is the closed list of reading kinds the driver may report.
	Readings []string
	// MaxRead bounds one frame read from the device.
	MaxRead int
	// MaxReadings bounds the readings one operation reports.
	MaxReadings int
}

// Pin is the one device a slot reaches, pinned by the host at connection
// (DEV-3), never by the driver.
type Pin struct {
	// Address is a GATT device's Bluetooth address, AA:BB:CC:DD:EE:FF.
	Address string
	// Host is a TCP device's home-network address; Key is the SHA-256 of
	// the identity key the host's transport checks (DEV-3).
	Host netip.Addr
	Key  [32]byte
}

// Slot-wide caps, whatever a declaration says.
const (
	CapRead  = 65540 // one frame read
	CapWrite = 4096  // one frame written
	// CapWrites is the most frames one run of an operation writes: a
	// CapWrite payload in 20-byte chunks, Bluetooth LE's smallest MTU, is
	// 205; rounded up to 256.
	CapWrites   = 256
	CapReadings = 1024 // readings per operation
	CapKinds    = 32   // reading kinds, each its own DEV-8 window (DEVSLOT-host-lib-8)
)

// devVerbs is DEV-4's verb list: read, actuate, actuate-physical, present,
// and the administration verbs.
var devVerbs = map[key.Verb]bool{
	key.Read: true, key.Actuate: true, key.ActuatePhysical: true, key.Present: true,
	key.ChangeAccount: true, key.DeleteRemote: true, key.RevealOrCreateSecret: true,
}

var (
	nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,39}$`)
	uuidRe = regexp.MustCompile(`^([0-9a-f]{4}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$`)
	macRe  = regexp.MustCompile(`^[0-9A-F]{2}(:[0-9A-F]{2}){5}$`)
)

// ErrDeclaration is a declaration or pin the slot refuses; the driver does
// not run.
var ErrDeclaration = errors.New("devslot: declaration refused")

func refuse(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrDeclaration}, a...)...)
}

// Check is whether d and p may run: only DEV-4 verbs, only known link and
// shape kinds, names from a closed alphabet (so no device text reaches an
// event), bounded frames, and a pin on the home network only (DEV-2). The
// host passes home, the uplink's enclosing /56, for global IPv6 pins.
func Check(d Declaration, p Pin, home ...netip.Prefix) error {
	if !nameRe.MatchString(d.Device) {
		return refuse("device name")
	}
	sk, ok := shapeOf[d.Link]
	if !ok {
		return refuse("unknown link kind %q", d.Link)
	}
	var h netip.Prefix
	if len(home) > 1 {
		return refuse("one home prefix")
	} else if len(home) == 1 {
		h = home[0]
	}
	if err := checkPin(d.Link, p, h); err != nil {
		return err
	}
	if d.MaxRead < 1 || d.MaxRead > CapRead {
		return refuse("MaxRead out of range")
	}
	if d.MaxReadings < 0 || d.MaxReadings > CapReadings {
		return refuse("MaxReadings out of range")
	}
	chans := map[string]bool{}
	if d.Link == TCP && len(d.Channels) != 1 {
		return refuse("a tcp link has one channel")
	}
	if len(d.Channels) == 0 {
		return refuse("no channel")
	}
	for _, c := range d.Channels {
		if !nameRe.MatchString(c.Name) || chans[c.Name] {
			return refuse("channel name")
		}
		chans[c.Name] = true
		switch d.Link {
		case GATT:
			if !uuidRe.MatchString(c.Service) || !uuidRe.MatchString(c.Char) || c.Port != 0 {
				return refuse("channel %s: a gatt channel is a service and a characteristic", c.Name)
			}
		case TCP:
			if c.Port == 0 || c.Service != "" || c.Char != "" {
				return refuse("channel %s: a tcp channel is a port", c.Name)
			}
		}
	}
	shapes := map[string]bool{}
	for _, s := range d.Shapes {
		if !nameRe.MatchString(s.Name) || shapes[s.Name] {
			return refuse("shape name")
		}
		shapes[s.Name] = true
		if s.Kind != sk {
			return refuse("shape %s: kind %q is not %q", s.Name, s.Kind, sk)
		}
		if !chans[s.Channel] {
			return refuse("shape %s: undeclared channel", s.Name)
		}
		if s.Min < len(s.Prefix) || s.Min < 1 || s.Max < s.Min || s.Max > CapWrite {
			return refuse("shape %s: bounds", s.Name)
		}
	}
	if len(d.Operations) == 0 {
		return refuse("no operation")
	}
	ops := map[string]bool{}
	for _, o := range d.Operations {
		if !nameRe.MatchString(o.Name) || ops[o.Name] {
			return refuse("operation name")
		}
		ops[o.Name] = true
		if !devVerbs[o.Verb] {
			return refuse("operation %s: verb %q is not a DEV-4 verb", o.Name, o.Verb)
		}
		if o.Subscribe && o.Verb != key.Read {
			return refuse("operation %s: a subscription is a read", o.Name)
		}
		for _, s := range o.Shapes {
			if !shapes[s] {
				return refuse("operation %s: undeclared shape", o.Name)
			}
		}
		if o.MaxWrites < 0 || o.MaxWrites > CapWrites || (len(o.Shapes) == 0) != (o.MaxWrites == 0) {
			return refuse("operation %s: MaxWrites out of range", o.Name)
		}
	}
	if len(d.Readings) > CapKinds {
		return refuse("more than %d reading kinds", CapKinds)
	}
	kinds := map[string]bool{}
	for _, k := range d.Readings {
		if !nameRe.MatchString(k) || kinds[k] {
			return refuse("reading kind")
		}
		kinds[k] = true
	}
	return nil
}

func checkPin(l LinkKind, p Pin, home netip.Prefix) error {
	switch l {
	case GATT:
		if !macRe.MatchString(p.Address) || p.Host.IsValid() {
			return refuse("a gatt pin is one Bluetooth address")
		}
	case TCP:
		if p.Address != "" || !homeAddr(p.Host, home) {
			return refuse("a tcp pin is a home-network address")
		}
		if p.Key == ([32]byte{}) {
			return refuse("a tcp pin needs the device's key (DEV-3)")
		}
	}
	return nil
}

// homeAddr is a home-network unicast address (DEV-1, DEV-2): a private,
// shared (100.64.0.0/10) or link-local IPv4 address that is not a directed
// broadcast, a unique-local or link-local IPv6 address, or a global IPv6
// address inside home, the uplink's enclosing /56. Never the internet, the
// box itself, or a broadcast or multicast group. A v4-mapped address is
// judged as its IPv4 address. A home outside 2000::/3, or inside a prefix
// that carries IPv4 addresses (NAT64, 6to4, Teredo), holds no home address,
// since such addresses reach the IPv4 internet.
func homeAddr(a netip.Addr, home netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		// Every broadcast of a /24 or wider ends in .255; a narrower home
		// subnet's broadcast is not caught here (DEVSLOT-host-lib-3).
		return (a.IsPrivate() || a.IsLinkLocalUnicast() || shared.Contains(a)) && a.As4()[3] != 255
	}
	if a.IsPrivate() || a.IsLinkLocalUnicast() {
		return true
	}
	// The /56 must lie in 2000::/3, the global unicast allocation, which
	// its first three bits decide, whatever host bits a caller left set.
	if !home.IsValid() || home.Bits() != 56 || !globalUnicast.Contains(home.Addr()) ||
		!a.IsGlobalUnicast() || !home.Contains(a.WithZone("")) {
		return false
	}
	for _, t := range translated {
		if t.Overlaps(home) {
			return false
		}
	}
	return true
}

// globalUnicast is IPv6's global unicast allocation (RFC 4291 §2.4).
var globalUnicast = netip.MustParsePrefix("2000::/3")

// translated are the prefixes inside 2000::/3 whose addresses carry IPv4
// ones: 6to4 (RFC 3056) and Teredo (RFC 4380). NAT64's (64:ff9b::/96,
// 64:ff9b:1::/48), the IPv4-compatible ::/96 and the IPv4-translated
// ::ffff:0:0:0/96 lie outside 2000::/3.
var translated = []netip.Prefix{
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

// shared is RFC 6598's shared address space, which a carrier-grade NAT or
// a home router's own segment may use.
var shared = netip.MustParsePrefix("100.64.0.0/10")

// match is whether frame on ch is one of op's declared shapes.
func (d *Declaration) match(op Operation, ch string, frame []byte) bool {
	for _, name := range op.Shapes {
		for _, s := range d.Shapes {
			if s.Name == name && s.Channel == ch && len(frame) >= s.Min && len(frame) <= s.Max &&
				bytes.HasPrefix(frame, s.Prefix) {
				return true
			}
		}
	}
	return false
}
