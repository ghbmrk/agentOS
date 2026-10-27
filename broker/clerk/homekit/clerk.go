package homekit

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

// DefaultTimeout bounds each dial and each exchange with an accessory
// (#3325 item 3, HK-11).
const DefaultTimeout = 10 * time.Second

// ErrDeviceOff: the accessory failed pair-verify against its pin; it stays
// off until the owner pairs it again with its HomeKit code (DEV-3).
var ErrDeviceOff = errors.New("homekit: device is off until the owner pairs it again")

// ErrUnresolved: the accessory is paired, but its thermostats are not yet
// resolved; the Device keeps the pin, and Resolve runs again later.
var ErrUnresolved = errors.New("homekit: paired, thermostats not resolved")

// Device is what the host keeps for one paired thermostat. None of it is
// secret: the controller key stays in the sealed store. The clerk sets Off
// on an identity mismatch and Bounds when the owner confirms them.
type Device struct {
	// Name is the host's name for the device on the bus.
	Name string
	// Addr is the pinned "ip:port"; the clerk dials nothing else.
	Addr string
	Pin  Pin
	// AID is the thermostat's accessory on the pinned accessory (a bridge
	// exposes one per thermostat).
	AID uint64
	// Bounds are the owner's confirmed setpoint bounds, by characteristic
	// type, for the kernel table's WriteVerb (DEV-4, DEV-5).
	Bounds map[string]Bounds
	Off    bool
}

// Label is an event's data-flow label: always private (PLN-3).
const Label = "private"

// Event is one thermostat value as it goes onto the bus (DEV-8): private
// and untrusted, from an accessory that proved its pinned key at this
// session's pair-verify (DEV-3). It carries no text from the accessory: the
// type is a resolved HAP type and the value a bool or number.
type Event struct {
	Device         string
	Label          string
	Characteristic string
	Value          any
}

// Clerk is the core-side HomeKit clerk (part b of #3291). It pairs by the
// owner's HomeKit code, opens pinned sessions, and puts thermostat values on
// the bus through Emit. Which verb a write needs is the kernel table's
// (ThermostatRows); the clerk performs only what the kernel admitted.
type Clerk struct {
	Keys KeyHolder
	// Dial reaches one pinned address; nil dials TCP with Timeout.
	Dial func(ctx context.Context, addr string) (net.Conn, error)
	// Timeout bounds each dial and exchange; 0 is DefaultTimeout.
	Timeout time.Duration
	// Emit puts one event on the bus.
	Emit func(Event) error
	// Log takes one line per step: fixed phrases, device names and
	// accessory IDs only, never key material.
	Log func(string)
}

// Format prints no field, whatever the verb.
func (c *Clerk) Format(f fmt.State, _ rune) { fmt.Fprint(f, "homekit.Clerk{}") }

func (c *Clerk) log(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

func (c *Clerk) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// checkAddr admits only an "ip:port" on the local network: a private,
// link-local or unique-local address, never a name to resolve, so the clerk
// reaches no internet host (NET-2, HK-11).
func checkAddr(addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || ap.Port() == 0 {
		return fmt.Errorf("%w: address is not ip:port", ErrRefused)
	}
	a := ap.Addr()
	if !a.IsPrivate() && !a.IsLinkLocalUnicast() {
		return fmt.Errorf("%w: address is not on the local network", ErrRefused)
	}
	return nil
}

// dial reaches addr and bounds the whole step by Timeout: the step's
// context closes the connection when it ends. done stops watching it.
func (c *Clerk) dial(ctx context.Context, addr string) (net.Conn, func(), error) {
	if err := checkAddr(addr); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	var conn net.Conn
	var err error
	if c.Dial != nil {
		conn, err = c.Dial(ctx, addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		cancel()
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return conn, func() { stop(); cancel() }, nil
}

// Connect is the tier-4 connect step (DEV-10, CH-3): one pair-setup with the
// HomeKit code the owner typed on the local page, then Resolve. It makes one
// attempt (HK-5); a wrong code pins nothing and returns no Device.
//
// Once pair-setup succeeds the accessory holds the box as its controller,
// so the pin must not be lost: if Resolve then fails, Connect returns the
// pinned Device with AID 0 and an error wrapping ErrUnresolved. The host
// keeps that Device and calls Resolve again later.
func (c *Clerk) Connect(ctx context.Context, name, addr, code string) ([]Device, error) {
	conn, done, err := c.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	pin, err := PairSetup(conn, addr, code, c.Keys, Options{Logf: c.logf()})
	done()
	conn.Close()
	if err != nil {
		return nil, err
	}
	d := Device{Name: name, Addr: addr, Pin: pin}
	out, err := c.Resolve(ctx, &d)
	if err != nil {
		return []Device{d}, err
	}
	return out, nil
}

// Resolve opens a pinned session with d and returns one Device per
// thermostat accessory behind the pin (a bridge exposes one per `aid`),
// named d.Name, d.Name-2 and on. Any failure wraps ErrUnresolved; a key
// mismatch also turns d off (Open).
func (c *Clerk) Resolve(ctx context.Context, d *Device) ([]Device, error) {
	if d.Off {
		return nil, fmt.Errorf("%w: %w", ErrUnresolved, ErrDeviceOff)
	}
	l, err := c.open(ctx, d, false)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnresolved, err)
	}
	defer l.Close()
	aids := l.s.Accessories(ServiceThermostat)
	if len(aids) == 0 {
		c.log("homekit: accessory %s offers no thermostat", d.Pin.AccessoryID)
		return nil, fmt.Errorf("%w: %w: accessory offers no thermostat", ErrUnresolved, ErrRefused)
	}
	out := make([]Device, len(aids))
	for i, aid := range aids {
		out[i] = Device{Name: d.Name, Addr: d.Addr, Pin: d.Pin, AID: aid}
		if i > 0 {
			out[i].Name = fmt.Sprintf("%s-%d", d.Name, i+1)
		}
	}
	c.log("homekit: paired %s with accessory %s, %d thermostats", d.Name, d.Pin.AccessoryID, len(out))
	return out, nil
}

// logf adapts Log to Options.Logf.
func (c *Clerk) logf() func(string, ...any) {
	if c.Log == nil {
		return nil
	}
	return func(format string, args ...any) { c.log(format, args...) }
}

// Open dials d's pinned address, proves its pinned key with pair-verify,
// resolves the thermostat and subscribes to its events. An accessory that
// proves another key turns d off with a KRN-7 line; it stays off, with
// nothing read or written, until the owner pairs it again.
func (c *Clerk) Open(ctx context.Context, d *Device) (*Link, error) {
	if d.Off {
		return nil, ErrDeviceOff
	}
	if d.AID == 0 {
		return nil, ErrUnresolved
	}
	return c.open(ctx, d, true)
}

func (c *Clerk) open(ctx context.Context, d *Device, thermostat bool) (*Link, error) {
	conn, done, err := c.dial(ctx, d.Addr)
	if err != nil {
		return nil, err
	}
	l := &Link{c: c, d: d, conn: conn}
	s, err := Verify(conn, d.Addr, d.Pin, c.Keys, Options{Logf: c.logf(), OnEvent: l.onEvent})
	if err != nil {
		done()
		if errors.Is(err, ErrIdentity) {
			d.Off = true
			c.log("homekit: KRN-7 device %s off: accessory did not prove pinned key of %s; owner must pair it again", d.Name, d.Pin.AccessoryID)
		}
		return nil, err
	}
	l.s = s
	err = s.Resolve()
	if err == nil && thermostat {
		err = l.subscribe()
	}
	done()
	if err != nil {
		s.Close()
		return nil, err
	}
	return l, nil
}

// Link is one open session with a device's thermostat.
type Link struct {
	c    *Clerk
	d    *Device
	conn net.Conn
	s    *Session

	// stepMu serializes exchanges, so one step's deadline is never set
	// or cleared under another's (#3335 L3).
	stepMu sync.Mutex

	mu     sync.Mutex
	failed int // events the bus refused
}

// Close ends the session; a blocked exchange ends at once.
func (l *Link) Close() error { return l.s.Close() }

// step bounds one exchange by the clerk's Timeout. Steps run one at a time:
// a step waits at most for the one before it, which its own deadline
// bounds. Every exchange on a Link goes through step.
func (l *Link) step(fn func() error) error {
	l.stepMu.Lock()
	defer l.stepMu.Unlock()
	l.conn.SetDeadline(time.Now().Add(l.c.timeout()))
	defer l.conn.SetDeadline(time.Time{})
	return fn()
}

func (l *Link) find(typ string) (Characteristic, error) {
	ch, ok := l.s.Find(l.d.AID, ServiceThermostat, typ)
	if !ok {
		return Characteristic{}, fmt.Errorf("%w: thermostat %s has no characteristic %s", ErrRefused, l.d.Name, typ)
	}
	return ch, nil
}

func (l *Link) subscribe() error {
	chars := l.s.Of(l.d.AID, ServiceThermostat)
	if len(chars) == 0 {
		return fmt.Errorf("%w: accessory %d is not a thermostat", ErrRefused, l.d.AID)
	}
	for _, ch := range chars {
		if ch.can("ev") {
			if err := l.s.Subscribe(ch.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

// Poll reads every readable characteristic of the thermostat and puts each
// value on the bus. Events the accessory queued arrive with it, so the host
// polls to hear them; it returns the number of values emitted.
func (l *Link) Poll() (int, error) {
	var ids []ID
	for _, ch := range l.s.Of(l.d.AID, ServiceThermostat) {
		if ch.can("pr") {
			ids = append(ids, ch.ID)
		}
	}
	var vals []Value
	err := l.step(func() (err error) { vals, err = l.s.Read(ids...); return })
	if err != nil {
		return 0, err
	}
	return l.emit(vals), nil
}

// Config takes the accessory's TXT c# and re-resolves when it changed.
func (l *Link) Config(c int) error {
	return l.step(func() error {
		if err := l.s.ConfigNumber(c); err != nil {
			return err
		}
		return l.subscribe()
	})
}

// Write sets one thermostat characteristic by type, after the kernel
// admitted it under the row's verb. The session checks the value against
// the resolved shape before framing it (DEV-4).
func (l *Link) Write(typ string, value any) error {
	ch, err := l.find(typ)
	if err != nil {
		return err
	}
	return l.step(func() error { return l.s.Write(ch.ID, value) })
}

// ConfirmBounds records the owner's confirmed bounds for a setpoint (DEV-5).
// Only a row with an in-bounds verb takes bounds, and they must lie inside
// the characteristic's declared range.
func (l *Link) ConfirmBounds(typ string, lo, hi float64) error {
	ch, err := l.find(typ)
	if err != nil {
		return err
	}
	if ClassFor(ch.Service, ch.Type).InBounds == "" {
		return fmt.Errorf("%w: %s takes no bounds", ErrRefused, typ)
	}
	if math.IsNaN(lo) || math.IsNaN(hi) || math.IsInf(lo, 0) || math.IsInf(hi, 0) || lo > hi ||
		ch.Min != nil && lo < *ch.Min || ch.Max != nil && hi > *ch.Max {
		return fmt.Errorf("%w: bounds outside the declared range", ErrRefused)
	}
	if l.d.Bounds == nil {
		l.d.Bounds = map[string]Bounds{}
	}
	l.d.Bounds[typ] = Bounds{Min: lo, Max: hi, Confirmed: true}
	l.c.log("homekit: owner confirmed bounds for %s on %s", typ, l.d.Name)
	return nil
}

// onEvent is the session's event hook. It runs after the session's lock is
// released, so it may look the characteristic up (#3325 item 1); values of
// another accessory on a bridge are dropped (#3325 item 2).
func (l *Link) onEvent(vals []Value) { l.emit(vals) }

func (l *Link) emit(vals []Value) int {
	sent := 0
	for _, v := range vals {
		if v.AID != l.d.AID {
			continue
		}
		ch, ok := l.s.Characteristic(v.ID)
		if !ok || ch.Service != ServiceThermostat {
			continue
		}
		switch v.V.(type) {
		case bool, float64:
		default:
			continue
		}
		if l.c.Emit == nil {
			continue
		}
		if err := l.c.Emit(Event{Device: l.d.Name, Label: Label, Characteristic: ch.Type, Value: v.V}); err != nil {
			l.mu.Lock()
			l.failed++
			l.mu.Unlock()
			l.c.log("homekit: bus refused a value from %s", l.d.Name)
			continue
		}
		sent++
	}
	return sent
}

// Refused is how many values the bus refused on this link.
func (l *Link) Refused() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.failed
}
