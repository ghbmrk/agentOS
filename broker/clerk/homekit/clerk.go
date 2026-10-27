package homekit

import (
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// ControllerSlot is the sealed-store slot of the box's controller long-term
// key seed (iOSDeviceLTSK, Ed25519): a static slot under clerk.DeviceSlots,
// opened only through clerk.Secrets.DeviceKey (STO-2, CLK-1).
const ControllerSlot = "device/homekit/controller"

// NewControllerKey draws a fresh 32-byte seed, hands it to put (the host
// seals it into ControllerSlot with clerk.Secrets.Put) and wipes it after.
func NewControllerKey(put func(seed []byte) error) error {
	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	return put(seed)
}

// SealedKey is the controller key as the clerk holds it: no key bytes, only
// Open, which lends the seed from the sealed store for one call and wipes it
// after (clerk.Secrets.DeviceKey(ControllerSlot)). Sign opens it, signs and
// wipes the expanded key; only the public half is kept (#3325 item 4).
type SealedKey struct {
	Open func(fn func(seed []byte) error) error
	// ID is the controller's pairing ID, a UUID chosen at setup.
	ID string

	mu  sync.Mutex
	pub ed25519.PublicKey
}

// errSeed is a sealed seed of the wrong size.
var errSeed = errors.New("homekit: sealed controller key is not a 32-byte seed")

func (k *SealedKey) with(fn func(priv ed25519.PrivateKey)) error {
	return k.Open(func(seed []byte) error {
		if len(seed) != ed25519.SeedSize {
			return errSeed
		}
		priv := ed25519.NewKeyFromSeed(seed)
		defer clear(priv)
		fn(priv)
		return nil
	})
}

func (k *SealedKey) PairingID() string { return k.ID }

// PublicKey returns the controller's public key, opening the store once to
// derive it; it returns nil when the store cannot lend a valid seed, which
// pairing refuses.
func (k *SealedKey) PublicKey() ed25519.PublicKey {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.pub == nil {
		var pub ed25519.PublicKey
		if k.with(func(priv ed25519.PrivateKey) {
			pub = append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...)
		}) != nil {
			return nil
		}
		k.pub = pub
	}
	return append(ed25519.PublicKey(nil), k.pub...)
}

// Sign signs msg inside one lent call.
func (k *SealedKey) Sign(msg []byte) ([]byte, error) {
	var sig []byte
	if err := k.with(func(priv ed25519.PrivateKey) { sig = ed25519.Sign(priv, msg) }); err != nil {
		return nil, err
	}
	return sig, nil
}

// Format prints no field, whatever the verb.
func (k *SealedKey) Format(f fmt.State, _ rune) { fmt.Fprint(f, "homekit.SealedKey{key: sealed}") }

// Label is an event's data-flow label: always private (PLN-3).
const Label = "private"

// Event is one characteristic value as it goes onto the bus (DEV-8):
// private and unverified (DEV-3), a bool or a number, never accessory text.
type Event struct {
	Device        string // the owner's name for the device
	Label         string
	Unverified    bool
	ID            ID
	Service, Type string
	Value         any // bool or float64
	Time          time.Time
}

// Clerk limits.
const (
	// DefaultGap is the least time between two events of one
	// characteristic; values in between are coalesced to the latest.
	DefaultGap = time.Minute
	// DefaultMaxEvents bounds the events of all devices in one gap.
	DefaultMaxEvents = 64
	// DefaultTimeout bounds each pairing step and each session round trip.
	DefaultTimeout = 30 * time.Second
)

var (
	// ErrNotPaired: the device has no pin; the owner pairs it first.
	ErrNotPaired = errors.New("homekit: device is not paired")
	// ErrDeviceOff: the device failed its pin and is off until the owner
	// pairs it again (DEV-3).
	ErrDeviceOff = errors.New("homekit: device is off until the owner pairs it again")
)

// Stats counts what the clerk did not put on the bus at once.
type Stats struct {
	Coalesced int // values held back by the gap or the window
	Text      int // text values, never put on the bus
	Failed    int // events the bus refused (held for the next Flush)
	Refused   int // connections refused because the device is off
}

// DeviceState is one device in the pin store, for the host to keep.
type DeviceState struct {
	Name   string
	Pin    Pin
	Off    bool
	Bounds map[string]Bounds // by characteristic type
}

type device struct {
	pin    Pin
	off    bool
	bounds map[string]Bounds
}

type flowKey struct {
	device string
	id     ID
}

type flow struct {
	last    time.Time
	pending *Event
}

// Clerk is the core-side HomeKit clerk (part b1 of #3291): it pairs and pins
// devices on the owner's step, opens verified sessions with the sealed
// controller key, keeps the owner's setpoint bounds, and puts characteristic
// events on the bus through Emit, at most one per characteristic per Gap
// and MaxEvents per Gap in all.
//
// Pair, ConfirmBounds and Restore are the owner's: only the tier-4 local
// page (part b2) and the host's own state call them. No other call pins a
// device or turns one back on.
type Clerk struct {
	Key KeyHolder
	// Emit puts one event on the bus.
	Emit      func(Event) error
	Gap       time.Duration
	MaxEvents int
	Timeout   time.Duration
	Now       func() time.Time
	// Log takes one line per step: fixed phrases, the owner's device name,
	// the host and the accessory ID, never key material.
	Log func(string)

	mu       sync.Mutex
	devices  map[string]*device
	flows    map[flowKey]*flow
	winStart time.Time
	winN     int
	stats    Stats
}

// Format prints no field, whatever the verb.
func (c *Clerk) Format(f fmt.State, _ rune) { fmt.Fprint(f, "homekit.Clerk{}") }

func (c *Clerk) log(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

func (c *Clerk) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Clerk) gap() time.Duration {
	if c.Gap > 0 {
		return c.Gap
	}
	return DefaultGap
}

func (c *Clerk) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

// deadline bounds a pairing step on conn, when conn takes deadlines.
func (c *Clerk) deadline(conn io.ReadWriter) func() {
	d, ok := conn.(deadliner)
	if !ok {
		return func() {}
	}
	d.SetDeadline(time.Now().Add(c.timeout()))
	return func() { d.SetDeadline(time.Time{}) }
}

func closeConn(conn io.ReadWriter) {
	if cl, ok := conn.(io.Closer); ok {
		cl.Close()
	}
}

// Pair runs pair-setup with the HomeKit code the owner typed and pins the
// accessory as name, turning it on. It is the owner's step (DEV-10): the
// only call that pins or re-pins. A failure pins nothing and leaves any
// earlier pin as it was. It makes one attempt and closes conn.
func (c *Clerk) Pair(name string, conn io.ReadWriter, host, code string) error {
	defer closeConn(conn)
	if err := checkPairingID(name); err != nil {
		return fmt.Errorf("%w: device name", ErrRefused)
	}
	done := c.deadline(conn)
	pin, err := PairSetup(conn, host, code, c.Key, Options{Logf: c.log})
	done()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.devices == nil {
		c.devices = map[string]*device{}
	}
	d := c.devices[name]
	if d == nil {
		d = &device{bounds: map[string]Bounds{}}
		c.devices[name] = d
	}
	d.pin, d.off = pin, false
	c.log("homekit: owner paired %s", name)
	return nil
}

// Connect runs pair-verify for the paired device name over conn and returns
// its session; events go onto the bus. A device that is off is refused
// before a byte is written. An accessory that does not prove the pinned key
// pins nothing, turns the device off and logs one line (DEV-3, KRN-7).
func (c *Clerk) Connect(name string, conn io.ReadWriter, host string) (*Session, error) {
	c.mu.Lock()
	d := c.devices[name]
	var pin Pin
	var err error
	switch {
	case d == nil:
		err = ErrNotPaired
	case d.off:
		c.stats.Refused++
		err = ErrDeviceOff
	default:
		pin = d.pin
	}
	c.mu.Unlock()
	if err != nil {
		closeConn(conn)
		return nil, err
	}

	// Lines from pair-verify are held until its outcome is known, so a
	// mismatch logs exactly one line.
	var lmu sync.Mutex
	var held []string
	live := false
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		lmu.Lock()
		if !live {
			held = append(held, line)
			lmu.Unlock()
			return
		}
		lmu.Unlock()
		c.log("%s", line)
	}
	var sp atomic.Pointer[Session]
	opt := Options{Logf: logf, OnEvent: c.onEvent(name, &sp), Timeout: c.timeout()}
	done := c.deadline(conn)
	s, err := Verify(conn, host, pin, c.Key, opt)
	done()
	if errors.Is(err, ErrIdentity) {
		c.mu.Lock()
		if d := c.devices[name]; d != nil && d.pin.AccessoryID == pin.AccessoryID && d.pin.LTPK.Equal(pin.LTPK) {
			d.off = true
		}
		c.mu.Unlock()
		c.log("homekit: %s turned off: the accessory did not prove its pinned key; the owner pairs it again", name)
		return nil, err
	}
	lmu.Lock()
	lines := held
	held, live = nil, true
	lmu.Unlock()
	for _, l := range lines {
		c.log("%s", l)
	}
	if err != nil {
		return nil, err
	}
	sp.Store(s)
	return s, nil
}

// onEvent turns a session's event values into bus events. It runs after the
// session is released, so it may ask the session for the characteristic.
func (c *Clerk) onEvent(name string, sp *atomic.Pointer[Session]) func([]Value) {
	return func(vs []Value) {
		s := sp.Load()
		if s == nil {
			return
		}
		for _, v := range vs {
			if ch, ok := s.Characteristic(v.ID); ok {
				c.take(name, ch, v)
			}
		}
	}
}

// take offers one value: it goes out now if its characteristic's gap and the
// window allow, otherwise it is held as that characteristic's latest value
// for Flush. Text never leaves.
func (c *Clerk) take(name string, ch Characteristic, v Value) {
	switch v.V.(type) {
	case bool, float64:
	default:
		c.mu.Lock()
		c.stats.Text++
		c.mu.Unlock()
		return
	}
	e := &Event{Device: name, Label: Label, Unverified: true, ID: v.ID, Service: ch.Service, Type: ch.Type, Value: v.V}
	c.mu.Lock()
	if c.flows == nil {
		c.flows = map[flowKey]*flow{}
	}
	k := flowKey{name, v.ID}
	f := c.flows[k]
	if f == nil {
		f = &flow{}
		c.flows[k] = f
	}
	f.pending = e
	out := c.due()
	if f.pending == e {
		c.stats.Coalesced++
	}
	c.mu.Unlock()
	c.send(out)
}

// Flush puts out the held values whose gap has passed, as the window
// allows. The host calls it on a timer.
func (c *Clerk) Flush() {
	c.mu.Lock()
	out := c.due()
	c.mu.Unlock()
	c.send(out)
}

// due takes the held events that may go out now. Called with c.mu held.
func (c *Clerk) due() []Event {
	gap, now := c.gap(), c.now()
	limit := c.MaxEvents
	if limit <= 0 {
		limit = DefaultMaxEvents
	}
	if c.winStart.IsZero() || now.Sub(c.winStart) >= gap {
		c.winStart, c.winN = now, 0
	}
	keys := slices.SortedFunc(maps.Keys(c.flows), func(a, b flowKey) int {
		return cmp.Or(cmp.Compare(a.device, b.device), cmp.Compare(a.id.AID, b.id.AID), cmp.Compare(a.id.IID, b.id.IID))
	})
	var out []Event
	for _, k := range keys {
		f := c.flows[k]
		if f.pending == nil || !f.last.IsZero() && now.Sub(f.last) < gap {
			continue
		}
		if c.winN >= limit {
			break
		}
		e := *f.pending
		e.Time = now
		out = append(out, e)
		f.pending, f.last = nil, now
		c.winN++
	}
	return out
}

// send emits outside the lock. An event the bus refuses is held again for
// the next Flush, unless a newer value is already held.
func (c *Clerk) send(out []Event) {
	if c.Emit == nil {
		return
	}
	failed := 0
	for _, e := range out {
		if err := c.Emit(e); err != nil {
			failed++
			c.mu.Lock()
			c.stats.Failed++
			if f := c.flows[flowKey{e.Device, e.ID}]; f != nil && f.pending == nil {
				f.pending = &e
			}
			c.mu.Unlock()
		}
	}
	if failed > 0 {
		c.log("homekit: bus refused %d of %d events", failed, len(out))
	}
}

// takesBounds reports whether char takes owner bounds (DEV-4, DEV-5).
func takesBounds(char string) bool { return ClassFor(ServiceThermostat, char).InBounds != "" }

// ProposeBounds records bounds for a setpoint of the paired device, as
// unconfirmed: they admit no write as `actuate` until the owner confirms
// them. A new proposal unconfirms the old bounds.
func (c *Clerk) ProposeBounds(name, char string, lo, hi float64) error {
	if !takesBounds(char) {
		return fmt.Errorf("%w: %s takes no bounds", ErrRefused, char)
	}
	if math.IsNaN(lo) || math.IsNaN(hi) || math.IsInf(lo, 0) || math.IsInf(hi, 0) || lo > hi {
		return fmt.Errorf("%w: bounds not a finite range", ErrRefused)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.devices[name]
	if d == nil {
		return ErrNotPaired
	}
	d.bounds[char] = Bounds{Min: lo, Max: hi}
	return nil
}

// ConfirmBounds is the owner's confirmation of the proposed bounds, given
// as the owner saw them; other values confirm nothing.
func (c *Clerk) ConfirmBounds(name, char string, lo, hi float64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	d := c.devices[name]
	if d == nil {
		return ErrNotPaired
	}
	b, ok := d.bounds[char]
	if !ok || b.Min != lo || b.Max != hi {
		return fmt.Errorf("%w: these bounds were not proposed", ErrRefused)
	}
	b.Confirmed = true
	d.bounds[char] = b
	c.log("homekit: owner confirmed bounds for %s", name)
	return nil
}

// Bounds returns the device's bounds for char; unconfirmed or absent
// bounds admit no value.
func (c *Clerk) Bounds(name, char string) Bounds {
	c.mu.Lock()
	defer c.mu.Unlock()
	if d := c.devices[name]; d != nil {
		return d.bounds[char]
	}
	return Bounds{}
}

// WriteVerb is the class-table verb of writing v to the device's
// characteristic, under the owner's confirmed bounds (DEV-4, DEV-5).
func (c *Clerk) WriteVerb(name, service, char string, v float64) key.Verb {
	b := Bounds{}
	if service == ServiceThermostat {
		b = c.Bounds(name, char)
	}
	return ClassFor(service, char).WriteVerb(v, b)
}

// Stats is what the clerk has not put on the bus at once.
func (c *Clerk) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Snapshot is the pin store, by name, for the host to keep.
func (c *Clerk) Snapshot() []DeviceState {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]DeviceState, 0, len(c.devices))
	for _, n := range slices.Sorted(maps.Keys(c.devices)) {
		d := c.devices[n]
		out = append(out, DeviceState{Name: n, Off: d.off, Bounds: maps.Clone(d.bounds),
			Pin: Pin{AccessoryID: d.pin.AccessoryID, LTPK: append(ed25519.PublicKey(nil), d.pin.LTPK...)}})
	}
	return out
}

// Restore replaces the pin store with what Snapshot gave, as the host kept
// it. Every entry needs a name and a valid pin, or nothing changes.
func (c *Clerk) Restore(states []DeviceState) error {
	next := map[string]*device{}
	for _, s := range states {
		if checkPairingID(s.Name) != nil || !s.Pin.Valid() || next[s.Name] != nil {
			return fmt.Errorf("%w: device state", ErrRefused)
		}
		b := map[string]Bounds{}
		for char, v := range s.Bounds {
			if takesBounds(char) && v.Min <= v.Max {
				b[char] = v
			}
		}
		next[s.Name] = &device{pin: Pin{AccessoryID: s.Pin.AccessoryID, LTPK: append(ed25519.PublicKey(nil), s.Pin.LTPK...)},
			off: s.Off, bounds: b}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.devices = next
	return nil
}
