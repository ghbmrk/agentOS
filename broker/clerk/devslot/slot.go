package devslot

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// Driver is one vendor's protocol code. Declare is called once, before
// anything runs; Run performs one declared operation over link and returns
// its readings. A driver reaches nothing but its arguments.
type Driver interface {
	Declare() Declaration
	Run(ctx context.Context, op string, link Link, sec Secrets) ([]Reading, error)
}

// Link is the driver's only reach: its pinned device's declared channels.
// Write sends a frame only if it is one of the running operation's shapes;
// Read returns the next frame from the pinned device and the channel it came
// on.
type Link interface {
	Write(ctx context.Context, ch string, frame []byte) error
	Read(ctx context.Context) (ch string, frame []byte, err error)
}

// Target is where a frame goes or came from, as the host's transport sees
// it: the pin and a declared channel.
type Target struct {
	Pin     Pin
	Channel Channel
}

// Transport is the host's raw link to the device (part b): the enforcer's
// GATT relay, or a TCP stream whose key it checked against the pin. Its calls
// return once ctx ends, which is how the slot ends a call still in flight
// when an operation finishes.
type Transport interface {
	Write(ctx context.Context, t Target, frame []byte) error
	Read(ctx context.Context) (Target, []byte, error)
}

// Reading is one value the driver reports: a declared kind, a decimal
// (Value × 10^Exp) and when the device took it. It carries no device text:
// the slot emits Time in UTC, whatever zone the driver gave it.
type Reading struct {
	Kind  string
	Value int64
	Exp   int8
	Time  time.Time
}

// Label is every event's data-flow label (PLN-3).
const Label = "private"

// Event is one reading as it goes onto the bus (DEV-8): private, and
// unverified unless the device was pinned by a key (DEV-3).
type Event struct {
	Device     string
	Op         string
	Label      string
	Unverified bool
	Reading    Reading
}

// Env is what the host gives the slot. The driver sees none of it.
type Env struct {
	Pin Pin
	// Home is the uplink's enclosing /56, inside which a global IPv6 pin is
	// on the home network (DEV-2); unset, no global address is.
	Home      netip.Prefix
	Transport Transport
	// Lend is clerk.Secrets.DeviceKey for the device/ slot pinned at pairing
	// (D-184), or nil for a device with no key.
	Lend func(fn func(key []byte) error) error
	// Emit puts one event on the bus.
	Emit func(Event) error
	// Log, if set, gets the slot's fixed messages; nothing from the driver.
	Log func(msg string)
}

// Secrets is the driver's custody handle: Open lends its one device key for
// one call (CLK-1). It names no slot, so it opens no other, and it works only
// while its operation runs.
type Secrets struct{ l *link }

// ErrNoKey is a device with no key.
var ErrNoKey = errors.New("devslot: device has no key")

// ErrClosed is a link or key handle used after its operation ended.
var ErrClosed = errors.New("devslot: operation ended, handle closed")

// Open lends the key to fn and wipes it after fn returns.
func (s Secrets) Open(fn func(key []byte) error) error {
	if s.l == nil || s.l.env.Lend == nil {
		return ErrNoKey
	}
	if err := s.l.enter(); err != nil {
		return err
	}
	defer s.l.inflight.Done()
	return s.l.env.Lend(fn)
}

// Format prints no field, whatever the verb.
func (Secrets) Format(f fmt.State, _ rune) { fmt.Fprint(f, "devslot.Secrets{key: sealed}") }

// Errors an operation ends with. None carries text from the driver or the
// device, so a key the driver mishandles cannot leave through one.
var (
	ErrUnknownOp  = errors.New("devslot: undeclared operation")
	ErrUndeclared = errors.New("devslot: frame is not a declared shape, not sent")
	ErrUnpinned   = errors.New("devslot: frame not from the pinned device's declared channel")
	ErrTooLarge   = errors.New("devslot: frame larger than declared")
	ErrReading    = errors.New("devslot: reading refused")
	ErrDriver     = errors.New("devslot: driver failed")
	ErrPanic      = errors.New("devslot: driver panicked")
)

// Slot runs one checked driver for one pinned device, one operation at a
// time.
type Slot struct {
	mu  sync.Mutex
	drv Driver
	d   Declaration
	env Env
}

// New checks the driver's declaration against the pin and returns its slot.
// A refused declaration never reaches Run.
func New(drv Driver, env Env) (*Slot, error) {
	d := drv.Declare()
	if err := Check(d, env.Pin, env.Home); err != nil {
		return nil, err
	}
	if env.Transport == nil || env.Emit == nil {
		return nil, errors.New("devslot: host gave no transport or bus")
	}
	return &Slot{drv: drv, d: cloneDecl(d), env: env}, nil
}

// cloneDecl copies d, so a driver that keeps and edits its declaration
// changes nothing the slot checked.
func cloneDecl(d Declaration) Declaration {
	d.Channels = slices.Clone(d.Channels)
	d.Shapes = slices.Clone(d.Shapes)
	for i := range d.Shapes {
		d.Shapes[i].Prefix = slices.Clone(d.Shapes[i].Prefix)
	}
	d.Operations = slices.Clone(d.Operations)
	for i := range d.Operations {
		d.Operations[i].Shapes = slices.Clone(d.Operations[i].Shapes)
	}
	d.Readings = slices.Clone(d.Readings)
	return d
}

// Declaration is the checked declaration.
func (s *Slot) Declaration() Declaration { return cloneDecl(s.d) }

func (s *Slot) log(msg string) {
	if s.env.Log != nil {
		s.env.Log(msg)
	}
}

// Do runs op and puts its readings on the bus. It returns how many it put.
// Readings are all checked before any is emitted, so a refused one emits
// none.
func (s *Slot) Do(ctx context.Context, op string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	i := slices.IndexFunc(s.d.Operations, func(o Operation) bool { return o.Name == op })
	if i < 0 {
		s.log("devslot: " + s.d.Device + ": undeclared operation refused")
		return 0, ErrUnknownOp
	}
	o := s.d.Operations[i]
	runCtx, cancel := context.WithCancel(ctx)
	l := &link{d: &s.d, op: o, env: &s.env, run: runCtx}
	rs, err := s.run(ctx, o.Name, l)
	refused := l.close(cancel)
	if refused != nil {
		s.log("devslot: " + s.d.Device + " " + o.Name + ": " + refused.Error())
		return 0, refused
	}
	if err != nil {
		s.log("devslot: " + s.d.Device + " " + o.Name + ": " + err.Error())
		return 0, err
	}
	if err := s.checkReadings(rs); err != nil {
		s.log("devslot: " + s.d.Device + " " + o.Name + ": readings refused")
		return 0, err
	}
	unverified := s.d.Link != TCP
	for n, r := range rs {
		// UTC drops the driver's *time.Location, whose name is free text.
		r.Time = r.Time.UTC().Round(0)
		ev := Event{Device: s.d.Device, Op: o.Name, Label: Label, Unverified: unverified, Reading: r}
		if err := s.env.Emit(ev); err != nil {
			return n, err
		}
	}
	return len(rs), nil
}

// run calls the driver, turning a panic or an error into a fixed error.
func (s *Slot) run(ctx context.Context, op string, l *link) (rs []Reading, err error) {
	defer func() {
		if recover() != nil {
			rs, err = nil, ErrPanic
		}
	}()
	rs, err = s.drv.Run(ctx, op, l, Secrets{l})
	if err != nil {
		return nil, ErrDriver
	}
	return slices.Clone(rs), nil
}

func (s *Slot) checkReadings(rs []Reading) error {
	if len(rs) > s.d.MaxReadings {
		return ErrReading
	}
	for _, r := range rs {
		if !slices.Contains(s.d.Readings, r.Kind) || r.Exp < -18 || r.Exp > 18 {
			return ErrReading
		}
	}
	return nil
}

// link is the driver's Link and key handle for one operation. When Run
// returns, close revokes it: a driver that kept it, or a goroutine it left,
// gets ErrClosed, so it can neither replay the operation's shapes with no
// operation running nor open the key again (CLK-1, DEV-4).
type link struct {
	d   *Declaration
	op  Operation
	env *Env
	// run ends when the operation does; every transport call runs under it.
	run      context.Context
	inflight sync.WaitGroup
	mu       sync.Mutex
	done     bool
	refused  error // the first refusal; the operation then fails with it
}

// enter admits one call while the operation runs.
func (l *link) enter() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return ErrClosed
	}
	if l.refused != nil {
		return l.refused
	}
	l.inflight.Add(1)
	return nil
}

// close revokes the link, ends calls still in flight through cancel, waits
// for them, and returns the first refusal.
func (l *link) close(cancel context.CancelFunc) error {
	l.mu.Lock()
	l.done = true
	l.mu.Unlock()
	cancel()
	l.inflight.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refused
}

func (l *link) refuse(err error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.refused == nil {
		l.refused = err
	}
	return err
}

func (l *link) channel(name string) (Channel, bool) {
	i := slices.IndexFunc(l.d.Channels, func(c Channel) bool { return c.Name == name })
	if i < 0 {
		return Channel{}, false
	}
	return l.d.Channels[i], true
}

// ctx is the driver's ctx, also ended when the operation ends.
func (l *link) ctx(ctx context.Context) (context.Context, func()) {
	c, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.run, cancel)
	return c, func() { stop(); cancel() }
}

func (l *link) Write(ctx context.Context, ch string, frame []byte) error {
	if err := l.enter(); err != nil {
		return err
	}
	defer l.inflight.Done()
	c, ok := l.channel(ch)
	if !ok || !l.d.match(l.op, ch, frame) {
		return l.refuse(ErrUndeclared)
	}
	ctx, end := l.ctx(ctx)
	defer end()
	if err := l.env.Transport.Write(ctx, Target{l.env.Pin, c}, slices.Clone(frame)); err != nil {
		return ErrDriver
	}
	return nil
}

func (l *link) Read(ctx context.Context) (string, []byte, error) {
	if err := l.enter(); err != nil {
		return "", nil, err
	}
	defer l.inflight.Done()
	ctx, end := l.ctx(ctx)
	defer end()
	t, frame, err := l.env.Transport.Read(ctx)
	if err != nil {
		return "", nil, err
	}
	c, ok := l.channel(t.Channel.Name)
	if !ok || t.Pin != l.env.Pin || t.Channel != c {
		return "", nil, l.refuse(ErrUnpinned)
	}
	if len(frame) > l.d.MaxRead {
		return "", nil, l.refuse(ErrTooLarge)
	}
	return c.Name, slices.Clone(frame), nil
}

// Serve runs drv for its host: it checks the declaration, then runs each
// operation from ops until ops closes or ctx ends. An operation that fails
// is logged and the next one runs; a refused declaration ends Serve before
// the driver runs. Part b's process main wires Env and ops to the host.
func Serve(ctx context.Context, drv Driver, env Env, ops <-chan string) error {
	s, err := New(drv, env)
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case op, ok := <-ops:
			if !ok {
				return nil
			}
			s.Do(ctx, op)
		}
	}
}
