// Package devhost is the device-driver host library (DEVSLOT-drivers part
// b2a, D-189). The host runs outside every driver's address space, under its
// own uid with no key. For each operation it opens one connection to the
// driver's socket unit, so each operation runs in a fresh, sandboxed process
// (part b1's template), and it re-checks everything that process says
// against the image's copy of the declaration: the declaration itself, byte
// for byte; every frame's channel, prefix and length; the pin of every frame
// the device sends; and every reading. The slot's own checks inside the
// driver's process are a second layer, since a data race in driver code can
// corrupt them (DEVSLOT-a-7). The host owns the transport to the device and
// is the only emitter of device events, which it rate-limits and coalesces
// per source and reading kind (DEV-8). A subscription operation stays up and
// emits each reading as it arrives; the host subscribes again when each
// instance reaches its deadline (DEVSLOT-subscribe).
package devhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devslot"
)

// Event is one device event as the host emits it. A Coalesced event stands
// for that many readings of one kind from the source that arrived in one
// window past its limit; its Reading is the last of them (DEV-8).
type Event struct {
	devslot.Event
	Coalesced int
}

// Sink takes the host's events: the kernel's device-report entry (b3).
type Sink interface {
	Emit(Event) error
}

// Conn is one connection to a driver's socket unit.
type Conn interface {
	devslot.Conn
	io.Closer
}

// Dialer opens a new connection to the driver's socket unit, which starts a
// fresh instance of the driver for it (Accept=yes).
type Dialer interface {
	Dial(ctx context.Context) (Conn, error)
}

// Limit is a source's DEV-8 rate limit for each reading kind: Burst events
// per Window, and one coalesced, counted event for the rest. A kind has its
// own window, so a flood of one kind never hides another (a smoke reading
// in a flood of temperatures).
type Limit struct {
	Burst  int
	Window time.Duration
}

// Config is one driver for one pinned device.
type Config struct {
	// Decl is the declaration the image's drivers.json holds for the
	// driver (part b1), never the one the driver sends.
	Decl devslot.Declaration
	Pin  devslot.Pin
	// Home is the uplink's enclosing /56 (DEV-2).
	Home      netip.Prefix
	Dialer    Dialer
	Transport devslot.Transport
	Sink      Sink
	// Deadline bounds each operation, from dial to done. The unit's
	// RuntimeMaxSec kills the process past it (part b1).
	Deadline time.Duration
	// Subscription bounds each instance of a subscription operation, after
	// which the host subscribes again; it must be set when the declaration
	// has one, at least MinSubscription, and within the unit's RuntimeMaxSec
	// for subscriptions.
	Subscription time.Duration
	Limit        Limit
	// Now, if set, is the clock the limit reads.
	Now func() time.Time
	// Log, if set, gets the host's fixed messages, which name only the
	// declared device and operation.
	Log func(msg string)
}

// Errors an operation ends with. None carries text from the driver or the
// device.
var (
	ErrNotInImage = errors.New("devhost: driver's declaration is not the image's")
	ErrDeadline   = errors.New("devhost: operation past its deadline")
	ErrDial       = errors.New("devhost: driver did not start")
	// ErrSubscription is Do on a subscription, Subscribe on any other
	// operation, or a second subscription while one runs.
	ErrSubscription = errors.New("devhost: not a subscription here")
)

// MinSubscription is the shortest Config.Subscription New takes. Each
// instance writes up to its operation's MaxWrites, so this floor, not the
// host's config alone, bounds a subscription's write rate: at most MaxWrites
// per MinSubscription, plus one instance after each Do that preempts it
// (DEVSLOT-subscribe-1). A shorter instance is polling, which is Do's job.
const MinSubscription = 30 * time.Second

// minSubscription is the floor New checks; only this package's tests lower
// it (export_test.go), so no linking package can.
var minSubscription = MinSubscription

// errPreempted ends a subscription's instance when Do needs the driver.
var errPreempted = errors.New("devhost: subscription preempted")

// Host runs one driver's operations, one at a time. A subscription holds
// the driver between operations: Do ends its instance, runs, and the
// subscription resumes.
type Host struct {
	mu    sync.Mutex // held by the running operation or subscription instance
	cfg   Config
	decl  devslot.Declaration
	canon []byte

	smu     sync.Mutex
	scond   *sync.Cond
	pending int                     // calls to Do waiting for mu
	preempt context.CancelCauseFunc // ends the running subscription instance
	subbing bool

	lmu sync.Mutex
	win map[string]*window
}

// window is one reading kind's DEV-8 window.
type window struct {
	open    bool
	start   time.Time
	n       int
	dropped int
	last    devslot.Event
}

// New checks the image's declaration and the pin and returns the host.
func New(cfg Config) (*Host, error) {
	if err := devslot.Check(cfg.Decl, cfg.Pin, cfg.Home); err != nil {
		return nil, err
	}
	if cfg.Dialer == nil || cfg.Transport == nil || cfg.Sink == nil || cfg.Deadline <= 0 ||
		cfg.Limit.Burst < 1 || cfg.Limit.Window <= 0 {
		return nil, errors.New("devhost: config needs a dialer, a transport, a sink, a deadline and a limit")
	}
	canon, err := devslot.Canonical(cfg.Decl)
	if err != nil {
		return nil, err
	}
	// The declaration must fit one message with room for its fields.
	if len(canon) > devslot.MaxMsg*2/3 {
		return nil, devslot.ErrDeclaration
	}
	if cfg.Subscription < minSubscription && slices.ContainsFunc(cfg.Decl.Operations, func(o devslot.Operation) bool { return o.Subscribe }) {
		return nil, errors.New("devhost: config needs a subscription deadline of at least MinSubscription")
	}
	h := &Host{cfg: cfg, canon: canon, win: map[string]*window{}}
	h.scond = sync.NewCond(&h.smu)
	// The host's own copy, decoded from the canonical bytes, so a caller
	// that edits cfg.Decl later changes nothing.
	if err := json.Unmarshal(canon, &h.decl); err != nil {
		return nil, err
	}
	if h.cfg.Now == nil {
		h.cfg.Now = time.Now
	}
	return h, nil
}

func (h *Host) log(op string, err error) {
	if h.cfg.Log != nil {
		h.cfg.Log("devhost: " + h.decl.Device + " " + op + ": " + err.Error())
	}
}

// Do runs op in a fresh instance of the driver and emits its readings. It
// returns how many readings it took. A refusal fails the whole operation,
// closes its connection and emits nothing. A running subscription's
// instance is ended first, and resumes after.
func (h *Host) Do(ctx context.Context, op string) (int, error) {
	o, ok := h.decl.Op(op)
	if !ok {
		h.log("(undeclared)", devslot.ErrUnknownOp)
		return 0, devslot.ErrUnknownOp
	}
	if o.Subscribe {
		h.log(o.Name, ErrSubscription)
		return 0, ErrSubscription
	}
	h.smu.Lock()
	h.pending++
	if h.preempt != nil {
		h.preempt(errPreempted)
	}
	h.smu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.smu.Lock()
	h.pending--
	h.scond.Broadcast()
	h.smu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, h.cfg.Deadline)
	defer cancel()
	var rs []devslot.Reading
	err := h.instance(ctx, o, func(r devslot.Reading) error {
		if len(rs) >= h.decl.MaxReadings {
			return devslot.ErrReading
		}
		rs = append(rs, r)
		return nil
	})
	if err != nil {
		h.log(o.Name, err)
		return 0, err
	}
	for i, r := range rs {
		if err := h.emit(h.event(o, r)); err != nil {
			return i, err
		}
	}
	return len(rs), nil
}

// Subscribe runs subscription op until ctx ends. Each instance of the
// driver stays up for Config.Subscription and each reading it sends is
// checked and emitted at once, under the DEV-8 limit; when the instance
// reaches that deadline, or Do needs the driver, the host subscribes again
// with a fresh instance. Subscribe returns how many readings it emitted, and
// nil if the driver ended the subscription cleanly, ctx's error if ctx
// ended, or the error of an instance that ended any other way: a refusal, a
// failed dial or a failed done. A refusal stops the instance's later
// readings, not those already emitted. One subscription runs at a time.
func (h *Host) Subscribe(ctx context.Context, op string) (int, error) {
	o, ok := h.decl.Op(op)
	if !ok {
		h.log("(undeclared)", devslot.ErrUnknownOp)
		return 0, devslot.ErrUnknownOp
	}
	h.smu.Lock()
	if !o.Subscribe || h.subbing {
		h.smu.Unlock()
		h.log(o.Name, ErrSubscription)
		return 0, ErrSubscription
	}
	h.subbing = true
	h.smu.Unlock()
	defer func() {
		h.smu.Lock()
		h.subbing = false
		h.smu.Unlock()
	}()
	stop := context.AfterFunc(ctx, func() {
		h.smu.Lock()
		h.scond.Broadcast()
		h.smu.Unlock()
	})
	defer stop()
	n := 0
	for {
		ictx, cancel, ok := h.acquire(ctx)
		if !ok {
			return n, ctx.Err()
		}
		dctx, dcancel := context.WithTimeout(ictx, h.cfg.Subscription)
		err := h.instance(dctx, o, func(r devslot.Reading) error {
			if err := h.emit(h.event(o, r)); err != nil {
				return err
			}
			n++
			return nil
		})
		resume := errors.Is(dctx.Err(), context.DeadlineExceeded) || errors.Is(context.Cause(ictx), errPreempted)
		dcancel()
		h.release(cancel)
		switch {
		case ctx.Err() != nil:
			return n, ctx.Err()
		case err == nil:
			return n, nil
		case !resume:
			h.log(o.Name, err)
			return n, err
		}
	}
}

// acquire takes the driver for one subscription instance once no Do is
// waiting for it, and returns the instance's context, which Do cancels.
func (h *Host) acquire(ctx context.Context) (context.Context, context.CancelCauseFunc, bool) {
	for {
		h.smu.Lock()
		for h.pending > 0 && ctx.Err() == nil {
			h.scond.Wait()
		}
		h.smu.Unlock()
		if ctx.Err() != nil {
			return nil, nil, false
		}
		h.mu.Lock()
		h.smu.Lock()
		if h.pending == 0 {
			ictx, cancel := context.WithCancelCause(ctx)
			h.preempt = cancel
			h.smu.Unlock()
			return ictx, cancel, true
		}
		h.smu.Unlock()
		h.mu.Unlock()
	}
}

func (h *Host) release(cancel context.CancelCauseFunc) {
	h.smu.Lock()
	h.preempt = nil
	h.smu.Unlock()
	cancel(nil)
	h.mu.Unlock()
}

// instance runs one instance of op under ctx, whose deadline bounds it from
// dial to done, and passes each checked reading to take.
func (h *Host) instance(ctx context.Context, o devslot.Operation, take func(devslot.Reading) error) error {
	c, err := h.cfg.Dialer.Dial(ctx)
	if err != nil {
		return ErrDial
	}
	defer c.Close()
	// The deadline, or the caller's cancel, ends every read and write.
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	err = h.run(ctx, c, o, take)
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = ErrDeadline
	}
	return err
}

func (h *Host) event(o devslot.Operation, r devslot.Reading) devslot.Event {
	return devslot.Event{Device: h.decl.Device, Op: o.Name, Label: devslot.Label, Unverified: h.decl.Link != devslot.TCP, Reading: r}
}

// run carries one operation's messages, checking each.
func (h *Host) run(ctx context.Context, c Conn, o devslot.Operation, take func(devslot.Reading) error) error {
	m, err := devslot.ReadMsg(c)
	if err != nil {
		return devslot.ErrWire
	}
	if m.T != devslot.MsgDeclare || !bytes.Equal(m.B, h.canon) {
		return ErrNotInImage
	}
	if err := devslot.WriteMsg(c, devslot.PinMsg(o.Name, h.cfg.Pin, h.cfg.Home)); err != nil {
		return devslot.ErrWire
	}
	// writes counts the frames sent to the device; one run of o sends at
	// most o.MaxWrites, so one approval covers no more (#3506).
	writes := 0
	for {
		m, err := devslot.ReadMsg(c)
		if err != nil {
			return devslot.ErrWire
		}
		var reply devslot.Msg
		switch m.T {
		case devslot.MsgWrite:
			ch, ok := h.decl.Chan(m.Ch)
			if !ok || !h.decl.Writes(o.Name, m.Ch, m.B) {
				return devslot.ErrUndeclared
			}
			if writes >= o.MaxWrites {
				return devslot.ErrWrites
			}
			writes++
			reply = devslot.Msg{T: devslot.MsgAck}
			if err := h.cfg.Transport.Write(ctx, devslot.Target{Pin: h.cfg.Pin, Channel: ch}, slices.Clone(m.B)); err != nil {
				reply.Err = devslot.Failed
			}
		case devslot.MsgRead:
			reply = devslot.Msg{T: devslot.MsgFrame}
			t, f, err := h.cfg.Transport.Read(ctx)
			if err != nil {
				reply.Err = devslot.Failed
				break
			}
			ch, ok := h.decl.Chan(t.Channel.Name)
			if !ok || t.Pin != h.cfg.Pin || t.Channel != ch {
				return devslot.ErrUnpinned
			}
			if len(f) > h.decl.MaxRead {
				return devslot.ErrTooLarge
			}
			reply.Ch, reply.B = ch.Name, f
		case devslot.MsgReading:
			r, ok := h.reading(m)
			if !ok {
				return devslot.ErrReading
			}
			if err := take(r); err != nil {
				return err
			}
			continue
		case devslot.MsgDone:
			if m.Err != "" {
				return devslot.ErrDriver
			}
			return nil
		default:
			return devslot.ErrWire
		}
		if err := devslot.WriteMsg(c, reply); err != nil {
			return devslot.ErrWire
		}
	}
}

// maxTime is the longest canonical RFC 3339 UTC time with nanoseconds.
const maxTime = len("2006-01-02T15:04:05.999999999Z")

// reading is m as a reading, if it is one the image's declaration allows:
// a declared kind, an exponent in [-18, 18], and a time in canonical RFC
// 3339 form in UTC, so no zone name or offset (free text) reaches an event.
func (h *Host) reading(m devslot.Msg) (devslot.Reading, bool) {
	if !slices.Contains(h.decl.Readings, m.Kind) || m.Exp < -18 || m.Exp > 18 || len(m.Time) > maxTime {
		return devslot.Reading{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, m.Time)
	if err != nil || t.Location() != time.UTC || t.Format(time.RFC3339Nano) != m.Time {
		return devslot.Reading{}, false
	}
	return devslot.Reading{Kind: m.Kind, Value: m.Value, Exp: int8(m.Exp), Time: t}, true
}

// emit passes e under its kind's limit: the first Burst events of a window
// go to the sink, the rest are counted, and the count goes out as one
// coalesced event once the window has ended (DEV-8).
func (h *Host) emit(e devslot.Event) error {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	now := h.cfg.Now()
	if err := h.flush(now); err != nil {
		return err
	}
	// Kinds are the declaration's, so there are at most CapKinds windows.
	w := h.win[e.Reading.Kind]
	if w == nil {
		w = &window{}
		h.win[e.Reading.Kind] = w
	}
	if !w.open {
		w.open, w.start, w.n = true, now, 0
	}
	if w.n < h.cfg.Limit.Burst {
		w.n++
		return h.cfg.Sink.Emit(Event{Event: e})
	}
	w.dropped++
	w.last = e
	return nil
}

// Flush emits the coalesced events of windows that have ended. The host's
// process calls it on a timer, so a flood's count goes out even if the
// source then falls silent.
func (h *Host) Flush() error {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	return h.flush(h.cfg.Now())
}

// flush ends each kind's window that has run its length, in the
// declaration's order of kinds.
func (h *Host) flush(now time.Time) error {
	for _, k := range h.decl.Readings {
		w := h.win[k]
		if w == nil || !w.open || now.Sub(w.start) < h.cfg.Limit.Window {
			continue
		}
		w.open = false
		if w.dropped == 0 {
			continue
		}
		ev := Event{Event: w.last, Coalesced: w.dropped}
		w.dropped, w.last = 0, devslot.Event{}
		if err := h.cfg.Sink.Emit(ev); err != nil {
			return err
		}
	}
	return nil
}
