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
// per source (DEV-8).
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
// for that many readings from the source that arrived in one window past
// its limit; its Reading is the last of them (DEV-8).
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

// Limit is a source's DEV-8 rate limit: Burst events per Window, and one
// coalesced, counted event for the rest.
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
	Limit    Limit
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
)

// Host runs one driver's operations, one at a time.
type Host struct {
	mu    sync.Mutex
	cfg   Config
	decl  devslot.Declaration
	canon []byte

	lmu     sync.Mutex
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
	h := &Host{cfg: cfg, canon: canon}
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
// closes its connection and emits nothing.
func (h *Host) Do(ctx context.Context, op string) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	o, ok := h.decl.Op(op)
	if !ok {
		h.log("(undeclared)", devslot.ErrUnknownOp)
		return 0, devslot.ErrUnknownOp
	}
	ctx, cancel := context.WithTimeout(ctx, h.cfg.Deadline)
	defer cancel()
	c, err := h.cfg.Dialer.Dial(ctx)
	if err != nil {
		h.log(o.Name, ErrDial)
		return 0, ErrDial
	}
	defer c.Close()
	// The deadline, or the caller's cancel, ends every read and write.
	stop := context.AfterFunc(ctx, func() { c.SetDeadline(time.Now()) })
	defer stop()
	rs, err := h.run(ctx, c, o)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = ErrDeadline
		}
		h.log(o.Name, err)
		return 0, err
	}
	unverified := h.decl.Link != devslot.TCP
	for i, r := range rs {
		ev := devslot.Event{Device: h.decl.Device, Op: o.Name, Label: devslot.Label, Unverified: unverified, Reading: r}
		if err := h.emit(ev); err != nil {
			return i, err
		}
	}
	return len(rs), nil
}

// run carries one operation's messages, checking each.
func (h *Host) run(ctx context.Context, c Conn, o devslot.Operation) ([]devslot.Reading, error) {
	m, err := devslot.ReadMsg(c)
	if err != nil {
		return nil, devslot.ErrWire
	}
	if m.T != devslot.MsgDeclare || !bytes.Equal(m.B, h.canon) {
		return nil, ErrNotInImage
	}
	if err := devslot.WriteMsg(c, devslot.PinMsg(o.Name, h.cfg.Pin, h.cfg.Home)); err != nil {
		return nil, devslot.ErrWire
	}
	var rs []devslot.Reading
	for {
		m, err := devslot.ReadMsg(c)
		if err != nil {
			return nil, devslot.ErrWire
		}
		var reply devslot.Msg
		switch m.T {
		case devslot.MsgWrite:
			ch, ok := h.decl.Chan(m.Ch)
			if !ok || !h.decl.Writes(o.Name, m.Ch, m.B) {
				return nil, devslot.ErrUndeclared
			}
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
				return nil, devslot.ErrUnpinned
			}
			if len(f) > h.decl.MaxRead {
				return nil, devslot.ErrTooLarge
			}
			reply.Ch, reply.B = ch.Name, f
		case devslot.MsgReading:
			r, ok := h.reading(m)
			if !ok || len(rs) >= h.decl.MaxReadings {
				return nil, devslot.ErrReading
			}
			rs = append(rs, r)
			continue
		case devslot.MsgDone:
			if m.Err != "" {
				return nil, devslot.ErrDriver
			}
			return rs, nil
		default:
			return nil, devslot.ErrWire
		}
		if err := devslot.WriteMsg(c, reply); err != nil {
			return nil, devslot.ErrWire
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

// emit passes e under the source's limit: the first Burst events of a
// window go to the sink, the rest are counted, and the count goes out as
// one coalesced event once the window has ended (DEV-8).
func (h *Host) emit(e devslot.Event) error {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	now := h.cfg.Now()
	if err := h.flush(now); err != nil {
		return err
	}
	if !h.open {
		h.open, h.start, h.n = true, now, 0
	}
	if h.n < h.cfg.Limit.Burst {
		h.n++
		return h.cfg.Sink.Emit(Event{Event: e})
	}
	h.dropped++
	h.last = e
	return nil
}

// Flush emits the coalesced event of a window that has ended. The host's
// process calls it on a timer, so a flood's count goes out even if the
// source then falls silent.
func (h *Host) Flush() error {
	h.lmu.Lock()
	defer h.lmu.Unlock()
	return h.flush(h.cfg.Now())
}

func (h *Host) flush(now time.Time) error {
	if !h.open || now.Sub(h.start) < h.cfg.Limit.Window {
		return nil
	}
	h.open = false
	if h.dropped == 0 {
		return nil
	}
	ev := Event{Event: h.last, Coalesced: h.dropped}
	h.dropped, h.last = 0, devslot.Event{}
	return h.cfg.Sink.Emit(ev)
}
