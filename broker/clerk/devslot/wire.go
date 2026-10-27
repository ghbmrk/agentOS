package devslot

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// The wire between the host (broker/clerk/devhost) and a driver's process
// carries one operation over one connection. The driver speaks first:
//
//	driver: declare {B: Canonical(declaration)}
//	host:   op {Op, Addr | Host + Key, Home}
//	driver: write {Ch, B}   host: ack {Err}
//	driver: read            host: frame {Ch, B, Err}
//	driver: reading {Kind, Value, Exp, Time}
//	driver: done {Err}
//
// Every message is a 4-byte big-endian length and that many bytes of JSON.
// The host re-checks each message against its own copy of the declaration,
// so nothing the driver's process says is trusted (DEVSLOT-host-lib-4).

// Message types.
const (
	MsgDeclare = "declare"
	MsgOp      = "op"
	MsgWrite   = "write"
	MsgAck     = "ack"
	MsgRead    = "read"
	MsgFrame   = "frame"
	MsgReading = "reading"
	MsgDone    = "done"
)

// Failed is the one error text the wire carries: a write or read the
// transport could not complete, or an operation that failed. No text from
// the driver or the device crosses the wire.
const Failed = "failed"

// MaxMsg bounds one message: a frame of CapRead bytes in base64 and the
// fields around it.
const MaxMsg = 1 << 17

// Msg is one message on the wire.
type Msg struct {
	T     string `json:"t"`
	Op    string `json:"op,omitempty"`
	Ch    string `json:"ch,omitempty"`
	B     []byte `json:"b,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Value int64  `json:"value,omitempty"`
	Exp   int    `json:"exp,omitempty"`
	Time  string `json:"time,omitempty"`
	Err   string `json:"err,omitempty"`
	// The op message's pin: a GATT address, or a TCP host and its key's
	// SHA-256 in hex, and the uplink's /56 (DEV-2).
	Addr string `json:"addr,omitempty"`
	Host string `json:"host,omitempty"`
	Key  string `json:"key,omitempty"`
	Home string `json:"home,omitempty"`
}

// ErrWire is a message the wire refuses: too long, empty, not one JSON
// object of Msg's fields, or not the message expected next.
var ErrWire = errors.New("devslot: wire message refused")

// WriteMsg writes m to w.
func WriteMsg(w io.Writer, m Msg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMsg {
		return ErrWire
	}
	buf := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(b)), uint32(len(b)))
	_, err = w.Write(append(buf, b...))
	return err
}

// ReadMsg reads one message from r. It reads at most 4+MaxMsg bytes and
// allocates no more than the length it checked.
func ReadMsg(r io.Reader) (Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Msg{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > MaxMsg {
		return Msg{}, ErrWire
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return Msg{}, err
	}
	return DecodeMsg(b)
}

// DecodeMsg decodes one message body: exactly one JSON object with only
// Msg's fields.
func DecodeMsg(b []byte) (Msg, error) {
	var m Msg
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || dec.More() || m.T == "" {
		return Msg{}, ErrWire
	}
	if _, err := dec.Token(); err != io.EOF {
		return Msg{}, ErrWire
	}
	return m, nil
}

// Canonical is a declaration's canonical form, the bytes the image's
// drivers.json holds and the host compares byte for byte with what the
// driver's process sends at start: its JSON, with every empty list and
// prefix as null, so an empty and a missing one read the same.
func Canonical(d Declaration) ([]byte, error) {
	d = cloneDecl(d)
	d.Channels = nilIfEmpty(d.Channels)
	d.Shapes = nilIfEmpty(d.Shapes)
	for i := range d.Shapes {
		d.Shapes[i].Prefix = nilIfEmpty(d.Shapes[i].Prefix)
	}
	d.Operations = nilIfEmpty(d.Operations)
	for i := range d.Operations {
		d.Operations[i].Shapes = nilIfEmpty(d.Operations[i].Shapes)
	}
	d.Readings = nilIfEmpty(d.Readings)
	return json.Marshal(d)
}

func nilIfEmpty[S ~[]E, E any](s S) S {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Op is the declared operation named op.
func (d Declaration) Op(op string) (Operation, bool) {
	i := slices.IndexFunc(d.Operations, func(o Operation) bool { return o.Name == op })
	if i < 0 {
		return Operation{}, false
	}
	return d.Operations[i], true
}

// Chan is the declared channel named ch.
func (d Declaration) Chan(ch string) (Channel, bool) {
	i := slices.IndexFunc(d.Channels, func(c Channel) bool { return c.Name == ch })
	if i < 0 {
		return Channel{}, false
	}
	return d.Channels[i], true
}

// Writes is whether op may write frame on ch: one of its declared shapes.
func (d Declaration) Writes(op, ch string, frame []byte) bool {
	o, ok := d.Op(op)
	return ok && d.match(o, ch, frame)
}

// PinMsg is the op message for op, pin p and the uplink's /56 home.
func PinMsg(op string, p Pin, home netip.Prefix) Msg {
	m := Msg{T: MsgOp, Op: op, Addr: p.Address}
	if p.Host.IsValid() {
		m.Host, m.Key = p.Host.String(), hex.EncodeToString(p.Key[:])
	}
	if home.IsValid() {
		m.Home = home.String()
	}
	return m
}

// pinOf is the pin and home an op message names.
func pinOf(m Msg) (Pin, netip.Prefix, error) {
	p := Pin{Address: m.Addr}
	var home netip.Prefix
	if m.Host != "" {
		a, err := netip.ParseAddr(m.Host)
		k, kerr := hex.DecodeString(m.Key)
		if err != nil || kerr != nil || len(k) != len(p.Key) {
			return Pin{}, home, ErrWire
		}
		p.Host = a
		copy(p.Key[:], k)
	}
	if m.Home != "" {
		h, err := netip.ParsePrefix(m.Home)
		if err != nil {
			return Pin{}, home, ErrWire
		}
		home = h
	}
	return p, home, nil
}

// Conn is one connection on the wire: the descriptor the driver's process
// got from its socket unit, or the host's end of it.
type Conn interface {
	io.ReadWriter
	SetDeadline(time.Time) error
}

// ServeWire runs one operation of drv for the host on c: it declares, takes
// the operation and the pin, runs it through the slot, and reports done.
// Main calls it after its checks; tests call it on a pipe.
func ServeWire(ctx context.Context, drv Driver, c Conn) error {
	d := cloneDecl(drv.Declare())
	b, err := Canonical(d)
	if err != nil {
		return err
	}
	if err := WriteMsg(c, Msg{T: MsgDeclare, B: b}); err != nil {
		return err
	}
	m, err := ReadMsg(c)
	if err != nil {
		return err
	}
	if m.T != MsgOp {
		return ErrWire
	}
	pin, home, err := pinOf(m)
	if err != nil {
		return err
	}
	w := &wire{c: c, d: d, pin: pin}
	s, err := New(declared{drv, d}, Env{Pin: pin, Home: home, Transport: w, Emit: w.emit})
	if err != nil {
		return err
	}
	_, opErr := s.Do(ctx, m.Op)
	done := Msg{T: MsgDone}
	if opErr != nil {
		done.Err = Failed
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	// A call the slot interrupted at the operation's end set a deadline.
	c.SetDeadline(time.Time{})
	if err := WriteMsg(c, done); err != nil {
		return err
	}
	return opErr
}

// declared is drv with the declaration it gave first, so a driver whose
// Declare answers differently the second time changes nothing the host
// compared.
type declared struct {
	Driver
	d Declaration
}

func (x declared) Declare() Declaration { return cloneDecl(x.d) }

// wire is the slot's Transport and Emit in the driver's process: each
// call is one round trip to the host, one at a time. A call its context
// interrupted leaves the wire out of step, so every later call fails.
type wire struct {
	mu     sync.Mutex
	c      Conn
	d      Declaration
	pin    Pin
	broken bool
}

// call sends m and, if reply is set, reads the reply, under ctx.
func (w *wire) call(ctx context.Context, m Msg, reply string) (Msg, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.broken {
		return Msg{}, ErrWire
	}
	stop := context.AfterFunc(ctx, func() { w.c.SetDeadline(time.Now()) })
	defer func() {
		if !stop() {
			w.broken = true
		}
	}()
	if err := WriteMsg(w.c, m); err != nil {
		w.broken = true
		return Msg{}, err
	}
	if reply == "" {
		return Msg{}, nil
	}
	r, err := ReadMsg(w.c)
	if err != nil || r.T != reply {
		w.broken = true
		return Msg{}, ErrWire
	}
	return r, nil
}

func (w *wire) Write(ctx context.Context, t Target, frame []byte) error {
	r, err := w.call(ctx, Msg{T: MsgWrite, Ch: t.Channel.Name, B: frame}, MsgAck)
	if err != nil {
		return err
	}
	if r.Err != "" {
		return ErrDriver
	}
	return nil
}

func (w *wire) Read(ctx context.Context) (Target, []byte, error) {
	r, err := w.call(ctx, Msg{T: MsgRead}, MsgFrame)
	if err != nil {
		return Target{}, nil, err
	}
	if r.Err != "" {
		return Target{}, nil, ErrDriver
	}
	c, ok := w.d.Chan(r.Ch)
	if !ok {
		return Target{}, nil, ErrUnpinned
	}
	return Target{Pin: w.pin, Channel: c}, r.B, nil
}

func (w *wire) emit(e Event) error {
	r := e.Reading
	_, err := w.call(context.Background(), Msg{T: MsgReading, Kind: r.Kind, Value: r.Value, Exp: int(r.Exp),
		Time: r.Time.UTC().Format(time.RFC3339Nano)}, "")
	return err
}
