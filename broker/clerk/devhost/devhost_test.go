package devhost_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
)

// REQ: DEV-1, DEV-2, DEV-3, DEV-4, DEV-8, CLK-1

var pin = devslot.Pin{Address: "02:00:00:00:00:01"}

// script is a fake driver's process: it speaks the wire directly on its end
// of the connection, bypassing its slot.
type script func(t *testing.T, c net.Conn)

// dialer starts each dial's script on a fresh pipe and records every
// connection, so a test sees how many ran and whether each was closed.
// It also records when each dial came and the deadline its context
// carried, which the host set before dialing.
type dialer struct {
	t         *testing.T
	scripts   []script
	mu        sync.Mutex
	dials     int
	at        []time.Time
	deadlines []time.Time
	done      sync.WaitGroup
}

func (d *dialer) Dial(ctx context.Context) (devhost.Conn, error) {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dials >= len(d.scripts) {
		return nil, errors.New("no driver")
	}
	s := d.scripts[d.dials]
	d.dials++
	dl, _ := ctx.Deadline()
	d.at = append(d.at, now)
	d.deadlines = append(d.deadlines, dl)
	host, drv := net.Pipe()
	d.done.Add(1)
	go func() {
		defer d.done.Done()
		defer drv.Close()
		s(d.t, drv)
	}()
	return host, nil
}

// transport is the device: it answers reads from a queue and records writes.
type transport struct {
	mu     sync.Mutex
	writes [][]byte
	reads  []devslot.Target
	frames [][]byte
}

func (tr *transport) Write(_ context.Context, _ devslot.Target, f []byte) error {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.writes = append(tr.writes, f)
	return nil
}

func (tr *transport) Read(ctx context.Context) (devslot.Target, []byte, error) {
	tr.mu.Lock()
	if len(tr.frames) == 0 {
		tr.mu.Unlock()
		<-ctx.Done()
		return devslot.Target{}, nil, ctx.Err()
	}
	t, f := tr.reads[0], tr.frames[0]
	tr.reads, tr.frames = tr.reads[1:], tr.frames[1:]
	tr.mu.Unlock()
	return t, f, nil
}

func (tr *transport) queue(ch string, f []byte) {
	c, _ := fixture.Declaration().Chan(ch)
	tr.reads = append(tr.reads, devslot.Target{Pin: pin, Channel: c})
	tr.frames = append(tr.frames, f)
}

type sink struct {
	mu     sync.Mutex
	events []devhost.Event
}

func (s *sink) Emit(e devhost.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

type rig struct {
	h  *devhost.Host
	d  *dialer
	tr *transport
	s  *sink
}

func newRig(t *testing.T, scripts ...script) *rig {
	t.Helper()
	r := &rig{d: &dialer{t: t, scripts: scripts}, tr: &transport{}, s: &sink{}}
	h, err := devhost.New(devhost.Config{
		Decl: fixture.Declaration(), Pin: pin, Dialer: r.d, Transport: r.tr, Sink: r.s,
		Deadline: 5 * time.Second, Limit: devhost.Limit{Burst: 100, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.h = h
	t.Cleanup(r.d.done.Wait)
	return r
}

func send(t *testing.T, c net.Conn, m devslot.Msg) bool {
	t.Helper()
	return devslot.WriteMsg(c, m) == nil
}

func recv(t *testing.T, c net.Conn) (devslot.Msg, error) {
	t.Helper()
	return devslot.ReadMsg(c)
}

// declare sends the image's declaration and takes the op message.
func declare(t *testing.T, c net.Conn) (devslot.Msg, bool) {
	t.Helper()
	b, _ := devslot.Canonical(fixture.Declaration())
	if !send(t, c, devslot.Msg{T: devslot.MsgDeclare, B: b}) {
		return devslot.Msg{}, false
	}
	m, err := recv(t, c)
	if err != nil || m.T != devslot.MsgOp {
		t.Errorf("host's reply to the declaration: %+v, %v", m, err)
		return m, false
	}
	return m, true
}

// closed reports whether the host closed c.
func closed(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := devslot.ReadMsg(c)
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func reading(kind string, exp int, ts string) devslot.Msg {
	return devslot.Msg{T: devslot.MsgReading, Kind: kind, Value: 2150, Exp: exp, Time: ts}
}

const okTime = "2026-10-27T10:00:00Z"

// good is a well-behaved driver: it writes the get frame, reads the reply,
// and reports one reading.
func good(t *testing.T, c net.Conn) {
	if _, ok := declare(t, c); !ok {
		return
	}
	send(t, c, devslot.Msg{T: devslot.MsgWrite, Ch: "control", B: []byte{fixture.OpGet}})
	if m, err := recv(t, c); err != nil || m.T != devslot.MsgAck || m.Err != "" {
		t.Errorf("ack: %+v, %v", m, err)
	}
	send(t, c, reading("temperature", -2, okTime))
	send(t, c, devslot.Msg{T: devslot.MsgDone})
}

func TestHostRefusesDeclarationNotInImage(t *testing.T) {
	other := fixture.Declaration()
	other.Operations = append(other.Operations, devslot.Operation{Name: "unlock", Verb: "actuate-physical"})
	wider := fixture.Declaration()
	wider.Shapes[1].Max = 64
	cases := map[string]func() []byte{
		"another operation": func() []byte { b, _ := devslot.Canonical(other); return b },
		"a wider shape":     func() []byte { b, _ := devslot.Canonical(wider); return b },
		"non-canonical": func() []byte {
			b, _ := devslot.Canonical(fixture.Declaration())
			return append([]byte(" "), b...)
		},
	}
	for name, decl := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(t *testing.T, c net.Conn) {
				send(t, c, devslot.Msg{T: devslot.MsgDeclare, B: decl()})
				if !closed(c) {
					t.Errorf("host kept the connection of a driver whose declaration is not the image's")
				}
			})
			if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devhost.ErrNotInImage) {
				t.Fatalf("Do: %v, want ErrNotInImage", err)
			}
			if len(r.tr.writes) != 0 || len(r.s.events) != 0 {
				t.Fatalf("something ran: %d writes, %d events", len(r.tr.writes), len(r.s.events))
			}
		})
	}
	t.Run("operation the image lacks", func(t *testing.T) {
		r := newRig(t, good)
		if _, err := r.h.Do(context.Background(), "unlock"); !errors.Is(err, devslot.ErrUnknownOp) {
			t.Fatalf("Do: %v, want ErrUnknownOp", err)
		}
		if r.d.dials != 0 {
			t.Fatalf("the driver started for an operation the image lacks")
		}
	})
	t.Run("control: the image's declaration runs", func(t *testing.T) {
		r := newRig(t, good)
		if n, err := r.h.Do(context.Background(), "read-temperature"); err != nil || n != 1 {
			t.Fatalf("Do: %d, %v", n, err)
		}
	})
}

func TestHostRechecksShapes(t *testing.T) {
	cases := map[string]devslot.Msg{
		"undeclared frame":          {T: devslot.MsgWrite, Ch: "control", B: []byte{0x7f}},
		"oversize frame":            {T: devslot.MsgWrite, Ch: "control", B: []byte{fixture.OpGet, 0}},
		"frame for another channel": {T: devslot.MsgWrite, Ch: "data", B: []byte{fixture.OpGet}},
		"undeclared channel":        {T: devslot.MsgWrite, Ch: "debug", B: []byte{fixture.OpGet}},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(t *testing.T, c net.Conn) {
				if _, ok := declare(t, c); !ok {
					return
				}
				send(t, c, w)
				if !closed(c) {
					t.Errorf("host answered a refused write")
				}
			})
			if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrUndeclared) {
				t.Fatalf("Do: %v, want ErrUndeclared", err)
			}
			if len(r.tr.writes) != 0 {
				t.Fatalf("a refused frame reached the transport: %x", r.tr.writes)
			}
		})
	}
	t.Run("frame from another device", func(t *testing.T) {
		r := newRig(t, func(t *testing.T, c net.Conn) {
			if _, ok := declare(t, c); !ok {
				return
			}
			send(t, c, devslot.Msg{T: devslot.MsgRead})
			if !closed(c) {
				t.Errorf("host passed a frame from another device")
			}
		})
		c, _ := fixture.Declaration().Chan("data")
		r.tr.reads = []devslot.Target{{Pin: devslot.Pin{Address: "02:00:00:00:00:02"}, Channel: c}}
		r.tr.frames = [][]byte{{fixture.OpReadings, 0}}
		if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrUnpinned) {
			t.Fatalf("Do: %v, want ErrUnpinned", err)
		}
	})
	t.Run("device frame past MaxRead", func(t *testing.T) {
		r := newRig(t, func(t *testing.T, c net.Conn) {
			if _, ok := declare(t, c); ok {
				send(t, c, devslot.Msg{T: devslot.MsgRead})
				closed(c)
			}
		})
		r.tr.queue("data", make([]byte, fixture.Declaration().MaxRead+1))
		if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrTooLarge) {
			t.Fatalf("Do: %v, want ErrTooLarge", err)
		}
	})
	t.Run("control: a declared frame reaches the device", func(t *testing.T) {
		r := newRig(t, good)
		if _, err := r.h.Do(context.Background(), "read-temperature"); err != nil {
			t.Fatal(err)
		}
		if len(r.tr.writes) != 1 || r.tr.writes[0][0] != fixture.OpGet {
			t.Fatalf("writes %x", r.tr.writes)
		}
	})
}

func TestHostRechecksReadings(t *testing.T) {
	cases := map[string]devslot.Msg{
		"undeclared kind":      reading("humidity", 0, okTime),
		"exponent above range": reading("temperature", 19, okTime),
		"exponent below range": reading("temperature", -19, okTime),
		"zone offset":          reading("temperature", 0, "2026-10-27T11:00:00+01:00"),
		"zero offset, not Z":   reading("temperature", 0, "2026-10-27T10:00:00+00:00"),
		"zone name":            reading("temperature", 0, "2026-10-27T10:00:00Z Europe/Paris"),
		"non-canonical time":   reading("temperature", 0, "2026-10-27T10:00:00.500000000Z"),
		"no time":              reading("temperature", 0, ""),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(t *testing.T, c net.Conn) {
				if _, ok := declare(t, c); !ok {
					return
				}
				send(t, c, reading("temperature", -2, okTime))
				send(t, c, m)
				send(t, c, devslot.Msg{T: devslot.MsgDone})
			})
			if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrReading) {
				t.Fatalf("Do: %v, want ErrReading", err)
			}
			if len(r.s.events) != 0 {
				t.Fatalf("an operation with a refused reading emitted %d events", len(r.s.events))
			}
		})
	}
	t.Run("too many readings", func(t *testing.T) {
		r := newRig(t, func(t *testing.T, c net.Conn) {
			if _, ok := declare(t, c); !ok {
				return
			}
			for range fixture.Declaration().MaxReadings + 1 {
				if !send(t, c, reading("temperature", 0, okTime)) {
					return
				}
			}
		})
		if _, err := r.h.Do(context.Background(), "read-temperature"); !errors.Is(err, devslot.ErrReading) {
			t.Fatalf("Do: %v, want ErrReading", err)
		}
	})
	t.Run("control: a declared reading is a private event", func(t *testing.T) {
		r := newRig(t, good)
		if _, err := r.h.Do(context.Background(), "read-temperature"); err != nil {
			t.Fatal(err)
		}
		e := r.s.events[0]
		if e.Device != "fixture-thermometer" || e.Label != devslot.Label || !e.Unverified ||
			e.Reading.Value != 2150 || e.Reading.Exp != -2 || e.Reading.Time.Location() != time.UTC {
			t.Fatalf("event %+v", e)
		}
	})
}

func TestHostDeadlineFailsOperation(t *testing.T) {
	silent := func(t *testing.T, c net.Conn) {
		if _, ok := declare(t, c); !ok {
			return
		}
		if !closed(c) {
			t.Errorf("host kept the connection of an operation past its deadline")
		}
	}
	d := &dialer{t: t, scripts: []script{silent, good}}
	h, err := devhost.New(devhost.Config{
		Decl: fixture.Declaration(), Pin: pin, Dialer: d, Transport: &transport{}, Sink: &sink{},
		Deadline: 200 * time.Millisecond, Limit: devhost.Limit{Burst: 1, Window: time.Minute},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.done.Wait()
	start := time.Now()
	if _, err := h.Do(context.Background(), "read-temperature"); !errors.Is(err, devhost.ErrDeadline) {
		t.Fatalf("Do: %v, want ErrDeadline", err)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("a silent driver held its operation %v", el)
	}
	if n, err := h.Do(context.Background(), "read-temperature"); err != nil || n != 1 {
		t.Fatalf("next operation: %d, %v", n, err)
	}
	if d.dials != 2 {
		t.Fatalf("%d connections for two operations, want a new one each", d.dials)
	}
}

// clock is a test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestRateLimitCoalesces(t *testing.T) {
	burst := func(n int) script {
		return func(t *testing.T, c net.Conn) {
			if _, ok := declare(t, c); !ok {
				return
			}
			for range n {
				send(t, c, reading("temperature", 0, okTime))
			}
			send(t, c, devslot.Msg{T: devslot.MsgDone})
		}
	}
	clk := &clock{t: time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)}
	d, s := &dialer{t: t, scripts: []script{burst(20), burst(20), burst(2)}}, &sink{}
	h, err := devhost.New(devhost.Config{
		Decl: fixture.Declaration(), Pin: pin, Dialer: d, Transport: &transport{}, Sink: s,
		Deadline: 5 * time.Second, Limit: devhost.Limit{Burst: 3, Window: time.Minute}, Now: clk.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.done.Wait()
	// A flood of 40 readings in one window.
	for range 2 {
		if _, err := h.Do(context.Background(), "read-temperature"); err != nil {
			t.Fatal(err)
		}
		clk.t = clk.t.Add(10 * time.Second)
	}
	if len(s.events) != 3 {
		t.Fatalf("%d events inside the window, want the burst of 3", len(s.events))
	}
	h.Flush()
	if len(s.events) != 3 {
		t.Fatalf("the coalesced event went out before its window ended")
	}
	clk.t = clk.t.Add(time.Minute)
	h.Flush()
	if len(s.events) != 4 || s.events[3].Coalesced != 37 {
		t.Fatalf("events %+v, want one coalesced event counting 37", s.events[3:])
	}
	h.Flush()
	if len(s.events) != 4 {
		t.Fatalf("the window's count went out twice")
	}
	// The next window passes its own burst.
	if _, err := h.Do(context.Background(), "read-temperature"); err != nil {
		t.Fatal(err)
	}
	if len(s.events) != 6 || s.events[4].Coalesced != 0 {
		t.Fatalf("next window: %d events", len(s.events))
	}
}

// slotDriver is a real driver behind the real slot: it asks for one
// reading and parses the reply.
type slotDriver struct{}

func (slotDriver) Declare() devslot.Declaration { return fixture.Declaration() }

func (slotDriver) Run(ctx context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
	if err := l.Write(ctx, "control", []byte{fixture.OpGet}); err != nil {
		return nil, err
	}
	ch, f, err := l.Read(ctx)
	if err != nil || ch != "data" || len(f) != 8 || f[0] != fixture.OpReadings || f[1] != 1 {
		return nil, errors.New("bad reply")
	}
	v := int16(binary.BigEndian.Uint16(f[2:]))
	ts := time.Unix(int64(binary.BigEndian.Uint32(f[4:])), 0).In(time.FixedZone("Europe/Paris", 3600))
	return []devslot.Reading{{Kind: "temperature", Value: int64(v), Exp: -2, Time: ts}}, nil
}

func TestHostRunsSlotDriver(t *testing.T) {
	r := newRig(t, func(t *testing.T, c net.Conn) {
		if err := devslot.ServeWire(context.Background(), slotDriver{}, c); err != nil {
			t.Errorf("ServeWire: %v", err)
		}
	})
	r.tr.queue("data", []byte{fixture.OpReadings, 1, 0x08, 0x66, 0x65, 0x00, 0x00, 0x00})
	if n, err := r.h.Do(context.Background(), "read-temperature"); err != nil || n != 1 {
		t.Fatalf("Do: %d, %v", n, err)
	}
	e := r.s.events[0].Reading
	if e.Value != 2150 || e.Time.Location() != time.UTC || !e.Time.Equal(time.Unix(0x65000000, 0)) {
		t.Fatalf("reading %+v", e)
	}
}

func TestNewRefusesInternetPin(t *testing.T) {
	d := fixture.Declaration()
	d.Link = devslot.TCP
	d.Channels = []devslot.Channel{{Name: "control", Port: 8443}}
	d.Shapes = d.Shapes[:1]
	d.Shapes[0].Kind = devslot.TCPFrame
	d.Operations[0].Shapes = []string{d.Shapes[0].Name}
	cfg := devhost.Config{Decl: d, Dialer: &dialer{}, Transport: &transport{}, Sink: &sink{},
		Deadline: time.Second, Limit: devhost.Limit{Burst: 1, Window: time.Second}}
	home := netip.MustParsePrefix("2a02:1234:5678:ab00::/56")
	cfg.Pin = devslot.Pin{Host: netip.MustParseAddr("2a02:1234:5678:abcd::5"), Key: [32]byte{1}}
	if _, err := devhost.New(cfg); err == nil {
		t.Fatalf("a global address was accepted with no home prefix")
	}
	cfg.Home = home
	if _, err := devhost.New(cfg); err != nil {
		t.Fatalf("an address inside the uplink's /56 was refused: %v", err)
	}
	cfg.Pin.Host = netip.MustParseAddr("2a02:1234:5679::5")
	if _, err := devhost.New(cfg); err == nil {
		t.Fatalf("a global address outside the uplink's /56 was accepted")
	}
}
