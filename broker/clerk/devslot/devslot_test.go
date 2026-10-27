package devslot_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/conformance"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture/fake"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

// REQ: DEV-1, DEV-2, DEV-3, DEV-4, DEV-8, CLK-1, KRN-2

const pkg = "github.com/ghbmrk/agentos/broker/clerk/devslot"

// Synthetic canaries, two device slots' keys (32 bytes each).
var (
	canary      = []byte("devslot-test-canary-own-slot-001")
	otherCanary = []byte("devslot-test-canary-other-slot-2")
)

var gattPin = devslot.Pin{Address: "02:00:00:00:00:01"}

// transport carries frames between the slot and a fake device and records
// every frame written.
type transport struct {
	dev    *fake.Device
	pin    devslot.Pin
	d      devslot.Declaration
	queue  []conformance.Frame
	writes [][]byte
	// inject, if set, replaces the next read's target.
	inject *devslot.Target
	big    bool
}

func newTransport(dev *fake.Device) *transport {
	t := &transport{dev: dev, pin: gattPin, d: fixture.Declaration()}
	t.queue = dev.Connect("")
	return t
}

func (t *transport) Write(_ context.Context, to devslot.Target, f []byte) error {
	if to.Pin != t.pin {
		return errors.New("transport: write off the pin")
	}
	t.writes = append(t.writes, slices.Clone(f))
	t.queue = append(t.queue, t.dev.Respond(to.Channel.Name, f)...)
	return nil
}

func (t *transport) Read(context.Context) (devslot.Target, []byte, error) {
	if t.big {
		return devslot.Target{Pin: t.pin, Channel: t.d.Channels[1]}, make([]byte, t.d.MaxRead+1), nil
	}
	if t.inject != nil {
		to := *t.inject
		t.inject = nil
		return to, []byte{fixture.OpChallenge, 1, 2, 3, 4, 5, 6, 7, 8}, nil
	}
	if len(t.queue) == 0 {
		return devslot.Target{}, nil, errors.New("transport: nothing to read")
	}
	f := t.queue[0]
	t.queue = t.queue[1:]
	for _, c := range t.d.Channels {
		if c.Name == f.Channel {
			return devslot.Target{Pin: t.pin, Channel: c}, f.Bytes, nil
		}
	}
	return devslot.Target{}, nil, errors.New("transport: unknown channel")
}

func store(t *testing.T) *clerk.Secrets {
	t.Helper()
	s, err := clerk.NewAESSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sec := clerk.NewSecrets(s, nil)
	for slot, k := range map[string][]byte{"device/fixture-1": canary, "device/other": otherCanary, "mail-token": otherCanary} {
		if err := sec.Put(slot, clerk.KindStatic, k); err != nil {
			t.Fatal(err)
		}
	}
	return sec
}

// record is a host's view of one slot: the events, the log and the frames.
type record struct {
	events []devslot.Event
	logs   []string
}

func env(t *testing.T, tr devslot.Transport, slot string, r *record) devslot.Env {
	return devslot.Env{
		Pin: gattPin, Transport: tr, Lend: store(t).DeviceKey(slot),
		Emit: func(e devslot.Event) error { r.events = append(r.events, e); return nil },
		Log:  func(m string) { r.logs = append(r.logs, m) },
	}
}

func TestFixtureDriverServes(t *testing.T) {
	dev := &fake.Device{Key: canary, Temps: []int16{2150, -340, 2201}}
	var r record
	s, err := devslot.New(fixture.Driver{}, env(t, newTransport(dev), "device/fixture-1", &r))
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Do(context.Background(), "read-temperature")
	if err != nil || n != 3 {
		t.Fatalf("Do = %d, %v; want 3 readings", n, err)
	}
	for i, e := range r.events {
		if e.Device != "fixture-thermometer" || e.Op != "read-temperature" || devslot.Label != "private" ||
			e.Label != devslot.Label || !e.Unverified {
			t.Errorf("event %d = %+v; want the device's private, unverified event", i, e)
		}
		if e.Reading.Kind != "temperature" || e.Reading.Value != int64(dev.Temps[i]) || e.Reading.Exp != -2 ||
			e.Reading.Time.Unix() != int64(1_700_000_000+60*i) {
			t.Errorf("reading %d = %+v", i, e.Reading)
		}
	}
	// Serve runs the same driver from a host's queue of operations.
	r = record{}
	dev = &fake.Device{Key: canary, Temps: []int16{1}}
	ops := make(chan string, 2)
	ops <- "read-temperature"
	ops <- "set-temperature" // undeclared: refused and logged, Serve goes on
	close(ops)
	if err := devslot.Serve(context.Background(), fixture.Driver{}, env(t, newTransport(dev), "device/fixture-1", &r), ops); err != nil {
		t.Fatal(err)
	}
	if len(r.events) != 1 || len(r.logs) != 1 || !strings.Contains(r.logs[0], "undeclared operation") {
		t.Fatalf("Serve: events %v, logs %q", r.events, r.logs)
	}
	// A used transport has nothing left to read: the slot invents nothing.
	if _, err := s.Do(context.Background(), "read-temperature"); err == nil {
		t.Fatal("a second read on a used transport should fail, not invent readings")
	}
	// A device pinned by its key (a TCP pin) gives verified readings (DEV-3).
	d := fixture.Declaration()
	d.Link, d.Channels = devslot.TCP, []devslot.Channel{{Name: "control", Port: 8443}}
	d.Shapes = d.Shapes[:1]
	d.Shapes[0].Kind = devslot.TCPFrame
	d.Operations[0].Shapes = []string{"answer"}
	r = record{}
	e := env(t, newTransport(dev), "device/fixture-1", &r)
	e.Pin = devslot.Pin{Host: netip.MustParseAddr("192.168.1.20"), Key: [32]byte{9}}
	one := fn{d: d, run: func(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error) {
		return []devslot.Reading{{Kind: "temperature", Value: 1}}, nil
	}}
	if s, err := devslot.New(one, e); err != nil {
		t.Fatal(err)
	} else if _, err := s.Do(context.Background(), "read-temperature"); err != nil || len(r.events) != 1 || r.events[0].Unverified {
		t.Fatalf("tcp read: %v, %+v; want one verified event", err, r.events)
	}
}

// fn is a driver made of a declaration and a run function.
type fn struct {
	d   devslot.Declaration
	run func(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error)
	ran *bool
}

func (f fn) Declare() devslot.Declaration { return f.d }
func (f fn) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	if f.ran != nil {
		*f.ran = true
	}
	return f.run(ctx, op, l, sec)
}

func TestDeclarationOutsideDEV4IsRefused(t *testing.T) {
	tcp := func(d *devslot.Declaration, p *devslot.Pin, host string) {
		d.Link = devslot.TCP
		d.Channels = []devslot.Channel{{Name: "control", Port: 8443}}
		d.Shapes = d.Shapes[:1]
		d.Shapes[0].Kind = devslot.TCPFrame
		d.Operations[0].Shapes = []string{d.Shapes[0].Name}
		*p = devslot.Pin{Host: netip.MustParseAddr(host), Key: [32]byte{9}}
	}
	cases := map[string]func(d *devslot.Declaration, p *devslot.Pin){
		"verb send":             func(d *devslot.Declaration, _ *devslot.Pin) { d.Operations[0].Verb = key.Send },
		"verb fetch":            func(d *devslot.Declaration, _ *devslot.Pin) { d.Operations[0].Verb = key.Fetch },
		"verb buy":              func(d *devslot.Declaration, _ *devslot.Pin) { d.Operations[0].Verb = key.Buy },
		"verb not on any list":  func(d *devslot.Declaration, _ *devslot.Pin) { d.Operations[0].Verb = "shell" },
		"unknown shape kind":    func(d *devslot.Declaration, _ *devslot.Pin) { d.Shapes[0].Kind = "raw-socket" },
		"tcp shape on gatt":     func(d *devslot.Declaration, _ *devslot.Pin) { d.Shapes[0].Kind = devslot.TCPFrame },
		"unknown link kind":     func(d *devslot.Declaration, _ *devslot.Pin) { d.Link = "usb" },
		"undeclared shape":      func(d *devslot.Declaration, _ *devslot.Pin) { d.Operations[0].Shapes = []string{"anything"} },
		"device text in a name": func(d *devslot.Declaration, _ *devslot.Pin) { d.Readings = []string{"Call me now!"} },
		"oversize write":        func(d *devslot.Declaration, _ *devslot.Pin) { d.Shapes[0].Max = devslot.CapWrite + 1 },
		"internet host v4":      func(d *devslot.Declaration, p *devslot.Pin) { tcp(d, p, "8.8.8.8") },
		"internet host v6":      func(d *devslot.Declaration, p *devslot.Pin) { tcp(d, p, "2001:4860:4860::8888") },
		"the box itself":        func(d *devslot.Declaration, p *devslot.Pin) { tcp(d, p, "127.0.0.1") },
		"mapped internet host":  func(d *devslot.Declaration, p *devslot.Pin) { tcp(d, p, "::ffff:1.1.1.1") },
		"multicast":             func(d *devslot.Declaration, p *devslot.Pin) { tcp(d, p, "224.0.0.251") },
		"tcp pin without key": func(d *devslot.Declaration, p *devslot.Pin) {
			tcp(d, p, "192.168.1.20")
			p.Key = [32]byte{}
		},
		"gatt pin not an address": func(_ *devslot.Declaration, p *devslot.Pin) { p.Address = "scale.local" },
	}
	// The control: the same edits with a home-network host and a key pass.
	d, p := fixture.Declaration(), gattPin
	tcp(&d, &p, "192.168.1.20")
	if err := devslot.Check(d, p); err != nil {
		t.Fatalf("home-network tcp declaration refused: %v", err)
	}
	if err := devslot.Check(d, devslot.Pin{Host: netip.MustParseAddr("::ffff:192.168.1.20"), Key: p.Key}); err != nil {
		t.Fatalf("v4-mapped home-network host refused: %v", err)
	}
	if err := devslot.Check(fixture.Declaration(), gattPin); err != nil {
		t.Fatalf("fixture declaration refused: %v", err)
	}
	for name, edit := range cases {
		d, p := fixture.Declaration(), gattPin
		edit(&d, &p)
		ran := false
		drv := fn{d: d, ran: &ran, run: func(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error) {
			return nil, nil
		}}
		var r record
		e := env(t, newTransport(&fake.Device{}), "device/fixture-1", &r)
		e.Pin = p
		_, err := devslot.New(drv, e)
		if !errors.Is(err, devslot.ErrDeclaration) {
			t.Errorf("%s: New = %v; want ErrDeclaration", name, err)
		}
		ops := make(chan string, 1)
		ops <- d.Operations[0].Name
		close(ops)
		if err := devslot.Serve(context.Background(), drv, e, ops); !errors.Is(err, devslot.ErrDeclaration) || ran {
			t.Errorf("%s: Serve = %v, ran %v; want refused before the driver runs", name, err, ran)
		}
	}
}

func TestLinkReachesOnlyPinnedDevice(t *testing.T) {
	write := func(ch string, f []byte) func(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error) {
		return func(ctx context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
			l.Write(ctx, ch, f)
			return nil, nil // a driver that ignores the refusal still fails
		}
	}
	read := func(ctx context.Context, _ string, l devslot.Link, _ devslot.Secrets) ([]devslot.Reading, error) {
		_, _, err := l.Read(ctx)
		return nil, err
	}
	d := fixture.Declaration()
	otherChar := d.Channels[1]
	otherChar.Char = "0000fff9-0000-1000-8000-00805f9b34fb"
	cases := []struct {
		name   string
		run    func(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error)
		inject *devslot.Target
		big    bool
		want   error
	}{
		{"undeclared channel", write("firmware", []byte{fixture.OpGet}), nil, false, devslot.ErrUndeclared},
		{"declared channel, no shape", write("data", []byte{fixture.OpGet}), nil, false, devslot.ErrUndeclared},
		{"shape too long", write("control", []byte{fixture.OpGet, 0}), nil, false, devslot.ErrUndeclared},
		{"unknown opcode", write("control", []byte{0x07}), nil, false, devslot.ErrUndeclared},
		{"other address", read, &devslot.Target{Pin: devslot.Pin{Address: "02:00:00:00:00:02"}, Channel: d.Channels[1]}, false, devslot.ErrUnpinned},
		{"undeclared characteristic", read, &devslot.Target{Pin: gattPin, Channel: otherChar}, false, devslot.ErrUnpinned},
		{"frame over MaxRead", read, nil, true, devslot.ErrTooLarge},
	}
	for _, c := range cases {
		tr := newTransport(&fake.Device{Key: canary})
		tr.inject, tr.big = c.inject, c.big
		var r record
		s, err := devslot.New(fn{d: d, run: c.run}, env(t, tr, "device/fixture-1", &r))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Do(context.Background(), "read-temperature"); !errors.Is(err, c.want) {
			t.Errorf("%s: Do = %v; want %v", c.name, err, c.want)
		}
		if len(tr.writes) != 0 || len(r.events) != 0 {
			t.Errorf("%s: wrote %d frames, emitted %d events; want none", c.name, len(tr.writes), len(r.events))
		}
	}
	// Beyond the link, neither the slot nor the fixture driver imports a
	// socket, file or process package; the suite holds drivers to that.
	for _, p := range []string{pkg, pkg + "/testdata/fixture"} {
		out, err := exec.Command("go", "list", "-f", `{{join .Imports " "}}`, p).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", p, err, out)
		}
		for _, imp := range strings.Fields(string(out)) {
			if imp == "net" || imp == "os" || imp == "syscall" || imp == "unsafe" ||
				strings.HasPrefix(imp, "os/") || (strings.HasPrefix(imp, "net/") && imp != "net/netip") {
				t.Errorf("%s imports %s", p, imp)
			}
		}
	}
	if ps := conformance.Check(fixture.Driver{}, config(pkg+"/testdata/fixture")); len(ps) != 0 {
		t.Errorf("fixture fails the suite: %v", ps)
	}
}

func TestSecretsOpenOnlyOwnSlot(t *testing.T) {
	var lent []byte
	peek := func(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
		if s := fmt.Sprintf("%v %+v %#v %s", sec, sec, sec, sec); bytes.Contains([]byte(s), canary) {
			t.Errorf("Secrets prints its key: %s", s)
		}
		return nil, sec.Open(func(k []byte) error { lent = k; return bytes.ErrTooLarge })
	}
	d := fixture.Declaration()
	open := func(slot string) []byte {
		lent = nil
		var r record
		s, err := devslot.New(fn{d: d, run: peek}, env(t, newTransport(&fake.Device{}), slot, &r))
		if err != nil {
			t.Fatal(err)
		}
		s.Do(context.Background(), "read-temperature")
		return lent
	}
	// The pinned device slot lends its own key for the one call, then wipes it
	// (D-184), so the driver keeps nothing.
	if k := open("device/fixture-1"); k == nil || !bytes.Equal(k, make([]byte, len(canary))) {
		t.Errorf("own slot: kept key %x; want the canary lent then wiped", k)
	}
	if k := open("mail-token"); k != nil {
		t.Errorf("a non-device slot opened: %q", k)
	}
	// The driver's handle names no slot, so the other device's key is out of
	// reach whatever it does; a host pinning that slot lends that key only.
	var seen []byte
	s, _ := devslot.New(fn{d: d, run: func(_ context.Context, _ string, _ devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
		return nil, sec.Open(func(k []byte) error { seen = slices.Clone(k); return nil })
	}}, env(t, newTransport(&fake.Device{}), "device/fixture-1", &record{}))
	s.Do(context.Background(), "read-temperature")
	if !bytes.Equal(seen, canary) || bytes.Equal(seen, otherCanary) {
		t.Errorf("lent %q; want the own slot's key", seen)
	}
	// The canary appears in no log, error, event or written frame: a clean
	// run, a driver that puts the key in its error, and one that panics with it.
	leaks := map[string]func(context.Context, string, devslot.Link, devslot.Secrets) ([]devslot.Reading, error){
		"clean": fixture.Driver{}.Run,
		"error": func(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
			var err error
			sec.Open(func(k []byte) error { err = fmt.Errorf("auth failed with key %s / %x", k, k); return nil })
			return nil, err
		},
		"panic": func(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
			sec.Open(func(k []byte) error { panic(string(k)) })
			return nil, nil
		},
	}
	for name, run := range leaks {
		tr := newTransport(&fake.Device{Key: canary, Temps: []int16{1, 2}})
		var r record
		s, err := devslot.New(fn{d: d, run: run}, env(t, tr, "device/fixture-1", &r))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.Do(context.Background(), "read-temperature")
		all := fmt.Sprintf("%v|%+v|%q", err, r.events, r.logs)
		for _, w := range tr.writes {
			all += string(w)
		}
		if strings.Contains(all, string(canary)) || strings.Contains(all, hex.EncodeToString(canary)) {
			t.Errorf("%s: canary leaked: %s", name, all)
		}
		if name == "clean" && (err != nil || len(r.events) != 2) {
			t.Errorf("clean: %v, %d events", err, len(r.events))
		}
		if name != "clean" && err == nil {
			t.Errorf("%s: Do succeeded", name)
		}
	}
}

func config(pkgs ...string) conformance.Config {
	return conformance.Config{
		NewDevice: func(k []byte) conformance.Device { return &fake.Device{Key: k, Temps: []int16{2150, 2160}} },
		Packages:  pkgs,
		Seed:      1,
	}
}

// The bad fixtures.

// extra writes one frame after the fixture's own run.
type extra struct{ frame []byte }

func (extra) Declare() devslot.Declaration { return fixture.Declaration() }
func (e extra) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	rs, err := fixture.Driver{}.Run(ctx, op, l, sec)
	if err != nil {
		return nil, err
	}
	return rs, l.Write(ctx, "control", e.frame)
}

// leaker declares a roomy shape and writes its key through it.
type leaker struct{}

func (leaker) Declare() devslot.Declaration {
	d := fixture.Declaration()
	d.Shapes = append(d.Shapes, devslot.Shape{Name: "dump", Channel: "control", Kind: devslot.GATTWrite, Prefix: []byte{4}, Min: 1, Max: 64})
	d.Operations[0].Shapes = append(d.Operations[0].Shapes, "dump")
	return d
}
func (leaker) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	rs, err := fixture.Driver{}.Run(ctx, op, l, sec)
	sec.Open(func(k []byte) error { return l.Write(ctx, "control", append([]byte{4}, k...)) })
	return rs, err
}

// trusting parses the reply without checking its length.
type trusting struct{ fixture.Driver }

func (trusting) Run(ctx context.Context, op string, l devslot.Link, sec devslot.Secrets) ([]devslot.Reading, error) {
	_, f, err := l.Read(ctx)
	if err != nil {
		return nil, err
	}
	answer := []byte{fixture.OpAnswer}
	sec.Open(func(k []byte) error { answer = append(answer, fixture.Tag(k, f[1:])...); return nil })
	l.Write(ctx, "control", answer)
	l.Write(ctx, "control", []byte{fixture.OpGet})
	if _, f, err = l.Read(ctx); err != nil {
		return nil, err
	}
	var rs []devslot.Reading
	for i := range int(f[1]) {
		rs = append(rs, devslot.Reading{Kind: "temperature", Value: int64(binary.BigEndian.Uint16(f[2+6*i:]))})
	}
	return rs, nil
}

func TestConformanceRejectsBadFixtures(t *testing.T) {
	if ps := conformance.Check(fixture.Driver{}, config(pkg+"/testdata/fixture")); len(ps) != 0 {
		t.Fatalf("the good fixture fails: %v", ps)
	}
	cases := []struct {
		name string
		drv  devslot.Driver
		pkgs []string
		want string
	}{
		{"undeclared shape", extra{[]byte{0x05, 1}}, nil, "undeclared-write"},
		{"canary leak", leaker{}, nil, "canary"},
		{"panicking parser", trusting{}, nil, "panic"},
		{"own socket", fixture.Driver{}, []string{pkg + "/testdata/netdriver"}, "imports"},
	}
	for _, c := range cases {
		ps := conformance.Check(c.drv, config(c.pkgs...))
		if !slices.ContainsFunc(ps, func(p conformance.Problem) bool { return p.Kind == c.want }) {
			t.Errorf("%s: problems %v; want a %s problem", c.name, ps, c.want)
		}
	}
}

// The kernel, the key library and the clerk check path link neither the slot
// nor any driver (KRN-2): driver code runs only in its own clerk process.
func TestCheckPathDoesNotLinkDevslot(t *testing.T) {
	for _, p := range []string{"..", "../../kernel", "../../kernel/key"} {
		out, err := exec.Command("go", "list", "-deps", p).CombinedOutput()
		if err != nil {
			t.Fatalf("go list %s: %v\n%s", p, err, out)
		}
		if !strings.Contains(string(out), "github.com/ghbmrk/agentos/broker/kernel/key") {
			t.Fatalf("go list %s returned no kernel deps; the check proves nothing", p)
		}
		for _, d := range strings.Fields(string(out)) {
			if strings.HasPrefix(d, pkg) {
				t.Errorf("%s links %s", p, d)
			}
		}
	}
}
