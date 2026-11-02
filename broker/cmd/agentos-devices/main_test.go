package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/clerk/devslot"
	"github.com/ghbmrk/agentos/broker/clerk/devslot/testdata/fixture"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: DEV-1, DEV-3, CLK-1, KRN-2

// device is a TCP device: a TLS server with its own key, which records what
// reaches it after the handshake and answers each frame with "ack".
type device struct {
	ln    net.Listener
	spki  [32]byte
	mu    sync.Mutex
	got   []byte
	conns int
}

func newDevice(t *testing.T) *device {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}})
	if err != nil {
		t.Fatal(err)
	}
	d := &device{ln: ln, spki: sha256.Sum256(cert.RawSubjectPublicKeyInfo)}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns++
			d.mu.Unlock()
			go func() {
				defer c.Close()
				buf := make([]byte, 64)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					d.mu.Lock()
					d.got = append(d.got, buf[:n]...)
					d.mu.Unlock()
					c.Write([]byte("ack"))
				}
			}()
		}
	}()
	return d
}

func (d *device) received() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return bytes.Clone(d.got)
}

func (d *device) connections() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}

// guardFor is the process's guard for these pins of a TCP declaration.
func guardFor(t *testing.T, d devslot.Declaration, pins ...devslot.Pin) *deviceGuard {
	t.Helper()
	image := map[string]imageDriver{"plug": {Name: "plug", Decl: d}}
	var ps []pinned
	for _, p := range pins {
		ps = append(ps, pinned{"plug", p})
	}
	return newDeviceGuard(image, ps, func(string) {})
}

func (d *device) port() uint16 { return uint16(d.ln.Addr().(*net.TCPAddr).Port) }

func tcpDecl(port uint16) devslot.Declaration {
	return devslot.Declaration{
		Device:      "fixture-plug",
		Link:        devslot.TCP,
		Channels:    []devslot.Channel{{Name: "stream", Port: port}},
		Shapes:      []devslot.Shape{{Name: "get", Channel: "stream", Kind: devslot.TCPFrame, Prefix: []byte("get"), Min: 3, Max: 3}},
		Operations:  []devslot.Operation{{Name: "read-power", Verb: key.Read, Shapes: []string{"get"}, MaxWrites: 1}},
		Readings:    []string{"power"},
		MaxRead:     64,
		MaxReadings: 4,
	}
}

func TestTCPTransportRefusesWrongKey(t *testing.T) {
	dev := newDevice(t)
	d := tcpDecl(dev.port())
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Another device's key: the handshake is refused, and no frame reaches
	// the device.
	wrong := devslot.Pin{Host: netip.MustParseAddr("127.0.0.1"), Key: sha256.Sum256([]byte("another device"))}
	tr, err := newTCPTransport(d, wrong, guardFor(t, d, wrong))
	if err != nil {
		t.Fatal(err)
	}
	tg := devslot.Target{Pin: wrong, Channel: d.Channels[0]}
	if err := tr.Write(ctx, tg, []byte("get")); !errors.Is(err, errWrongKey) {
		t.Fatalf("write to a device whose key is not the pin's: %v, want errWrongKey", err)
	}
	if _, _, err := tr.Read(ctx); !errors.Is(err, errWrongKey) {
		t.Fatalf("read from a device whose key is not the pin's: %v, want errWrongKey", err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := dev.received(); len(got) != 0 {
		t.Fatalf("the device got %q under the wrong key", got)
	}

	// The pinned key: the frame goes through, and the answer comes back on
	// the declared channel.
	right := devslot.Pin{Host: netip.MustParseAddr("127.0.0.1"), Key: dev.spki}
	tg = devslot.Target{Pin: right, Channel: d.Channels[0]}

	// The address guard (DEV-2): with no pin for the device's address and
	// port, the dial is refused before any connection is made.
	before := dev.connections()
	other := tcpDecl(dev.port() + 1)
	for what, g := range map[string]*deviceGuard{
		"no pins":         guardFor(t, d),
		"another port":    guardFor(t, other, right),
		"unlisted driver": newDeviceGuard(map[string]imageDriver{}, []pinned{{"plug", right}}, func(string) {}),
	} {
		tr, err = newTCPTransport(d, right, g)
		if err != nil {
			t.Fatal(err)
		}
		if err := tr.Write(ctx, tg, []byte("get")); !errors.Is(err, netguard.ErrDenied) {
			t.Fatalf("%s: write: %v, want the guard's refusal", what, err)
		}
	}
	if dev.connections() != before {
		t.Fatal("a dial the guard refused reached the device")
	}
	if _, err := newTCPTransport(d, right, nil); err == nil {
		t.Fatal("a TCP transport with no address guard")
	}

	tr, err = newTCPTransport(d, right, guardFor(t, d, right))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Write(ctx, tg, []byte("get")); err != nil {
		t.Fatal(err)
	}
	from, frame, err := tr.Read(ctx)
	if err != nil || from != tg || string(frame) != "ack" {
		t.Fatalf("read = %v %q %v, want the pinned target and ack", from, frame, err)
	}
	// A frame for another device or another port never goes out.
	for _, other := range []devslot.Target{
		{Pin: devslot.Pin{Host: netip.MustParseAddr("127.0.0.2"), Key: dev.spki}, Channel: d.Channels[0]},
		{Pin: right, Channel: devslot.Channel{Name: "stream", Port: dev.port() + 1}},
	} {
		if err := tr.Write(ctx, other, []byte("get")); !errors.Is(err, errNotPinned) {
			t.Fatalf("write to %v: %v, want errNotPinned", other, err)
		}
	}
	if got := dev.received(); string(got) != "get" {
		t.Fatalf("the device got %q, want the one pinned frame", got)
	}

	// A call whose context ends while the device is silent returns, and
	// the next call connects again.
	short, stop := context.WithTimeout(ctx, 50*time.Millisecond)
	defer stop()
	if _, _, err := tr.Read(short); err == nil {
		t.Fatal("a read past its context's end returned a frame")
	}
	if err := tr.Write(ctx, tg, []byte("get")); err != nil {
		t.Fatalf("write after a dropped stream: %v", err)
	}
}

// The guard admits only pinned devices (Security delta probe on #3589): a
// public or private address no pin names is refused whatever the purpose.
func TestDeviceGuardAdmitsOnlyPins(t *testing.T) {
	d := tcpDecl(443)
	pin := devslot.Pin{Host: netip.MustParseAddr("192.168.1.2"), Key: sha256.Sum256([]byte("plug"))}
	ctx := context.Background()
	for what, g := range map[string]*deviceGuard{"no pins": guardFor(t, d), "one pin": guardFor(t, d, pin)} {
		for _, ap := range []string{"1.1.1.1:443", "192.168.1.3:443", "192.168.1.2:444", "[2606:4700::1111]:443"} {
			a := netip.MustParseAddrPort(ap)
			if err := g.Check(ctx, a.Addr(), a.Port(), "tcp"); !errors.Is(err, netguard.ErrDenied) {
				t.Errorf("%s: %s admitted: %v", what, ap, err)
			}
			if _, err := g.DialContext(ctx, a); !errors.Is(err, netguard.ErrDenied) {
				t.Errorf("%s: dial %s: %v, want refused", what, ap, err)
			}
		}
	}
	g := guardFor(t, d, pin)
	if err := g.Check(ctx, pin.Host, 443, "tcp"); err != nil {
		t.Fatalf("the pinned device: %v", err)
	}
	if err := g.Check(ctx, pin.Host, 443, "udp"); err == nil {
		t.Fatal("udp to the pinned device admitted")
	}
}

func TestTransportFor(t *testing.T) {
	g, err := transportFor(fixture.Declaration(), devslot.Pin{Address: "02:00:00:00:00:01"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Write(context.Background(), devslot.Target{}, []byte{1}); !errors.Is(err, errNoRelay) {
		t.Fatalf("GATT write: %v, want errNoRelay until part c", err)
	}
	if _, err := transportFor(tcpDecl(1), devslot.Pin{Host: netip.MustParseAddr("192.168.1.2")}, guardFor(t, tcpDecl(1))); err == nil {
		t.Fatal("a TCP transport with no pinned key")
	}
}

// image is a drivers.json with the fixture driver, its binary and its
// socket directory, all in a test directory.
type image struct {
	c       config
	bin     string
	ln      net.Listener
	accepts chan struct{}
	logs    []string
	mu      sync.Mutex
}

func newImage(t *testing.T) *image {
	t.Helper()
	dir := t.TempDir()
	x := &image{accepts: make(chan struct{}, 8)}
	x.c = config{drivers: filepath.Join(dir, "usr/drivers.json"), socketDir: filepath.Join(dir, "run"), uid: os.Getuid()}
	x.c.driversDir = filepath.Join(dir, "usr/drivers")
	x.bin = filepath.Join(x.c.driversDir, "fixture", "driver")
	if err := os.MkdirAll(filepath.Dir(x.bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(x.c.socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := []byte("\x7fELF the fixture driver")
	if err := os.WriteFile(x.bin, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	canon, err := devslot.Canonical(fixture.Declaration())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bin)
	doc := map[string]any{"drivers": []any{map[string]any{
		"name": "fixture", "repository": "ghbmrk/agentos-private", "commit": strings.Repeat("ab", 20),
		"sha256": hex.EncodeToString(sum[:]), "declaration": json.RawMessage(canon),
		"classes": map[string]string{"read-temperature": "read"}, "measure": map[string]int{"lines": 1, "deps": 0, "parsers": 0},
	}}}
	b, _ := json.Marshal(doc)
	if err := os.WriteFile(x.c.drivers, b, 0o644); err != nil {
		t.Fatal(err)
	}
	// The fixture's socket unit: each connection is one instance. This one
	// records the connection and closes it, so the operation fails after.
	x.ln, err = net.Listen("unix", filepath.Join(x.c.socketDir, "fixture.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { x.ln.Close() })
	go func() {
		for {
			c, err := x.ln.Accept()
			if err != nil {
				return
			}
			c.Close()
			x.accepts <- struct{}{}
		}
	}()
	return x
}

func (x *image) log(m string) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.logs = append(x.logs, m)
}

func (x *image) logged(sub string) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	for _, l := range x.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

func (x *image) hosts(t *testing.T, pins ...pinned) map[string]*devhost.Host {
	t.Helper()
	img, err := loadImage(x.c.drivers)
	if err != nil {
		t.Fatal(err)
	}
	return hosts(x.c, img, pins, x.log)
}

var fixturePin = pinned{"fixture", devslot.Pin{Address: "02:00:00:00:00:01"}}

func TestHostStartsOnlyImageDrivers(t *testing.T) {
	x := newImage(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A pin for a driver drivers.json does not list starts no host, and is
	// logged.
	hs := x.hosts(t, fixturePin, pinned{"ghost", devslot.Pin{Address: "02:00:00:00:00:02"}})
	if _, ok := hs["ghost"]; ok || len(hs) != 1 {
		t.Fatalf("hosts = %v, want the fixture's alone", hs)
	}
	if !x.logged(`driver "ghost", which drivers.json does not list; refused`) {
		t.Fatalf("no refusal logged for the unlisted driver: %q", x.logs)
	}

	// The image's binary: the operation reaches the driver's socket unit.
	if _, err := hs["fixture"].Do(ctx, "read-temperature"); err == nil {
		t.Fatal("the closed connection's operation succeeded")
	}
	select {
	case <-x.accepts:
	case <-ctx.Done():
		t.Fatal("the image's driver was never started")
	}

	// A binary whose hash differs from drivers.json's: refused before the
	// socket unit starts an instance, and logged.
	if err := os.WriteFile(x.bin, []byte("\x7fELF another driver"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := hs["fixture"].Do(ctx, "read-temperature"); !errors.Is(err, devhost.ErrDial) && !errors.Is(err, errBinary) {
		t.Fatalf("operation on a changed binary: %v, want a refused dial", err)
	}
	if !x.logged("driver fixture: devices: driver's binary is not the one drivers.json lists; refused") {
		t.Fatalf("no refusal logged for the changed binary: %q", x.logs)
	}
	// A binary that is gone, or is not a regular file, is refused too.
	os.Remove(x.bin)
	if err := os.Mkdir(x.bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := hs["fixture"].Do(ctx, "read-temperature"); err == nil {
		t.Fatal("operation on a directory for a binary succeeded")
	}
	select {
	case <-x.accepts:
		t.Fatal("a driver whose binary is not drivers.json's was started")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestLoadImageRefusesADamagedFile(t *testing.T) {
	x := newImage(t)
	good, _ := os.ReadFile(x.c.drivers)
	for what, edit := range map[string]func(string) string{
		"unknown key": func(s string) string { return strings.Replace(s, `"name"`, `"extra":1,"name"`, 1) },
		"short hash":  func(s string) string { return strings.Replace(s, `"sha256":"`, `"sha256":"0`, 1) },
		"name off":    func(s string) string { return strings.Replace(s, `"name":"fixture"`, `"name":"Fixture"`, 1) },
		"trailing":    func(s string) string { return s + "{}" },
		"listed twice": func(s string) string {
			i := strings.Index(s, "[") + 1
			j := strings.LastIndex(s, "]")
			return s[:i] + s[i:j] + "," + s[i:j] + s[j:]
		},
		"declaration key": func(s string) string { return strings.Replace(s, `"Device"`, `"Owner":1,"Device"`, 1) },
	} {
		t.Run(what, func(t *testing.T) {
			if err := os.WriteFile(x.c.drivers, []byte(edit(string(good))), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadImage(x.c.drivers); err == nil {
				t.Fatal("loaded")
			}
		})
	}
	if err := os.WriteFile(x.c.drivers, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if img, err := loadImage(x.c.drivers); err != nil || img["fixture"].Decl.Device != "fixture-thermometer" {
		t.Fatalf("loadImage = %v, %v", img, err)
	}
}

func TestPinsAndFlags(t *testing.T) {
	dir := t.TempDir()
	if p, err := loadPins(filepath.Join(dir, "missing.json")); err != nil || p != nil {
		t.Fatalf("missing pins file: %v %v, want no devices", p, err)
	}
	path := filepath.Join(dir, "pins.json")
	key := strings.Repeat("0a", 32)
	os.WriteFile(path, []byte(`{"pins":[{"driver":"plug","host":"192.168.1.9","key":"`+key+`"}]}`), 0o600)
	p, err := loadPins(path)
	if err != nil || len(p) != 1 || p[0].pin.Host != netip.MustParseAddr("192.168.1.9") || p[0].pin.Key[0] != 0x0a {
		t.Fatalf("loadPins = %v, %v", p, err)
	}
	for _, bad := range []string{
		`{"pins":[{"driver":"plug","key":"0a"}]}`,
		`{"pins":[{"driver":"plug","host":"nowhere"}]}`,
		`{"pins":[{"driver":"a","address":"02:00:00:00:00:01"},{"driver":"a","address":"02:00:00:00:00:02"}]}`,
		`{"pins":[],"more":1}`,
	} {
		os.WriteFile(path, []byte(bad), 0o600)
		if _, err := loadPins(path); err == nil {
			t.Fatalf("loaded %s", bad)
		}
	}
	for _, args := range [][]string{{"-drivers", "rel.json"}, {"-home", "2001:db8::/48"}, {"-home", "2001:db8::1/56"}, {"x"}} {
		if _, err := parse(args, io.Discard); err == nil {
			t.Fatalf("parse(%q) passed", args)
		}
	}
	c, err := parse([]string{"-home", "2001:db8:0:100::/56"}, io.Discard)
	if err != nil || c.driversDir != "/usr/lib/agentos/drivers" || c.socketDir != defaultSocketDir || c.uid != hostUID {
		t.Fatalf("parse = %+v, %v", c, err)
	}
}

func TestRunRefusesAnotherUID(t *testing.T) {
	x := newImage(t)
	x.c.uid = os.Getuid() + 1
	if err := run(context.Background(), x.c); err == nil || !strings.Contains(err.Error(), "peer check") {
		t.Fatalf("run under another uid: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	x.c.uid = os.Getuid()
	if err := run(ctx, x.c); err != nil {
		t.Fatalf("run: %v", err)
	}
}
