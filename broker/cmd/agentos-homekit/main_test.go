package main

// REQ: DEV-3, DEV-8, DEV-10, CLK-1, KRN-7, A16, CH-6

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/clerk/homekit"
	"github.com/ghbmrk/agentos/broker/clerk/run"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
	"github.com/ghbmrk/agentos/broker/sockets"
)

// Every key here is generated per run and every code is a canary:
// synthetic, never a real credential.

const (
	accAddr  = "192.168.1.50:51826"
	accIP    = "192.168.1.50"
	accPort  = 51826
	accID    = "00:00:5E:00:53:01"
	hkCode   = "111-22-333"
	canaryHK = "11122333"
)

func init() {
	backoff.Min, backoff.Max = time.Millisecond, 5*time.Millisecond
	pollEvery = 5 * time.Millisecond
}

// fakeAcc is one synthetic HomeKit accessory as the fake clerk sees it.
// The protocol itself (SRP, pair-verify, frames, remove-pairing on the
// wire) is clerk/homekit's and tested there against its synthetic
// accessory; this fake keeps homekit.Clerk's contract (HK-host-9).
type fakeAcc struct {
	key       ed25519.PrivateKey // the key pair-verify proves
	paired    bool
	pinned    ed25519.PublicKey // the key pair-setup handed over
	ctrl      string            // the controller ID that paired
	reachable bool
	aids      []uint64
	tries     int
	removed   []string // pairing IDs remove-pairing named
	unresolve bool     // the first resolve after pair-setup fails
	opens     int
	configs   []int
}

// fakeClerk is homekit.Clerk's contract over fakeAccs: every dial goes
// through the host's guard, as the clerk's does.
type fakeClerk struct {
	mu    sync.Mutex
	accs  map[string]*fakeAcc
	guard *netguard.Policy
	kh    homekit.KeyHolder
	emit  func(homekit.Event) error
	dials []string
}

func newAcc(t *testing.T) *fakeAcc {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeAcc{key: sk, reachable: true, aids: []uint64{1}}
}

func (f *fakeClerk) dial(ctx context.Context, addr string) error {
	c, err := f.guard.DialContext(netguard.WithPurpose(ctx, netguard.PurposeDevice), "tcp", addr)
	if err != nil {
		return err
	}
	c.Close()
	f.mu.Lock()
	f.dials = append(f.dials, addr)
	f.mu.Unlock()
	return nil
}

func (f *fakeClerk) acc(addr string) (*fakeAcc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := f.accs[addr]
	if a == nil || !a.reachable {
		return nil, errors.New("fake: connection refused")
	}
	return a, nil
}

func (f *fakeClerk) Connect(ctx context.Context, name, addr, code string) ([]homekit.Device, error) {
	if err := f.dial(ctx, addr); err != nil {
		return nil, err
	}
	a, err := f.acc(addr)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	a.tries++
	switch {
	case a.paired:
		f.mu.Unlock()
		return nil, homekit.ErrUnavailable
	case strings.ReplaceAll(code, "-", "") != canaryHK:
		f.mu.Unlock()
		return nil, homekit.ErrAuthentication
	}
	a.paired, a.pinned, a.ctrl = true, a.key.Public().(ed25519.PublicKey), f.kh.PairingID()
	d := homekit.Device{Name: name, Addr: addr, Pin: homekit.Pin{AccessoryID: accID, LTPK: a.pinned}}
	unres := a.unresolve
	a.unresolve = false
	f.mu.Unlock()
	if unres {
		return []homekit.Device{d}, fmt.Errorf("%w: fake", homekit.ErrUnresolved)
	}
	return f.Resolve(ctx, &d)
}

// verify is pair-verify's outcome: a key other than the pin turns d off.
func (f *fakeClerk) verify(ctx context.Context, d *homekit.Device) (*fakeAcc, error) {
	if d.Off {
		return nil, homekit.ErrDeviceOff
	}
	if err := f.dial(ctx, d.Addr); err != nil {
		return nil, err
	}
	a, err := f.acc(d.Addr)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	a.opens++
	if !bytes.Equal(a.key.Public().(ed25519.PublicKey), d.Pin.LTPK) {
		d.Off = true
		return nil, homekit.ErrIdentity
	}
	if !a.paired || a.ctrl != f.kh.PairingID() {
		return nil, homekit.ErrAuthentication
	}
	return a, nil
}

func (f *fakeClerk) Resolve(ctx context.Context, d *homekit.Device) ([]homekit.Device, error) {
	a, err := f.verify(ctx, d)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", homekit.ErrUnresolved, err)
	}
	var out []homekit.Device
	for i, aid := range a.aids {
		o := homekit.Device{Name: d.Name, Addr: d.Addr, Pin: d.Pin, AID: aid}
		if i > 0 {
			o.Name = fmt.Sprintf("%s-%d", d.Name, i+1)
		}
		out = append(out, o)
	}
	return out, nil
}

func (f *fakeClerk) Open(ctx context.Context, d *homekit.Device) (link, error) {
	if d.AID == 0 {
		return nil, homekit.ErrUnresolved
	}
	a, err := f.verify(ctx, d)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	k := a.key
	f.mu.Unlock()
	return &fakeLink{f: f, a: a, key: k, d: d}, nil
}

type fakeLink struct {
	f      *fakeClerk
	a      *fakeAcc
	key    ed25519.PrivateKey // the key the session was verified with
	d      *homekit.Device
	mu     sync.Mutex
	closed bool
}

func (l *fakeLink) live() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.f.mu.Lock()
	// A reset accessory (a new key) ends its sessions.
	gone := !l.a.reachable || !l.a.paired || !l.a.key.Equal(l.key)
	l.f.mu.Unlock()
	if l.closed || gone {
		l.closed = true
		return homekit.ErrClosed
	}
	return nil
}

func (l *fakeLink) Poll() (int, error) {
	if err := l.live(); err != nil {
		return 0, err
	}
	for _, c := range []string{homekit.CharCurrentTemperature, homekit.CharTargetTemperature} {
		l.f.emit(homekit.Event{Device: l.d.Name, Label: homekit.Label, Characteristic: c, Value: 20.5})
	}
	return 2, nil
}

func (l *fakeLink) Config(c int) error {
	if err := l.live(); err != nil {
		return err
	}
	l.f.mu.Lock()
	l.a.configs = append(l.a.configs, c)
	l.f.mu.Unlock()
	return nil
}

// ConfirmBounds keeps Link.ConfirmBounds's contract: setpoints only,
// inside the declared range (10 to 38 °C here), recorded on the Device.
func (l *fakeLink) ConfirmBounds(typ string, lo, hi float64) error {
	if homekit.ClassFor(homekit.ServiceThermostat, typ).InBounds == "" || lo < 10 || hi > 38 || lo > hi {
		return homekit.ErrRefused
	}
	if l.d.Bounds == nil {
		l.d.Bounds = map[string]homekit.Bounds{}
	}
	l.d.Bounds[typ] = homekit.Bounds{Min: lo, Max: hi, Confirmed: true}
	return nil
}

func (l *fakeLink) RemovePairing() error {
	defer l.Close()
	if err := l.live(); err != nil {
		return err
	}
	l.f.mu.Lock()
	defer l.f.mu.Unlock()
	l.a.removed = append(l.a.removed, l.f.kh.PairingID())
	l.a.paired = false
	return nil
}

func (l *fakeLink) Close() error { l.mu.Lock(); l.closed = true; l.mu.Unlock(); return nil }
func (l *fakeLink) Dropped() int { return 0 }
func (l *fakeLink) Refused() int { return 0 }

type lines struct {
	mu sync.Mutex
	l  []string
}

func (l *lines) add(s string) { l.mu.Lock(); l.l = append(l.l, s); l.mu.Unlock() }
func (l *lines) all() string  { l.mu.Lock(); defer l.mu.Unlock(); return strings.Join(l.l, "\n") }

// box is one HomeKit clerk directory with a host booted on it and the
// accessories it can reach.
type box struct {
	t      *testing.T
	dir    string
	sealer clerk.Sealer
	seed   []byte
	accs   map[string]*fakeAcc
	h      *host
	f      *fakeClerk
	log    *lines
	cancel context.CancelFunc
	done   chan struct{}
}

func newBox(t *testing.T) *box {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "homekit")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	sk := make([]byte, 32)
	rand.Read(sk)
	sealer, err := clerk.NewAESSealer(sk)
	if err != nil {
		t.Fatal(err)
	}
	b := &box{t: t, dir: dir, sealer: sealer, accs: map[string]*fakeAcc{accAddr: newAcc(t)}}
	// The canary controller seed (A16), put in the slot before the first
	// start as the host's own first start would.
	b.seed = make([]byte, 32)
	rand.Read(b.seed)
	sec, err := run.OpenSecrets(dir, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if err := sec.Put(ctrlSlot, clerk.KindStatic, bytes.Clone(b.seed)); err != nil {
		t.Fatal(err)
	}
	b.boot()
	t.Cleanup(b.halt)
	return b
}

func (b *box) connectFn(context.Context, string, string) (net.Conn, error) {
	c, s := net.Pipe()
	s.Close()
	return c, nil
}

// boot starts a host on the box's directory, as the process does at start.
func (b *box) boot() {
	b.t.Helper()
	if err := b.bootErr(); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) bootErr() error {
	sec, err := run.OpenSecrets(b.dir, b.sealer)
	if err != nil {
		return err
	}
	b.log = &lines{}
	b.h, err = newHostWith(b.dir, sec, b.connectFn, b.log.add, func(g *netguard.Policy, kh homekit.KeyHolder, emit func(homekit.Event) error) pairer {
		b.f = &fakeClerk{accs: b.accs, guard: g, kh: kh, emit: emit}
		return b.f
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := b.h.start(ctx); err != nil {
		cancel()
		return err
	}
	b.cancel, b.done = cancel, make(chan struct{})
	go func() { b.h.tick(ctx, time.Hour); close(b.done) }()
	return nil
}

func (b *box) halt() {
	if b.cancel == nil {
		return
	}
	b.cancel()
	<-b.done
	b.cancel = nil
}

func (b *box) restart() { b.halt(); b.boot() }

func (b *box) list(sf uint8) {
	b.t.Helper()
	if err := b.h.setListed([]listed{{Device: "enf-dev-7", Addr: accIP, Port: accPort, ID: accID, C: 1, SF: sf}}); err != nil {
		b.t.Fatal(err)
	}
}

func (b *box) acc() *fakeAcc { return b.accs[accAddr] }

// with runs fn on the accessory at addr under the fake clerk's lock.
func (b *box) with(addr string, fn func(a *fakeAcc)) {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	fn(b.accs[addr])
}

// get reads one accessory field under the lock.
func get[T any](b *box, fn func(a *fakeAcc) T) T {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	return fn(b.accs[accAddr])
}

func (b *box) dials() int {
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	return len(b.f.dials)
}

func (b *box) stateOf(name string) string {
	for _, d := range b.h.status().Devices {
		if d.Name == name {
			return d.State
		}
	}
	return ""
}

func (b *box) file() string {
	raw, err := os.ReadFile(filepath.Join(b.dir, stateName))
	if err != nil {
		b.t.Fatal(err)
	}
	return string(raw)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(8 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Design point 3: only a listed accessory whose sf says unpaired is
// connected, and a refusal comes before any dial.
func TestConnectOnlyListed(t *testing.T) {
	b := newBox(t)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); !errors.Is(err, errNotListed) {
		t.Fatalf("an unlisted accessory: %v", err)
	}
	b.list(0)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); !errors.Is(err, errPaired) {
		t.Fatalf("an accessory listed as paired: %v", err)
	}
	if err := b.h.connect("hall", "enf-dev-8", hkCode); !errors.Is(err, errNotListed) {
		t.Fatalf("another device ID: %v", err)
	}
	if n, tries := b.dials(), get(b, func(a *fakeAcc) int { return a.tries }); n != 0 || tries != 0 {
		t.Fatalf("%d dials, %d tries before a listed, unpaired accessory", n, tries)
	}
	if err := b.h.setListed([]listed{{Device: "enf-dev-7", Addr: "203.0.113.5", Port: accPort, ID: accID, C: 1, SF: 1}}); !errors.Is(err, errArgs) {
		t.Fatalf("a listing off the home network: %v", err)
	}
}

// Connect by code pins the key, swaps the setup pin for GuardPin, and
// writes the device to homekit.json without the code or key material.
func TestConnectPinsAndSaves(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", "000-00-000"); !errors.Is(err, errCode) {
		t.Fatalf("a wrong code: %v", err)
	}
	if tries, paired := get(b, func(a *fakeAcc) int { return a.tries }), get(b, func(a *fakeAcc) bool { return a.paired }); tries != 1 || paired {
		t.Fatalf("a wrong code: %d tries, paired %v", tries, paired)
	}
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the link to open", func() bool { return b.stateOf("hall") == "open" })
	pub := get(b, func(a *fakeAcc) ed25519.PublicKey { return a.key.Public().(ed25519.PublicKey) })
	f := b.file()
	if !strings.Contains(f, hex.EncodeToString(pub)) || strings.Contains(f, canaryHK) || strings.Contains(f, hkCode) {
		t.Fatalf("devices file: %s", f)
	}
	// The setup pin is gone: the guard pins the address by the accessory
	// key's hash only, and the wrong code's attempt left no pin behind.
	want, _ := b.h.devs[0].dev.GuardPin()
	b.h.mu.Lock()
	pins := b.h.pinned
	b.h.mu.Unlock()
	if len(pins) != 1 || pins[0] != want || pins[0].Key == b.h.setupKey {
		t.Fatalf("pins after connect: %+v", pins)
	}
	if err := b.f.guard.Check(netguard.WithPurpose(context.Background(), netguard.PurposeDevice), netip.MustParseAddr("192.168.1.51"), accPort, "tcp"); err == nil {
		t.Fatal("an address no device is paired at is reachable")
	}
	if err := b.h.connect("hall", "enf-dev-7", hkCode); !errors.Is(err, errExists) {
		t.Fatalf("a name in use: %v", err)
	}
}

// Design point 4: after a restart every device not off reopens by
// pair-verify and emits polled values; a device that is off is not dialed.
func TestRestartReopensPinnedDevices(t *testing.T) {
	b := newBox(t)
	b.accs["192.168.1.51:51826"] = newAcc(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	if err := b.h.setListed([]listed{{Device: "enf-dev-9", Addr: "192.168.1.51", Port: accPort, ID: "00:00:5E:00:53:02", C: 1, SF: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := b.h.connect("den", "enf-dev-9", hkCode); err != nil {
		t.Fatal(err)
	}
	// den goes off by a key change, so its file record is off.
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	b.with("192.168.1.51:51826", func(a *fakeAcc) { a.key = sk })
	waitFor(t, "den off", func() bool { return b.stateOf("den") == "off" })
	b.restart()
	waitFor(t, "values after the restart", func() bool { return b.h.events.stats("hall").sent > 0 })
	if b.stateOf("den") != "off" {
		t.Fatalf("den after the restart: %s", b.stateOf("den"))
	}
	b.f.mu.Lock()
	defer b.f.mu.Unlock()
	for _, a := range b.f.dials {
		if a == "192.168.1.51:51826" {
			t.Fatal("a device that is off was dialed after the restart")
		}
	}
}

// Design point 4: a malformed file is refused whole and nothing is dialed;
// the process refuses it before it reads its key.
func TestMalformedDevicesFileRefused(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	b.halt()
	var st state
	json.Unmarshal([]byte(b.file()), &st)
	st.Devices = append(st.Devices, record{Name: "den", Addr: "8.8.8.8:51826", AccessoryID: accID, Key: st.Devices[0].Key, AID: 1})
	raw, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(b.dir, stateName), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	before := b.acc().opens // the host is halted: no runner holds the lock
	if err := b.bootErr(); !errors.Is(err, errState) {
		t.Fatalf("a malformed file: %v", err)
	}
	if b.acc().opens != before {
		t.Fatal("a device was dialed from a refused file")
	}
	// The process: the refusal comes before the key hand-off is read (a
	// closed descriptor would refuse otherwise).
	kf, _ := os.Open(os.DevNull)
	kf.Close()
	err := start([]string{"-dir", b.dir, "-owner-sock", filepath.Join(t.TempDir(), "s"), "-owner-uid", "0"}, &bytes.Buffer{}, kf)
	if !errors.Is(err, errState) {
		t.Fatalf("start with a malformed file: %v", err)
	}
	for _, bad := range []string{`{"devices":[{"name":"hall"}]}`, `{"devices":[]`, `{"devices":[],"extra":` + strings.Repeat("1", maxState) + `}`} {
		os.WriteFile(filepath.Join(b.dir, stateName), []byte(bad), 0o600)
		if _, _, err := load(b.dir); !errors.Is(err, errState) {
			t.Fatalf("load %.40q: %v", bad, err)
		}
	}
}

// HK-18: a spoofed key at restart turns the device off with a KRN-7 line,
// and the file records it.
func TestKeyMismatchAfterRestartTurnsOff(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	b.halt()
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	b.acc().key = sk // halted: nothing else holds the accessory
	b.boot()
	waitFor(t, "hall off", func() bool { return b.stateOf("hall") == "off" })
	if !strings.Contains(b.log.all(), "hall: KRN-7 off") {
		t.Fatalf("no KRN-7 line:\n%s", b.log.all())
	}
	waitFor(t, "the file to record off", func() bool { return strings.Contains(b.file(), `"off":true`) })
	if b.h.events.stats("hall").sent != 0 {
		t.Fatal("values were read from a spoofed accessory")
	}
	opens := get(b, func(a *fakeAcc) int { return a.opens })
	b.restart()
	time.Sleep(20 * time.Millisecond)
	if get(b, func(a *fakeAcc) int { return a.opens }) != opens {
		t.Fatal("a device that is off was dialed again")
	}
}

// Design point 5: re-pin by code pins the new key, and the old key is
// refused.
func TestRepin(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	oldKey := get(b, func(a *fakeAcc) ed25519.PrivateKey { return a.key })
	// The owner resets HomeKit on the thermostat: a new key, unpaired.
	_, sk, _ := ed25519.GenerateKey(rand.Reader)
	b.f.mu.Lock()
	b.acc().key, b.acc().paired = sk, false
	b.f.mu.Unlock()
	waitFor(t, "hall off", func() bool { return b.stateOf("hall") == "off" })
	b.list(0)
	if err := b.h.repin("hall", "enf-dev-7", hkCode); !errors.Is(err, errPaired) {
		t.Fatalf("a re-pin to an accessory listed as paired: %v", err)
	}
	b.list(1)
	if err := b.h.repin("hall", "enf-dev-7", "000-00-000"); !errors.Is(err, errCode) {
		t.Fatalf("a re-pin with a wrong code: %v", err)
	}
	if err := b.h.repin("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "hall open on the new key", func() bool { return b.stateOf("hall") == "open" })
	if !strings.Contains(b.file(), hex.EncodeToString(sk.Public().(ed25519.PublicKey))) || strings.Contains(b.file(), hex.EncodeToString(oldKey.Public().(ed25519.PublicKey))) {
		t.Fatalf("file after the re-pin: %s", b.file())
	}
	// The old key is refused: an accessory proving it turns hall off.
	b.f.mu.Lock()
	b.acc().key = oldKey
	b.f.mu.Unlock()
	b.restart()
	waitFor(t, "the old key refused", func() bool { return b.stateOf("hall") == "off" })
}

// Design point 5: disconnect sends remove-pairing for the box's own
// pairing only, drops the device from the file, then erases its state.
// With the accessory unreachable, the device still goes, and the answer
// says to reset HomeKit.
func TestDisconnectRemovesPairing(t *testing.T) {
	b := newBox(t)
	b.list(1)
	b.with(accAddr, func(a *fakeAcc) { a.aids = []uint64{1, 2} })
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "values", func() bool { return b.h.events.stats("hall-2").sent > 0 })
	removed, err := b.h.disconnect("hall-2")
	if err != nil || !removed {
		t.Fatalf("disconnect: %v, removed %v", err, removed)
	}
	if r := get(b, func(a *fakeAcc) []string { return a.removed }); len(r) != 1 || r[0] != b.h.pairing {
		t.Fatalf("remove-pairing named %q, not the box's own %q", r, b.h.pairing)
	}
	// Both thermostats behind the one pairing go.
	if f := b.file(); strings.Contains(f, "hall") || len(b.h.status().Devices) != 0 || b.h.events.stats("hall-2").sent != 0 {
		t.Fatalf("after disconnect: %s %+v", f, b.h.status().Devices)
	}

	b.list(1)
	if err := b.h.connect("den", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	b.f.mu.Lock()
	b.acc().reachable = false
	b.f.mu.Unlock()
	removed, err = b.h.disconnect("den")
	if err != nil || removed || strings.Contains(b.file(), "den") {
		t.Fatalf("disconnect of an unreachable accessory: %v, removed %v, file %s", err, removed, b.file())
	}
	if _, err := b.h.disconnect("den"); !errors.Is(err, errUnknown) {
		t.Fatalf("a second disconnect: %v", err)
	}
}

// Design point 6: before homekit/bounds every setpoint's class is
// `actuate-physical`; after it, in-bounds values are `actuate`, and the
// bounds survive a restart.
func TestBoundsNeedConfirm(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the link to open", func() bool { return b.stateOf("hall") == "open" })
	for _, c := range []string{homekit.CharTargetTemperature, homekit.CharHeatingThreshold, homekit.CharCoolingThreshold} {
		if v, _ := b.h.verb("hall", c, 21); v != string(key.ActuatePhysical) {
			t.Fatalf("%s before bounds: %s", c, v)
		}
	}
	for _, bad := range []struct {
		c      string
		lo, hi float64
	}{{homekit.CharTargetHeatingCoolingState, 0, 3}, {homekit.CharTargetTemperature, 22, 18}, {homekit.CharTargetTemperature, 5, 30}} {
		if err := b.h.bounds("hall", bad.c, bad.lo, bad.hi); !errors.Is(err, errBounds) {
			t.Fatalf("bounds %+v: %v", bad, err)
		}
	}
	if err := b.h.bounds("hall", homekit.CharTargetTemperature, 18, 23); err != nil {
		t.Fatal(err)
	}
	b.restart()
	if v, _ := b.h.verb("hall", homekit.CharTargetTemperature, 21); v != string(key.Actuate) {
		t.Fatalf("in bounds after a restart: %s", v)
	}
	if v, _ := b.h.verb("hall", homekit.CharTargetTemperature, 25); v != string(key.ActuatePhysical) {
		t.Fatalf("out of bounds: %s", v)
	}
	if v, _ := b.h.verb("hall", homekit.CharHeatingThreshold, 21); v != string(key.ActuatePhysical) {
		t.Fatalf("another setpoint: %s", v)
	}
	if v, _ := b.h.verb("hall", homekit.CharTargetHeatingCoolingState, 1); v != string(key.ActuatePhysical) {
		t.Fatalf("the mode: %s", v)
	}
}

// verb is the class a write of v to char on the named device needs now,
// under its confirmed bounds (DEV-4, DEV-5), as the kernel will decide
// with the same rows (b2d).
func (h *host) verb(name, char string, v float64) (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.find(name)
	if e == nil {
		return "", false
	}
	return string(homekit.ClassFor(homekit.ServiceThermostat, char).WriteVerb(v, e.dev.Bounds[char])), true
}

// Design point 10: STOP closes every link and refuses every op but status
// and resume, across a restart.
func TestStopClosesLinks(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the link to open", func() bool { return b.stateOf("hall") == "open" })
	if err := b.h.stop(); err != nil {
		t.Fatal(err)
	}
	if s := b.stateOf("hall"); s != "stopped" {
		t.Fatalf("hall after STOP: %s", s)
	}
	for name, args := range map[string]any{
		"homekit/connect": connectArgs{Name: "den", Device: "enf-dev-7", Code: hkCode}, "homekit/bounds": boundsArgs{Name: "hall", Char: "35", Min: 18, Max: 22},
		"homekit/repin": repinArgs{Name: "hall", Device: "enf-dev-7", Code: hkCode}, "homekit/disconnect": nameArgs{Name: "hall"},
		"homekit/listed": listedArgs{},
	} {
		a, _ := json.Marshal(args)
		if _, err := ops[name](b.h, a); !errors.Is(err, errStopped) {
			t.Fatalf("%s during STOP: %v", name, err)
		}
	}
	if _, err := ops["homekit/status"](b.h, nil); err != nil {
		t.Fatal(err)
	}
	b.restart()
	opens := get(b, func(a *fakeAcc) int { return a.opens })
	time.Sleep(20 * time.Millisecond)
	if get(b, func(a *fakeAcc) int { return a.opens }) != opens || b.stateOf("hall") != "stopped" {
		t.Fatal("a link opened after a restart during STOP")
	}
	if _, err := ops["homekit/resume"](b.h, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the link after RESUME", func() bool { return b.stateOf("hall") == "open" })
}

func ownerCall(t *testing.T, sock, op string, args any) (map[string]any, string) {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	a, _ := json.Marshal(args)
	json.NewEncoder(c).Encode(map[string]any{"op": op, "args": json.RawMessage(a)})
	var out map[string]any
	json.NewDecoder(c).Decode(&out)
	e, _ := out["error"].(string)
	return out, e
}

// Design point 2: the owner socket admits only the owner side's uid.
func TestOwnerSocketRefusesOtherUID(t *testing.T) {
	b := newBox(t)
	sock := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := sockets.ListenPeers(sock, os.Getuid()+1)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serve(ln, b.h)
	if out, _ := ownerCall(t, sock, "homekit/status", nil); out != nil {
		t.Fatalf("another uid was answered: %v", out)
	}
}

// Design point 2: a closed table of calls, each strict about its fields;
// STATUS names devices by the owner's name, type and fingerprint.
func TestOwnerSocketClosedTable(t *testing.T) {
	b := newBox(t)
	sock := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := sockets.ListenPeers(sock, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serve(ln, b.h)
	want := []string{"homekit/bounds", "homekit/connect", "homekit/disconnect", "homekit/listed", "homekit/repin", "homekit/resume", "homekit/status", "homekit/stop"}
	if len(ops) != len(want) {
		t.Fatalf("%d ops", len(ops))
	}
	for _, op := range want {
		if ops[op] == nil {
			t.Fatalf("no %s", op)
		}
	}
	if _, e := ownerCall(t, sock, "homekit/listed", listedArgs{Accessories: []listed{{Device: "enf-dev-7", Addr: accIP, Port: accPort, ID: accID, C: 1, SF: 1}}}); e != "" {
		t.Fatal(e)
	}
	if _, e := ownerCall(t, sock, "homekit/connect", connectArgs{Name: "hall", Device: "enf-dev-7", Code: hkCode}); e != "" {
		t.Fatal(e)
	}
	for _, bad := range []struct {
		op   string
		args any
	}{
		{"homekit/write", map[string]any{"Name": "hall", "Char": "35", "Value": 30}},
		{"homekit/add-pairing", nil},
		{"homekit/connect", map[string]any{"Name": "den", "Device": "enf-dev-7", "code": hkCode, "Addr": accAddr}},
		{"homekit/bounds", map[string]any{"Name": "hall", "Char": "35", "Min": 18, "Max": 22, "Extra": 1}},
	} {
		if _, e := ownerCall(t, sock, bad.op, bad.args); e == "" {
			t.Fatalf("%s %v was answered", bad.op, bad.args)
		}
	}
	out, e := ownerCall(t, sock, "homekit/status", nil)
	if e != "" {
		t.Fatal(e)
	}
	res, _ := out["result"].(map[string]any)
	devs, _ := res["devices"].([]any)
	d, _ := devs[0].(map[string]any)
	fp := fingerprint(get(b, func(a *fakeAcc) ed25519.PublicKey { return a.key.Public().(ed25519.PublicKey) }))
	if len(devs) != 1 || d["name"] != "hall" || d["type"] != "thermostat" || d["key"] != fp || res["pairing"] != b.h.pairing {
		t.Fatalf("status: %v", out)
	}
}

// A16: the HomeKit code and the canary controller key appear in no log
// line, file, refusal, event or STATUS answer.
func TestCodeAndKeyNeverLeave(t *testing.T) {
	b := newBox(t)
	b.list(1)
	var refusals []string
	for _, c := range []string{"000-00-000", "12345678x"} {
		if err := b.h.connect("hall", "enf-dev-7", c); err != nil {
			refusals = append(refusals, err.Error())
		}
	}
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		refusals = append(refusals, err.Error())
	}
	waitFor(t, "values", func() bool { return b.h.events.stats("hall").sent > 0 })
	st, _ := json.Marshal(b.h.status())
	var files []string
	filepath.Walk(b.dir, func(p string, fi os.FileInfo, _ error) error {
		if fi != nil && fi.Mode().IsRegular() {
			raw, _ := os.ReadFile(p)
			files = append(files, string(raw))
		}
		return nil
	})
	priv := ed25519.NewKeyFromSeed(b.seed)
	hay := strings.Join(append(append(refusals, b.log.all(), string(st)), files...), "\n")
	for _, needle := range []string{canaryHK, hkCode, "000-00-000", hex.EncodeToString(b.seed), base64.StdEncoding.EncodeToString(b.seed),
		hex.EncodeToString(priv), base64.StdEncoding.EncodeToString(priv)} {
		if strings.Contains(hay, needle) {
			t.Fatalf("%q leaked", needle)
		}
	}
	if bytes.Contains([]byte(strings.Join(files, "")), b.seed) {
		t.Fatal("the seed is in a file in the clear")
	}
	if p := fmt.Sprintf("%+v %#v", b.f.kh, b.f.kh); strings.Contains(p, hex.EncodeToString(b.seed)) || strings.Contains(p, fmt.Sprint(b.seed)) {
		t.Fatal("the key holder prints its key")
	}
}

// Design point 8: a flood of one characteristic is limited and counted,
// and another characteristic still goes out.
func TestEventsLimitedAndCounted(t *testing.T) {
	now := time.Unix(1e9, 0)
	l := newLimiter(limit, func() time.Time { return now })
	for range 100 {
		l.emit(homekit.Event{Device: "hall", Characteristic: homekit.CharCurrentTemperature, Value: 20.0})
	}
	if c := l.stats("hall"); c.sent != limit.Burst || c.limited != 100-limit.Burst {
		t.Fatalf("after a flood: %+v", c)
	}
	l.emit(homekit.Event{Device: "hall", Characteristic: homekit.CharTargetTemperature, Value: 21.0})
	if c := l.stats("hall"); c.sent != limit.Burst+1 {
		t.Fatalf("another characteristic: %+v", c)
	}
	now = now.Add(limit.Window)
	l.Flush()
	if c := l.stats("hall"); c.coalesced != 1 {
		t.Fatalf("the flood's coalesced event: %+v", c)
	}
	l.emit(homekit.Event{Device: "hall", Characteristic: homekit.CharCurrentTemperature, Value: 20.0})
	if c := l.stats("hall"); c.sent != limit.Burst+2 {
		t.Fatalf("a new window: %+v", c)
	}
}

// Design point 3: a paired accessory listed with a new c# re-resolves its
// open link; the same c# does not.
func TestConfigChangeReResolves(t *testing.T) {
	b := newBox(t)
	b.list(1)
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the link to open", func() bool { return b.stateOf("hall") == "open" })
	b.list(0)
	if err := b.h.setListed([]listed{{Device: "enf-dev-7", Addr: accIP, Port: accPort, ID: accID, C: 2}}); err != nil {
		t.Fatal(err)
	}
	b.f.mu.Lock()
	got := b.acc().configs
	b.f.mu.Unlock()
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("config calls: %v", got)
	}
}

// A device paired before its thermostats resolved keeps its pin and is
// resolved by its runner.
func TestUnresolvedKeptAndResolved(t *testing.T) {
	b := newBox(t)
	b.list(1)
	b.with(accAddr, func(a *fakeAcc) { a.unresolve, a.aids = true, []uint64{3, 4} })
	if err := b.h.connect("hall", "enf-dev-7", hkCode); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both thermostats open", func() bool { return b.stateOf("hall") == "open" && b.stateOf("hall-2") == "open" })
	if f := b.file(); !strings.Contains(f, `"aid":3`) || !strings.Contains(f, `"aid":4`) {
		t.Fatalf("file: %s", f)
	}
}

func TestParse(t *testing.T) {
	good := []string{"-dir", "/d", "-owner-sock", "/s", "-owner-uid", "0"}
	if _, err := parse(good, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(good); i += 2 {
		bad := append(append([]string{}, good[:i]...), good[i+2:]...)
		if _, err := parse(bad, &bytes.Buffer{}); err == nil {
			t.Fatalf("parse without %s succeeded", good[i])
		}
	}
	if _, err := parse(append(good, "extra"), &bytes.Buffer{}); err == nil {
		t.Fatal("an extra argument was taken")
	}
}
