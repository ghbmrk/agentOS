package homekit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/clerk"
	"github.com/ghbmrk/agentos/broker/kernel/key"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// REQ: DEV-3, DEV-4, DEV-5, DEV-8, DEV-10, CLK-1, NET-2, A16

const (
	testAddr = "192.168.1.50:51826"
	ctrlSlot = clerk.DeviceSlots + "homekit/controller"
)

// sealedStore is a sealed store holding a fresh controller key, as part b
// keeps it (STO-2, CLK-1).
func sealedStore(t *testing.T, seed []byte) *clerk.Secrets {
	t.Helper()
	k := make([]byte, 32)
	rand.Read(k)
	sl, err := clerk.NewAESSealer(k)
	if err != nil {
		t.Fatal(err)
	}
	s := clerk.NewSecrets(sl, nil)
	put := func(b []byte) error { return s.Put(ctrlSlot, clerk.KindStatic, b) }
	if seed != nil {
		err = put(seed)
	} else {
		err = NewControllerKey(put)
	}
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type bus struct {
	mu     sync.Mutex
	events []Event
	lines  []string
	refuse bool
}

func (b *bus) emit(e Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.refuse {
		return errors.New("bus full")
	}
	b.events = append(b.events, e)
	return nil
}

func (b *bus) log(s string) { b.mu.Lock(); b.lines = append(b.lines, s); b.mu.Unlock() }

func (b *bus) snapshot() ([]Event, []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Event(nil), b.events...), append([]string(nil), b.lines...)
}

type dials struct {
	mu    sync.Mutex
	n     int
	addrs []string
	taps  []*tapConn
	wrap  func(net.Conn) net.Conn
}

// setupKey keys the test's guard pin for testAddr before pair-setup.
var setupKey = sha256.Sum256([]byte("homekit-test-setup-pin"))

// guardFor is a guard whose final connect is connect and that pins testAddr
// as a device, as the host does for the connect step.
func guardFor(t *testing.T, connect func(ctx context.Context, addr string) (net.Conn, error)) *netguard.Policy {
	t.Helper()
	g := netguard.New(netguard.Config{Connect: func(ctx context.Context, _, addr string) (net.Conn, error) { return connect(ctx, addr) }})
	if err := g.SetPins([]netguard.Pin{{Kind: netguard.PinDevice, Addr: netip.MustParseAddrPort(testAddr), Key: setupKey}}); err != nil {
		t.Fatal(err)
	}
	return g
}

// newClerk is a clerk over the sealed store whose dial reaches acc.
func newClerk(t *testing.T, acc *fakeAccessory, b *bus) (*Clerk, *dials) {
	t.Helper()
	kh, err := NewSealedKeyHolder(sealedStore(t, nil).DeviceKey(ctrlSlot))
	if err != nil {
		t.Fatal(err)
	}
	d := &dials{}
	c := &Clerk{Keys: kh, Emit: b.emit, Log: b.log, Guard: guardFor(t, func(ctx context.Context, addr string) (net.Conn, error) {
		tap := acc.connect(t)
		d.mu.Lock()
		d.n++
		d.addrs = append(d.addrs, addr)
		d.taps = append(d.taps, tap)
		wrap := d.wrap
		d.mu.Unlock()
		if wrap != nil {
			return wrap(tap), nil
		}
		return tap, nil
	})}
	return c, d
}

func connectOne(t *testing.T, c *Clerk) *Device {
	t.Helper()
	devs, err := c.Connect(context.Background(), "hall", testAddr, testCode)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(devs) != 1 || devs[0].AID != 1 || !devs[0].Pin.Valid() || devs[0].Name != "hall" {
		t.Fatalf("connect returned %+v", devs)
	}
	return &devs[0]
}

func TestSealedKeyHolderSignsWithoutHoldingTheKey(t *testing.T) {
	seed := []byte("homekit-canary-ctrl-key-sealed01")
	store := sealedStore(t, seed)
	kh, err := NewSealedKeyHolder(store.DeviceKey(ctrlSlot))
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(kh.PublicKey(), priv.Public().(ed25519.PublicKey)) {
		t.Fatal("public key does not match the sealed seed")
	}
	if err := checkPairingID(kh.PairingID()); err != nil || len(kh.PairingID()) != 36 {
		t.Fatalf("pairing id %q: %v", kh.PairingID(), err)
	}
	msg := []byte("pair-verify transcript")
	sig, err := kh.Sign(msg)
	if err != nil || !ed25519.Verify(kh.PublicKey(), msg, sig) {
		t.Fatalf("sign: %v", err)
	}
	// A replaced slot signs nothing under the old public key.
	store.Put(ctrlSlot, clerk.KindStatic, []byte("homekit-canary-ctrl-key-sealed02"))
	if _, err := kh.Sign(msg); err == nil {
		t.Fatal("signed with a replaced key")
	}
	// A slot outside DeviceSlots or of another kind gives no holder.
	store.Put("mail/x", clerk.KindStatic, seed)
	if _, err := NewSealedKeyHolder(store.DeviceKey("mail/x")); err == nil {
		t.Fatal("holder over a mail slot")
	}
	if _, err := NewSealedKeyHolder(store.DeviceKey(clerk.DeviceSlots + "missing")); err == nil {
		t.Fatal("holder over a missing slot")
	}
}

func TestConnectPinsAndOpensThermostat(t *testing.T) {
	acc := newFakeAccessory(t)
	b := &bus{}
	c, d := newClerk(t, acc, b)
	dev := connectOne(t, c)
	if !bytes.Equal(dev.Pin.LTPK, acc.ltsk.Public().(ed25519.PublicKey)) || dev.Pin.AccessoryID != acc.id {
		t.Fatal("pinned the wrong key")
	}
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	acc.mu.Lock()
	subs := len(acc.subs)
	acc.mu.Unlock()
	if subs != 7 {
		t.Fatalf("subscribed to %d characteristics, want every ev one (7)", subs)
	}
	n, err := l.Poll()
	if err != nil || n != 7 {
		t.Fatalf("poll emitted %d: %v", n, err)
	}
	if err := l.Write(CharTargetTemperature, 22.5); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(CharTargetTemperature, 99.0); !errors.Is(err, ErrRefused) {
		t.Fatalf("out-of-range write: %v", err)
	}
	if err := l.Write("FFFF", 1); !errors.Is(err, ErrRefused) {
		t.Fatalf("unresolved write: %v", err)
	}
	events, _ := b.snapshot()
	for _, e := range events {
		if e.Device != "hall" || e.Label != "private" {
			t.Fatalf("event %+v", e)
		}
		switch e.Value.(type) {
		case bool, float64:
		default:
			t.Fatalf("event carries %T", e.Value)
		}
	}
	for _, a := range d.addrs {
		if a != testAddr {
			t.Fatalf("dialed %q", a)
		}
	}
}

func TestConnectWithWrongCodePinsNothing(t *testing.T) {
	acc := newFakeAccessory(t)
	b := &bus{}
	c, d := newClerk(t, acc, b)
	devs, err := c.Connect(context.Background(), "hall", testAddr, "111-22-334")
	if !errors.Is(err, ErrAuthentication) || devs != nil {
		t.Fatalf("wrong code: %v %+v", err, devs)
	}
	if d.n != 1 || acc.tries != 1 || len(acc.ctrls) != 0 {
		t.Fatalf("%d dials, %d tries, %d controllers: want one attempt and nothing paired", d.n, acc.tries, len(acc.ctrls))
	}
}

func TestIdentityMismatchTurnsDeviceOff(t *testing.T) {
	acc := newFakeAccessory(t)
	b := &bus{}
	c, d := newClerk(t, acc, b)
	dev := connectOne(t, c)
	_, spoof, _ := ed25519.GenerateKey(rand.Reader)
	acc.mu.Lock()
	acc.verifyKey = spoof
	before := acc.sessReqs
	acc.mu.Unlock()
	if _, err := c.Open(context.Background(), dev); !errors.Is(err, ErrIdentity) {
		t.Fatalf("spoofed accessory: %v", err)
	}
	if !dev.Off {
		t.Fatal("device not turned off")
	}
	acc.mu.Lock()
	after := acc.sessReqs
	acc.mu.Unlock()
	if after != before {
		t.Fatal("the spoofed accessory was read or written")
	}
	_, lines := b.snapshot()
	if !strings.Contains(strings.Join(lines, "\n"), "KRN-7 device hall off") {
		t.Fatalf("no KRN-7 line in %q", lines)
	}
	n := d.n
	acc.mu.Lock()
	acc.verifyKey = acc.ltsk
	acc.mu.Unlock()
	if _, err := c.Open(context.Background(), dev); !errors.Is(err, ErrDeviceOff) {
		t.Fatalf("off device opened: %v", err)
	}
	if d.n != n {
		t.Fatal("an off device was dialed")
	}
}

func TestOnlyLocalAddressesAreDialed(t *testing.T) {
	acc := newFakeAccessory(t)
	c, d := newClerk(t, acc, &bus{})
	for _, addr := range []string{"8.8.8.8:51826", "thermostat.local:51826", "127.0.0.1:51826", "192.168.1.50",
		"0.0.0.0:51826", "224.0.0.251:5353", "[2001:db8::1]:51826", "192.168.1.50:0", ""} {
		if _, err := c.Connect(context.Background(), "hall", addr, testCode); !errors.Is(err, ErrRefused) {
			t.Fatalf("%q: %v", addr, err)
		}
		dev := &Device{Name: "hall", Addr: addr, AID: 1}
		if _, err := c.Open(context.Background(), dev); !errors.Is(err, ErrRefused) {
			t.Fatalf("open %q: %v", addr, err)
		}
	}
	if d.n != 0 {
		t.Fatalf("dialed %d times", d.n)
	}
	for _, addr := range []string{"10.0.0.7:51826", "172.16.0.9:80", "[fe80::1%eth0]:51826", "[fd00::5]:51826"} {
		if err := checkAddr(addr); err != nil {
			t.Fatalf("%q refused: %v", addr, err)
		}
	}
}

func TestHungAccessoryTimesOut(t *testing.T) {
	// A peer that never answers: pair-setup ends at the clerk's timeout.
	b := &bus{}
	kh, _ := NewSealedKeyHolder(sealedStore(t, nil).DeviceKey(ctrlSlot))
	var peers []net.Conn
	c := &Clerk{Keys: kh, Emit: b.emit, Timeout: 50 * time.Millisecond, Guard: guardFor(t, func(context.Context, string) (net.Conn, error) {
		a, p := net.Pipe()
		peers = append(peers, p)
		t.Cleanup(func() { a.Close(); p.Close() })
		return a, nil
	})}
	start := time.Now()
	if _, err := c.Connect(context.Background(), "hall", testAddr, testCode); err == nil {
		t.Fatal("connect to a silent peer succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("connect took %v", time.Since(start))
	}

	// A paired accessory that stops answering: Poll ends at the timeout,
	// and Close ends a blocked read at once.
	acc := newFakeAccessory(t)
	c2, _ := newClerk(t, acc, b)
	dev := connectOne(t, c2)
	l, err := c2.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	hang := make(chan struct{})
	defer close(hang)
	acc.mu.Lock()
	acc.hang = hang
	acc.mu.Unlock()
	c2.Timeout = 50 * time.Millisecond
	start = time.Now()
	if _, err := l.Poll(); err == nil {
		t.Fatal("poll of a hung accessory succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("poll took %v", time.Since(start))
	}

	l2, err := (&Clerk{Keys: c2.Keys, Guard: c2.Guard, Emit: b.emit}).Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := l2.s.Read(ID{1, 11}); done <- err }()
	time.Sleep(20 * time.Millisecond)
	l2.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked read succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not end a blocked read")
	}
}

func TestEventHandlerMayCallBackIntoSession(t *testing.T) {
	acc := newFakeAccessory(t)
	kh := newHolder(t)
	var s *Session
	var mu sync.Mutex
	var found []Characteristic
	opt := Options{OnEvent: func(vs []Value) {
		// Calling back into the session deadlocked while OnEvent ran
		// under the session's lock (#3325 item 1).
		ch, ok := s.Characteristic(vs[0].ID)
		mu.Lock()
		if ok {
			found = append(found, ch)
		}
		mu.Unlock()
	}}
	_, s, _ = pairAndVerify(t, acc, kh, opt)
	acc.mu.Lock()
	acc.eventsOn = true
	acc.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := s.Read(ID{1, 12}); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("event handler calling the session deadlocked")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(found) != 1 || found[0].Type != CharCurrentTemperature {
		t.Fatalf("handler saw %+v", found)
	}
}

// bridgeJSON is a bridge exposing two thermostats, aid 1 and aid 2.
func bridgeJSON() string {
	one := strings.TrimSuffix(strings.TrimPrefix(thermostatJSON, `{"accessories":[`), `]}`)
	two := strings.Replace(one, `{"aid":1,`, `{"aid":2,`, 1)
	return `{"accessories":[` + one + "," + two + `]}`
}

func TestBridgeThermostatsResolveByAID(t *testing.T) {
	acc := newFakeAccessory(t)
	acc.accJSON = bridgeJSON()
	for id, v := range acc.values {
		acc.values[ID{2, id.IID}] = v
	}
	acc.values[ID{2, 11}] = 30.0
	b := &bus{}
	c, _ := newClerk(t, acc, b)
	devs, err := c.Connect(context.Background(), "hall", testAddr, testCode)
	if err != nil || len(devs) != 2 || devs[0].AID != 1 || devs[1].AID != 2 || devs[1].Name != "hall-2" {
		t.Fatalf("bridge connect: %+v %v", devs, err)
	}
	l, err := c.Open(context.Background(), &devs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if a, ok := l.s.Find(1, ServiceThermostat, CharCurrentTemperature); !ok || a.AID != 1 {
		t.Fatal("aid 1 not found")
	}
	if a, ok := l.s.Find(2, ServiceThermostat, CharCurrentTemperature); !ok || a.AID != 2 {
		t.Fatal("aid 2 not found")
	}
	if err := l.Write(CharTargetTemperature, 23.0); err != nil {
		t.Fatal(err)
	}
	acc.mu.Lock()
	w := acc.writes[len(acc.writes)-1]
	acc.mu.Unlock()
	if !strings.Contains(w, `"aid":1`) {
		t.Fatalf("write went to %s", w)
	}
	// Values of the other thermostat, of another service and text values
	// never leave as this device's.
	l.emit([]Value{{ID{2, 11}, 30.0}, {ID{1, 2}, 31.0}, {ID{1, 12}, "text"}, {ID{1, 11}, 20.5}})
	events, _ := b.snapshot()
	for _, e := range events {
		if e.Value != 20.5 {
			t.Fatalf("emitted %+v", e)
		}
	}
	if len(events) != 1 {
		t.Fatalf("%d events, want 1", len(events))
	}
}

func TestFindRefusesAmbiguousService(t *testing.T) {
	acc := newFakeAccessory(t)
	// Accessory 1 with a second thermostat service (iids 28 to 35).
	i := strings.Index(thermostatJSON, `{"iid":8,`)
	svc := thermostatJSON[i : len(thermostatJSON)-len(`]}]}`)]
	second := regexp.MustCompile(`"iid":(\d+)`).ReplaceAllStringFunc(svc, func(m string) string {
		n, _ := strconv.Atoi(m[len(`"iid":`):])
		return fmt.Sprintf(`"iid":%d`, n+20)
	})
	acc.accJSON = thermostatJSON[:len(thermostatJSON)-len(`]}]}`)] + "," + second + `]}]}`
	_, s, _ := pairAndVerify(t, acc, newHolder(t), Options{})
	if len(s.Of(1, ServiceThermostat)) != 14 {
		t.Fatalf("resolved %d thermostat characteristics, want 14", len(s.Of(1, ServiceThermostat)))
	}
	if c, ok := s.Find(1, ServiceThermostat, CharTargetTemperature); ok {
		t.Fatalf("ambiguous find returned %+v", c)
	}
}

func TestOwnerConfirmsBounds(t *testing.T) {
	acc := newFakeAccessory(t)
	c, _ := newClerk(t, acc, &bus{})
	dev := connectOne(t, c)
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	row := ClassFor(ServiceThermostat, CharTargetTemperature)
	if v := row.WriteVerb(20, dev.Bounds[CharTargetTemperature]); v != key.ActuatePhysical {
		t.Fatalf("unconfirmed bounds give %s", v)
	}
	if err := l.ConfirmBounds(CharTargetTemperature, 18, 23); err != nil {
		t.Fatal(err)
	}
	if v := row.WriteVerb(20, dev.Bounds[CharTargetTemperature]); v != key.Actuate {
		t.Fatalf("inside confirmed bounds gives %s", v)
	}
	if v := row.WriteVerb(24, dev.Bounds[CharTargetTemperature]); v != key.ActuatePhysical {
		t.Fatalf("outside confirmed bounds gives %s", v)
	}
	for _, bad := range []struct {
		typ    string
		lo, hi float64
	}{
		{CharTargetHeatingCoolingState, 0, 1}, // mode is always actuate-physical
		{CharTemperatureDisplayUnits, 0, 1},
		{CharCurrentTemperature, 0, 30},
		{CharTargetTemperature, 5, 20},  // below the declared minimum 10
		{CharTargetTemperature, 20, 40}, // above the declared maximum 38
		{CharTargetTemperature, 23, 18},
		{"FFFF", 0, 1},
	} {
		if err := l.ConfirmBounds(bad.typ, bad.lo, bad.hi); !errors.Is(err, ErrRefused) {
			t.Fatalf("bounds %+v: %v", bad, err)
		}
	}
	if len(dev.Bounds) != 1 {
		t.Fatalf("bounds %+v", dev.Bounds)
	}
}

func TestBusRefusalIsCounted(t *testing.T) {
	acc := newFakeAccessory(t)
	b := &bus{}
	c, _ := newClerk(t, acc, b)
	dev := connectOne(t, c)
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	b.mu.Lock()
	b.refuse = true
	b.mu.Unlock()
	if n, err := l.Poll(); err != nil || n != 0 || l.Refused() != 7 {
		t.Fatalf("poll sent %d, refused %d: %v", n, l.Refused(), err)
	}
}

func TestControllerKeyNeverLeavesClerk(t *testing.T) {
	seed := []byte("homekit-canary-ctrl-key-clerk001")
	kh, err := NewSealedKeyHolder(sealedStore(t, seed).DeviceKey(ctrlSlot))
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	acc := newFakeAccessory(t)
	b := &bus{}
	var taps []*tapConn
	c := &Clerk{Keys: kh, Emit: b.emit, Log: b.log, Guard: guardFor(t, func(context.Context, string) (net.Conn, error) {
		tap := acc.connect(t)
		taps = append(taps, tap)
		return tap, nil
	})}
	var out bytes.Buffer
	note := func(err error) {
		if err != nil {
			fmt.Fprintf(&out, "%v %+v %#v\n", err, err, err)
		}
	}
	_, err = c.Connect(context.Background(), "hall", testAddr, "111-22-334")
	note(err)
	devs, err := c.Connect(context.Background(), "hall", testAddr, testCode)
	if err != nil {
		t.Fatal(err)
	}
	dev := &devs[0]
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	acc.eventsOn = true
	_, err = l.Poll()
	note(err)
	note(l.Write(CharTargetTemperature, 99.0))
	note(l.ConfirmBounds(CharTargetTemperature, 18, 23))
	l.Close()
	_, spoof, _ := ed25519.GenerateKey(rand.Reader)
	acc.verifyKey = spoof
	_, err = c.Open(context.Background(), dev)
	note(err)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%q"} {
		fmt.Fprintf(&out, verb+"\n", kh)
		fmt.Fprintf(&out, verb+"\n", *kh)
		fmt.Fprintf(&out, verb+"\n", c)
		fmt.Fprintf(&out, verb+"\n", l)
		fmt.Fprintf(&out, verb+"\n", dev)
	}
	events, lines := b.snapshot()
	fmt.Fprintf(&out, "%#v\n%s\n", events, strings.Join(lines, "\n"))
	for _, tap := range taps {
		out.Write(tap.written.Bytes())
	}
	for _, secret := range [][]byte{seed, priv, priv[:32]} {
		for _, form := range [][]byte{secret, []byte(hex.EncodeToString(secret)), []byte(strings.ToUpper(hex.EncodeToString(secret))),
			[]byte(base64.StdEncoding.EncodeToString(secret)), []byte(base64.RawURLEncoding.EncodeToString(secret)), []byte(fmt.Sprint(secret))} {
			if bytes.Contains(out.Bytes(), form) {
				t.Fatalf("controller key canary found in output")
			}
		}
	}
	if len(events) == 0 || len(lines) < 4 || out.Len() < 2000 {
		t.Fatalf("too little output captured (%d events, %d lines, %d bytes)", len(events), len(lines), out.Len())
	}
}

type slowConn struct {
	net.Conn
	slow, stall *atomic.Bool
}

func (s slowConn) Read(p []byte) (int, error) {
	if s.slow.Load() {
		time.Sleep(100 * time.Millisecond)
	}
	return s.Conn.Read(p)
}

// Write swallows bytes while stalled: the accessory never sees the request.
func (s slowConn) Write(p []byte) (int, error) {
	if s.stall.Load() {
		return len(p), nil
	}
	return s.Conn.Write(p)
}

// Concurrent steps each keep their own deadline: Poll finishing must not
// clear the deadline of a Config waiting on a hung accessory (#3335 L3
// probe, /mnt/project-files/builds/2026-10-27-pr3335-concurrent-step-deadline_test.go).
func TestConcurrentStepsAreEachBounded(t *testing.T) {
	acc := newFakeAccessory(t)
	c, d := newClerk(t, acc, &bus{})
	var slow, stall atomic.Bool
	d.wrap = func(cn net.Conn) net.Conn { return slowConn{cn, &slow, &stall} }
	dev := connectOne(t, c)
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c.Timeout = 300 * time.Millisecond
	slow.Store(true)
	aDone := make(chan error, 1)
	go func() { _, err := l.Poll(); aDone <- err }()
	time.Sleep(30 * time.Millisecond)
	bDone := make(chan error, 1)
	go func() { bDone <- l.Config(9999) }()
	time.Sleep(30 * time.Millisecond)
	stall.Store(true)
	slow.Store(false)
	<-aDone
	select {
	case err := <-bDone:
		t.Logf("bounded: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("Config against a hung accessory was not bounded by Timeout: Poll's step cleared its deadline")
	}
}

// infoOnlyJSON is an accessory with no thermostat service.
const infoOnlyJSON = `{"accessories":[{"aid":1,"services":[
 {"iid":1,"type":"3E","characteristics":[{"iid":2,"type":"23","perms":["pr"],"format":"string","value":"Bridge"}]}]}]}`

func TestConnectKeepsThePinWhenResolveFails(t *testing.T) {
	acc := newFakeAccessory(t)
	acc.accJSON = infoOnlyJSON
	c, _ := newClerk(t, acc, &bus{})
	devs, err := c.Connect(context.Background(), "hall", testAddr, testCode)
	if !errors.Is(err, ErrUnresolved) || len(devs) != 1 || !devs[0].Pin.Valid() || devs[0].AID != 0 {
		t.Fatalf("connect after a failed resolve: %+v %v", devs, err)
	}
	d := devs[0]
	if _, err := c.Open(context.Background(), &d); !errors.Is(err, ErrUnresolved) {
		t.Fatalf("open of an unresolved device: %v", err)
	}
	acc.mu.Lock()
	acc.accJSON = ""
	acc.mu.Unlock()
	out, err := c.Resolve(context.Background(), &d)
	if err != nil || len(out) != 1 || out[0].AID != 1 || !bytes.Equal(out[0].Pin.LTPK, d.Pin.LTPK) {
		t.Fatalf("resolve later: %+v %v", out, err)
	}
	l, err := c.Open(context.Background(), &out[0])
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	acc.mu.Lock()
	tries := acc.tries
	acc.mu.Unlock()
	if tries != 1 {
		t.Fatalf("%d pair-setup attempts, want 1", tries)
	}
}

// An Emit hook that writes back to the same Link while an accessory event is
// delivered inside a step (#3335 L3 probe,
// /mnt/project-files/builds/2026-10-27-pr3335-emit-reentry-probe_test.go).
func TestEmitMayCallBackIntoLink(t *testing.T) {
	acc := newFakeAccessory(t)
	c, _ := newClerk(t, acc, &bus{})
	dev := connectOne(t, c)
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c.Timeout = 300 * time.Millisecond
	fired := false
	emitted := 0
	c.Emit = func(e Event) error {
		emitted++
		if !fired {
			fired = true
			l.Write(CharTargetTemperature, 21.0)
		}
		return nil
	}
	acc.mu.Lock()
	acc.eventsOn = true
	acc.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, err := l.Poll(); done <- err }()
	select {
	case err := <-done:
		// Seven read values and the one event the accessory sent first.
		if err != nil || !fired || emitted != 8 {
			t.Fatalf("poll: %v, hook fired: %v, %d emitted", err, fired, emitted)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("deadlock: Emit calling back into the Link during event delivery")
	}
}

func TestDroppedEventsAreCounted(t *testing.T) {
	acc := newFakeAccessory(t)
	c, _ := newClerk(t, acc, &bus{})
	l, err := c.Open(context.Background(), connectOne(t, c))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	vals := make([]Value, maxPending+76)
	for i := range vals {
		vals[i] = Value{ID{1, 11}, 20.0}
	}
	l.onEvent(vals)
	if l.Dropped() != 76 {
		t.Fatalf("link dropped %d, want 76", l.Dropped())
	}
	// The session's own queue counts its drops too.
	l.s.mu.Lock()
	for i := 0; i < maxPending/maxChars+1; i++ {
		l.s.deliver(valuesFor(maxChars))
	}
	l.s.pending = nil
	l.s.mu.Unlock()
	if l.Dropped() != 76+maxChars {
		t.Fatalf("dropped %d, want %d", l.Dropped(), 76+maxChars)
	}
}

func valuesFor(n int) []byte {
	var b strings.Builder
	b.WriteString(`{"characteristics":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"aid":1,"iid":11,"value":20}`)
	}
	b.WriteString(`]}`)
	return []byte(b.String())
}

func TestDialsGoThroughTheGuard(t *testing.T) {
	acc := newFakeAccessory(t)
	c, d := newClerk(t, acc, &bus{})
	// No pin for the address: denied before any connect.
	c.Guard.SetPins(nil)
	if _, err := c.Connect(context.Background(), "hall", testAddr, testCode); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("unpinned address: %v", err)
	}
	// A pin of another kind does not admit a device dial.
	c.Guard.SetPins([]netguard.Pin{{Kind: netguard.PinBackup, Addr: netip.MustParseAddrPort(testAddr), Key: setupKey}})
	if _, err := c.Connect(context.Background(), "hall", testAddr, testCode); !errors.Is(err, netguard.ErrDenied) {
		t.Fatalf("backup pin admitted a device dial: %v", err)
	}
	if d.n != 0 || acc.tries != 0 {
		t.Fatalf("%d connects, %d tries through a refusing guard", d.n, acc.tries)
	}
	// After pairing, the device's own pin is the only one needed.
	c.Guard.SetPins([]netguard.Pin{{Kind: netguard.PinDevice, Addr: netip.MustParseAddrPort(testAddr), Key: setupKey}})
	dev := connectOne(t, c)
	gp, err := dev.GuardPin()
	if err != nil || gp.Kind != netguard.PinDevice || gp.Addr.String() != testAddr || gp.Key != sha256.Sum256(dev.Pin.LTPK) {
		t.Fatalf("guard pin %+v: %v", gp, err)
	}
	c.Guard.SetPins([]netguard.Pin{gp})
	l, err := c.Open(context.Background(), dev)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := (Device{Addr: testAddr}).GuardPin(); !errors.Is(err, ErrRefused) {
		t.Fatalf("guard pin of an unpaired device: %v", err)
	}
	// No guard, no dial.
	c.Guard = nil
	if _, err := c.Open(context.Background(), dev); !errors.Is(err, ErrRefused) {
		t.Fatalf("open with no guard: %v", err)
	}
}

// b2a design point 5: remove-pairing names the box's own pairing ID only,
// over the pinned session; the accessory then refuses pair-verify, and a
// second controller's pairing is untouched.
func TestRemovePairingRemovesOnlyOwn(t *testing.T) {
	acc := newFakeAccessory(t)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	acc.ctrls["00000000-0000-4000-8000-000000000002"] = other
	c, _ := newClerk(t, acc, &bus{})
	d := connectOne(t, c)
	l, err := c.Open(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RemovePairing(); err != nil {
		t.Fatal(err)
	}
	acc.mu.Lock()
	removed, reqs, left := acc.removed, acc.pairings, len(acc.ctrls)
	acc.mu.Unlock()
	if len(reqs) != 1 || string(reqs[0][tlvIdentifier]) != c.Keys.PairingID() || len(removed) != 1 || left != 1 {
		t.Fatalf("removed %q of %d requests; %d controllers left", removed, len(reqs), left)
	}
	if _, err := l.Poll(); err == nil {
		t.Fatal("the link outlived its removed pairing")
	}
	if _, err := c.Open(context.Background(), d); err == nil || errors.Is(err, ErrIdentity) || d.Off {
		t.Fatalf("open after remove-pairing: %v, off %v", err, d.Off)
	}
}

// An accessory that refuses remove-pairing returns its error and still
// ends the link.
func TestRemovePairingRefused(t *testing.T) {
	acc := newFakeAccessory(t)
	c, _ := newClerk(t, acc, &bus{})
	d := connectOne(t, c)
	l, err := c.Open(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	acc.mu.Lock()
	clear(acc.ctrls)
	acc.mu.Unlock()
	if err := l.RemovePairing(); err == nil {
		t.Fatal("a refused remove-pairing succeeded")
	}
	if _, err := l.Poll(); err == nil {
		t.Fatal("the link outlived a refused remove-pairing")
	}
}
