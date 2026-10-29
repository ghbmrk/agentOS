package channel

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
	"github.com/ghbmrk/agentos/broker/kernel/key"
)

const rp = "enforcer.home.arpa"

// owner is a WebAuthn ES256 credential that signs as a phone's passkey
// would, as broker/enforcer/policy's tests sign.
type owner struct {
	priv *ecdsa.PrivateKey
}

func (a owner) public() key.PublicKey {
	point, _ := a.priv.PublicKey.Bytes()
	pk, err := key.ES256(rp, point)
	if err != nil {
		panic(err)
	}
	return pk
}

func (a owner) sign(msg []byte) []byte {
	c := key.Challenge(msg)
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(c[:]),
		"origin": "https://" + rp, "crossOrigin": false})
	h := sha256.Sum256([]byte(rp))
	ad := append(h[:], 0x01|0x04, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	m := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, m[:])
	if err != nil {
		panic(err)
	}
	b, err := key.AssertionSig(key.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig})
	if err != nil {
		panic(err)
	}
	return b
}

type memStore struct{ b []byte }

func (m *memStore) Load() ([]byte, error) { return m.b, nil }
func (m *memStore) Save(b []byte) error   { m.b = slices.Clone(b); return nil }

// home is the test household: every class NET-2 Safety devices names, as
// the signed policy records it (ASSUMPTIONS ENF-d-1), and two everyday
// devices.
func home() policy.Document {
	d := policy.Document{Version: 1}
	add := func(id string, everyday bool, s safety) {
		d.Devices = append(d.Devices, policy.Device{ID: id, Network: policy.NetDevices, Everyday: everyday, Class: s.class, Secure: s.secure})
	}
	add("lamp", true, safety{})
	add("tv", true, safety{})
	d.Devices[1].Allow = []string{"ads.example", "cdn.example"}
	d.Devices[1].VendorCloud = true
	add("speaker", true, safety{})
	d.Pairs = []policy.Pair{{A: "speaker", B: "tv"}}
	for id, s := range safetyDevices {
		add(id, false, s)
	}
	d.Standing = []policy.StandingRule{{ID: "plumber", Device: "lock", Action: "keypad-code", FromMS: 0, ToMS: 1 << 50}}
	return d
}

// safety is a safety-list device's class and the secure direction the
// owner named for it, if any.
type safety struct{ class, secure string }

// safetyDevices is one device per NET-2 safety class, with the secure
// direction the owner named for it, if any.
var safetyDevices = map[string]safety{
	"lock":            {policy.ClassLock, SecureLock},
	"valve":           {policy.ClassValve, SecureShut},
	"heater":          {policy.ClassHeater, SecureOff},
	"oven":            {policy.ClassOven, SecureOff},
	"plug":            {policy.ClassPlug, SecureOff},
	"relay":           {policy.ClassRelay, SecureOff},
	"garage":          {policy.ClassGarageDoor, SecureClose},
	"drone":           {policy.ClassDrone, SecureReturn},
	"camera":          {policy.ClassCamera, ""},
	"microphone":      {policy.ClassMicrophone, ""},
	"alarm":           {policy.ClassAlarm, ""},
	"siren":           {policy.ClassSiren, ""},
	"sensor":          {policy.ClassSensor, ""},
	"primary-heating": {policy.ClassPrimaryHeating, ""}, // cannot be named
	"feed-valve":      {policy.ClassFeedValve, ""},      // cannot be named
	"unknown":         {"", ""},
	"unnamed-valve":   {policy.ClassValve, ""},
}

type radio struct {
	mu   sync.Mutex
	done []string
	fail bool
}

func (r *radio) Do(device string, v wire.Verb, level uint8) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return errors.New("radio down")
	}
	r.done = append(r.done, device+" "+verbWords[v])
	return nil
}

func (r *radio) State(device string) ([]byte, error) { return []byte("state of " + device), nil }

func (r *radio) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.done)
}

type alerts struct {
	mu     sync.Mutex
	off    []string
	paused int
	// reenter, if set, runs inside each call, as slice h's alerts will
	// when they send a text back through the channel.
	reenter func()
}

func (a *alerts) SafetyOff(device string, v wire.Verb) {
	a.mu.Lock()
	a.off = append(a.off, device+" "+verbWords[v])
	f := a.reenter
	a.mu.Unlock()
	if f != nil {
		f()
	}
}

func (a *alerts) Paused() {
	a.mu.Lock()
	a.paused++
	f := a.reenter
	a.mu.Unlock()
	if f != nil {
		f()
	}
}

type heads struct{ n int }

func (h *heads) Head(wire.Head) error   { h.n++; return nil }
func (h *heads) Entry(wire.Entry) error { h.n++; return nil }

// rig is one enforcer channel over the real policy engine, with a fake
// radio host, alerts and clock.
type rig struct {
	t       testing.TB
	eng     *policy.Engine
	ch      *Channel
	radio   *radio
	alerts  *alerts
	core    ed25519.PrivateKey
	enf     ed25519.PublicKey
	revoked bool
	answers []uint64

	mu  sync.Mutex
	now time.Time
	log []Event
}

// signedHome is the engine's store with home() signed and applied, made
// once: the owner's key and signature are the slow part.
var signedHome = sync.OnceValues(func() (key.PublicKey, []byte) {
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o := owner{p}
	st := &memStore{}
	eng, err := policy.Open(o.public(), st)
	if err != nil {
		panic(err)
	}
	prop := policy.Proposal{Doc: home(), Diff: []byte("the test household")}
	root, err := prop.Root(o.public())
	if err != nil {
		panic(err)
	}
	if _, err := eng.Propose(prop, o.sign(key.RootMsg(root)), start.UnixMilli()); err != nil {
		panic(err)
	}
	if _, err := eng.Tick(start.Add(time.Hour).UnixMilli()); err != nil {
		panic(err)
	}
	return o.public(), st.b
})

var start = time.Unix(1_800_000_000, 0)

func newRig(t testing.TB, cfg func(*Config)) *rig {
	t.Helper()
	pub, b := signedHome()
	eng, err := policy.Open(pub, &memStore{b: slices.Clone(b)})
	if err != nil {
		t.Fatal(err)
	}
	_, core, _ := ed25519.GenerateKey(nil)
	enfPub, enfPriv, _ := ed25519.GenerateKey(nil)
	r := &rig{t: t, eng: eng, radio: &radio{}, alerts: &alerts{}, core: core, enf: enfPub, now: start.Add(2 * time.Hour)}
	c := Config{
		Core:        core.Public().(ed25519.PublicKey),
		Key:         enfPriv,
		Revoked:     func(k ed25519.PublicKey) bool { r.mu.Lock(); defer r.mu.Unlock(); return r.revoked },
		Policy:      eng,
		Radio:       r.radio,
		Heads:       &heads{},
		Alerts:      r.alerts,
		Fingerprint: func(string) ([wire.HashLen]byte, bool) { return sha256.Sum256([]byte("fp")), true },
		Traffic:     func(d string) ([]byte, error) { return []byte("traffic of " + d), nil },
		Answer:      func(id uint64, _ []byte) { r.answers = append(r.answers, id) },
		Log:         func(e Event) { r.mu.Lock(); r.log = append(r.log, e); r.mu.Unlock() },
		Now:         func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
	}
	if cfg != nil {
		cfg(&c)
	}
	if r.ch, err = New(c); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *rig) advance(d time.Duration) { r.mu.Lock(); r.now = r.now.Add(d); r.mu.Unlock() }

func (r *rig) events() []Event { r.mu.Lock(); defer r.mu.Unlock(); return slices.Clone(r.log) }

// client is the core's end of one connection.
type client struct {
	t    testing.TB
	conn net.Conn
	done chan error
}

var exporter = bytes.Repeat([]byte{0x5a}, wire.ExporterLen)

// dial opens a connection and completes both hellos.
func (r *rig) dial() *client {
	r.t.Helper()
	cl := r.connect()
	h, err := wire.SignHello(wire.RoleCore, r.core, exporter)
	if err != nil {
		r.t.Fatal(err)
	}
	cl.send(h)
	m := cl.recv()
	eh, ok := m.(wire.Hello)
	if !ok || eh.Verify(wire.RoleEnforcer, r.enf, exporter) != nil {
		r.t.Fatalf("enforcer hello: %+v", m)
	}
	return cl
}

// connect opens a connection with no hello sent.
func (r *rig) connect() *client {
	a, b := net.Pipe()
	cl := &client{t: r.t, conn: a, done: make(chan error, 1)}
	go func() { cl.done <- r.ch.Serve(b, exporter); b.Close() }()
	return cl
}

func (cl *client) send(m wire.Msg) {
	cl.t.Helper()
	f, err := wire.Encode(wire.ToEnforcer, m)
	if err != nil {
		cl.t.Fatalf("encode %T: %v", m, err)
	}
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(cl.conn, wire.ToEnforcer, f); err != nil {
		cl.t.Fatalf("write: %v", err)
	}
}

func (cl *client) recv() wire.Msg {
	cl.t.Helper()
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	f, err := wire.ReadFrame(cl.conn, wire.ToCore)
	if err != nil {
		cl.t.Fatalf("read: %v", err)
	}
	m, err := wire.Decode(wire.ToCore, f)
	if err != nil {
		cl.t.Fatalf("decode: %v", err)
	}
	return m
}

// do sends m and returns the reply.
func (cl *client) do(m wire.Msg) wire.Msg {
	cl.t.Helper()
	cl.send(m)
	return cl.recv()
}

// code sends m and returns the result code; a read reply is OK.
func (cl *client) code(m wire.Msg) wire.Code {
	cl.t.Helper()
	switch rep := cl.do(m).(type) {
	case wire.Result:
		return rep.Code
	case wire.ReadReply:
		return wire.OK
	default:
		cl.t.Fatalf("reply %T", rep)
		return 0
	}
}

// closed writes raw bytes and reports whether the enforcer ended the
// connection with no reply.
func (cl *client) closed(raw []byte) bool {
	cl.t.Helper()
	cl.conn.SetDeadline(time.Now().Add(5 * time.Second))
	go cl.conn.Write(raw)
	var b [1]byte
	_, err := cl.conn.Read(b[:])
	if err == nil {
		return false
	}
	select {
	case <-cl.done:
	case <-time.After(5 * time.Second):
		return false
	}
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}

func frameBytes(t Type, p []byte) []byte {
	b := []byte{byte(t), 0, 0, 0, 0}
	n := len(p)
	b[1], b[2], b[3], b[4] = byte(n>>24), byte(n>>16), byte(n>>8), byte(n)
	return append(b, p...)
}

// Type aliases the wire's frame type for frameBytes.
type Type = wire.Type
