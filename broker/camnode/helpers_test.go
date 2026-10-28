package camnode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camnode/se"
	"github.com/ghbmrk/agentos/broker/camnode/se/setest"
	"github.com/ghbmrk/agentos/broker/camwire"
)

// Every key here is generated per run: synthetic, never a real credential.

const testRP = "enforcer.home.arpa"

// passkey answers a WebAuthn get() as a platform passkey does.
type passkey struct{ priv *ecdsa.PrivateKey }

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func point(k *ecdsa.PrivateKey) [camwire.PointLen]byte {
	b, err := k.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	var out [camwire.PointLen]byte
	copy(out[:], b)
	return out
}

func (p passkey) owner() camwire.Owner { return camwire.Owner{RPID: testRP, Point: point(p.priv)} }

func (p passkey) assert(t testing.TB, msg []byte) camwire.Assertion {
	t.Helper()
	rp := sha256.Sum256([]byte(testRP))
	ad := append(rp[:], 0x01|0x04, 0, 0, 0, 0)
	ch := camwire.Challenge(msg)
	cd, err := json.Marshal(map[string]any{
		"type":        "webauthn.get",
		"challenge":   base64.RawURLEncoding.EncodeToString(ch[:]),
		"origin":      "https://" + testRP,
		"crossOrigin": false,
	})
	if err != nil {
		t.Fatal(err)
	}
	cdh := sha256.Sum256(cd)
	h := sha256.Sum256(append(append([]byte{}, ad...), cdh[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, p.priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return camwire.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: sig}
}

// sign encodes b with p's assertion over it.
func (p passkey) sign(t testing.TB, b camwire.Bundle) []byte {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := camwire.SignedBundle{Bundle: enc, Assertion: p.assert(t, enc)}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

var testRanges = Ranges{
	Modes:          []Mode{{1920, 1080, 30}, {1280, 720, 60}},
	MinBitrateKbps: 500,
	MaxBitrateKbps: 8000,
	IR:             true,
	Thermal:        camwire.Shape{Width: 4, Height: 3},
}

var goodSettings = camwire.Settings{Width: 1920, Height: 1080, FPS: 25, BitrateKbps: 4000, IR: camwire.IRAuto, Thermal: true, Stream: true}

// source is a fake camera: a video access unit and a thermal frame in
// turn, and a record of each Apply.
type source struct {
	mu      sync.Mutex
	applied []camwire.Settings
	n       int
}

func (s *source) Apply(set camwire.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, set)
	return nil
}

func (s *source) Applied() []camwire.Settings {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]camwire.Settings{}, s.applied...)
}

func (s *source) Next(ctx context.Context) (camwire.Frame, error) {
	select {
	case <-ctx.Done():
		return camwire.Frame{}, ctx.Err()
	case <-time.After(time.Millisecond):
	}
	s.mu.Lock()
	s.n++
	n := s.n
	s.mu.Unlock()
	if n%2 == 0 {
		th := camwire.AppendThermal(nil, camwire.Thermal{Width: 4, Height: 3, Counter: uint32(n), Samples: make([]byte, 24)})
		return camwire.Frame{Type: camwire.TypeThermal, Payload: th}, nil
	}
	return camwire.Frame{Type: camwire.TypeVideo, Payload: []byte{0, 0, 0, 1, 0x65, byte(n)}}, nil
}

// logs collects the server's log lines.
type logs struct {
	mu    sync.Mutex
	lines []string
}

func (l *logs) log(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}

func (l *logs) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// node is one camera node under test: its element and storage survive a
// restart, as on the board.
type node struct {
	t        *testing.T
	el       se.Element
	dir      Dir
	owner    passkey
	core     *ecdsa.PrivateKey
	enforcer *ecdsa.PrivateKey
	src      *source
	logs     *logs
	now      time.Time
	clock    sync.Mutex

	srv  *Server
	addr string
	l    net.Listener
}

func newNode(t *testing.T) *node {
	return &node{
		t: t, el: setest.NewMemory(), dir: Dir(t.TempDir()),
		owner: passkey{newKey(t)}, core: newKey(t), enforcer: newKey(t),
		now: time.Unix(1000, 0),
	}
}

func (n *node) Now() time.Time {
	n.clock.Lock()
	defer n.clock.Unlock()
	return n.now
}

func (n *node) advance(d time.Duration) {
	n.clock.Lock()
	defer n.clock.Unlock()
	n.now = n.now.Add(d)
}

// boot starts (or restarts) the server on a fresh loopback listener.
func (n *node) boot(button bool) {
	n.t.Helper()
	if n.l != nil {
		n.l.Close()
	}
	n.src, n.logs = &source{}, &logs{}
	srv, err := New(Config{
		Element: n.el, Store: n.dir, Ranges: testRanges, Source: n.src,
		ButtonHeld: button, Log: n.logs.log, Now: n.Now,
	})
	if err != nil {
		n.t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		n.t.Fatal(err)
	}
	n.srv, n.l, n.addr = srv, l, l.Addr().String()
	go srv.Serve(l)
	n.t.Cleanup(func() { l.Close() })
}

func (n *node) fingerprint() [32]byte {
	fp, err := se.Fingerprint(n.el)
	if err != nil {
		n.t.Fatal(err)
	}
	return fp
}

func (n *node) devicePoint() [camwire.PointLen]byte {
	p, err := n.el.Public()
	if err != nil {
		n.t.Fatal(err)
	}
	return p
}

// bundle is a bundle for this node at counter c with settings s.
func (n *node) bundle(c uint64, s camwire.Settings) camwire.Bundle {
	return camwire.Bundle{
		Node: n.fingerprint(), Counter: c, Owner: n.owner.owner(),
		Core: point(n.core), Enforcer: point(n.enforcer), Settings: s,
	}
}

// dial connects with key; nil presents no certificate.
func (n *node) dial(key *ecdsa.PrivateKey) (*tls.Conn, error) {
	n.t.Helper()
	var conf *tls.Config
	if key == nil {
		conf = &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, CurvePreferences: []tls.CurveID{Group}}
	} else {
		var err error
		if conf, err = ClientConfig(key, n.devicePoint()); err != nil {
			n.t.Fatal(err)
		}
	}
	c, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", n.addr, conf)
	if err != nil {
		return nil, err
	}
	n.t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(3 * time.Second))
	return c, nil
}

// send sends one signed bundle as key and returns the node's status reply,
// or the error that ended the connection.
func (n *node) send(key *ecdsa.PrivateKey, signed []byte) (camwire.Status, error) {
	n.t.Helper()
	c, err := n.dial(key)
	if err != nil {
		return camwire.Status{}, err
	}
	if err := camwire.WriteFrame(c, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: camwire.TypeBundle, Payload: signed}); err != nil {
		return camwire.Status{}, err
	}
	f, err := camwire.ReadFrame(c, camwire.ToEnforcer, camwire.Shape{})
	if err != nil {
		return camwire.Status{}, err
	}
	return camwire.ParseStatus(f.Payload)
}

// provision boots with the button and sends the first bundle as the
// enforcer, then restarts without the button.
func (n *node) provision() camwire.Bundle {
	n.t.Helper()
	n.boot(true)
	b := n.bundle(1, goodSettings)
	if _, err := n.send(n.enforcer, n.owner.sign(n.t, b)); err != nil {
		n.t.Fatalf("first bundle: %v\n%s", err, n.logs.all())
	}
	n.boot(false)
	return b
}

func (n *node) counter() uint64 {
	c, err := n.el.Counter(se.Settings)
	if err != nil {
		n.t.Fatal(err)
	}
	return c
}
