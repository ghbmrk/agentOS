package camera

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// Every key here is generated per run: synthetic, never a real credential.

const testID = "porch"

var testAddr = netip.MustParseAddrPort("192.168.1.60:8443")

var lepton = camwire.Shape{Width: 4, Height: 3}

// store is a fake sealed-store slot: it lends a copy of the scalar for one
// call and wipes the copy after, as clerk.Secrets.DeviceKey does.
type store struct {
	raw   []byte
	lends atomic.Int32
}

func (s *store) lend(fn func(raw []byte) error) error {
	s.lends.Add(1)
	cp := bytes.Clone(s.raw)
	defer clear(cp)
	return fn(cp)
}

// tlsConn is the node side of one connection.
type tlsConn = tls.Conn

// synth is a synthetic camera node on camwire: a TLS 1.3 server with its
// own P-256 key that requires the core's client key, and a serve func per
// connection.
type synth struct {
	cert  tls.Certificate
	pin   [32]byte
	core  [camwire.PointLen]byte
	dials atomic.Int32
	mu    sync.Mutex
	addrs []string
	serve func(n int, c *tls.Conn)
	wrong atomic.Int32 // connections whose client key was not the core's
	max   uint16       // the highest TLS version the node offers; 0 is 1.3
}

func newCert(t testing.TB) (tls.Certificate, [32]byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), NotBefore: time.Unix(0, 0), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, netguard.KeyHash(leaf)
}

func newSynth(t testing.TB, core [camwire.PointLen]byte) *synth {
	cert, pin := newCert(t)
	return &synth{cert: cert, pin: pin, core: core}
}

// connect is the guard's connect seam: each dial is one in-memory
// connection to the node.
func (s *synth) connect(ctx context.Context, _, addr string) (net.Conn, error) {
	n := int(s.dials.Add(1))
	s.mu.Lock()
	s.addrs = append(s.addrs, addr)
	s.mu.Unlock()
	// A loopback TCP pair, buffered as a real link is, so the clerk's
	// hang-up never waits on the node's write.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	b, err := ln.Accept()
	if err != nil {
		a.Close()
		return nil, err
	}
	go s.handle(n, b)
	return a, nil
}

func (s *synth) handle(n int, raw net.Conn) {
	defer raw.Close()
	tc := tls.Server(raw, &tls.Config{
		Certificates: []tls.Certificate{s.cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   s.max,
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			pub, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey)
			if b, _ := pub.Bytes(); !ok || !bytes.Equal(b, s.core[:]) {
				s.wrong.Add(1)
				return errors.New("not the core's key")
			}
			return nil
		},
	})
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	if s.serve != nil {
		s.serve(n, tc)
	}
}

func (s *synth) dialed() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.addrs)
}

// write sends frames; it ignores errors, since the clerk may have hung up.
func write(c net.Conn, frames ...camwire.Frame) {
	for _, f := range frames {
		if err := camwire.WriteFrame(c, camwire.ToCore, lepton, f); err != nil {
			return
		}
	}
}

// hold keeps a connection open, sending nothing, until the clerk closes it.
func hold(c net.Conn) {
	var b [1]byte
	c.Read(b[:])
}

var marker = []byte("MARKER-PAYLOAD-7d1f")

func video() camwire.Frame {
	p := append([]byte{0, 0, 0, 1, 0x65}, marker...)
	return camwire.Frame{Type: camwire.TypeVideo, Payload: p}
}

func thermal() camwire.Frame {
	s := make([]byte, 2*int(lepton.Width)*int(lepton.Height))
	copy(s, marker)
	p := camwire.AppendThermal(nil, camwire.Thermal{Width: lepton.Width, Height: lepton.Height, Counter: 9, Samples: s})
	return camwire.Frame{Type: camwire.TypeThermal, Payload: p}
}

func status() camwire.Frame {
	st := camwire.Status{Uptime: 42, Settings: 3, Temperature: 2150}
	copy(st.Image[:], marker)
	return camwire.Frame{Type: camwire.TypeStatus, Payload: camwire.AppendStatus(nil, st)}
}

type events struct {
	mu sync.Mutex
	ev []Event
}

func (e *events) Emit(ev Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ev = append(e.ev, ev)
	return nil
}

func (e *events) of(k Kind) []Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []Event
	for _, ev := range e.ev {
		if ev.Kind == k {
			out = append(out, ev)
		}
	}
	return out
}

type frames struct {
	mu sync.Mutex
	f  []camwire.Frame
}

func (s *frames) Frame(_ string, f camwire.Frame) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.f = append(s.f, camwire.Frame{Type: f.Type, Payload: bytes.Clone(f.Payload)})
	return nil
}

func (s *frames) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.f)
}

type lines struct {
	mu sync.Mutex
	l  []string
}

func (l *lines) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.l = append(l.l, s)
}

func (l *lines) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.l, "\n")
}

// clock is a manual clock for the limit's windows.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	c      *Clerk
	node   *synth
	store  *store
	ev     *events
	fr     *frames
	log    *lines
	guard  *netguard.Policy
	clock  *clock
	errs   []error
	errsMu sync.Mutex
}

type opt func(*Config, *Node)

func newRig(t *testing.T, opts ...opt) *rig {
	t.Helper()
	st := &store{}
	if err := NewClientKey(func(raw []byte) error { st.raw = bytes.Clone(raw); return nil }); err != nil {
		t.Fatal(err)
	}
	key, err := OpenClientKey(st.lend)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{store: st, ev: &events{}, fr: &frames{}, log: &lines{}, clock: &clock{t: time.Date(2026, 10, 28, 8, 0, 0, 0, time.UTC)}}
	r.node = newSynth(t, key.Point())
	r.guard = netguard.New(netguard.Config{Connect: r.node.connect})
	if err := r.guard.SetPins([]netguard.Pin{{Kind: netguard.PinDevice, Addr: testAddr, Key: r.node.pin}}); err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		Guard: r.guard, Key: key, Frames: r.fr, Events: r.ev,
		Limit:   Limit{Burst: 5, Window: time.Minute},
		Admit:   func(string) bool { return true },
		Backoff: Backoff{Min: time.Millisecond, Max: 5 * time.Millisecond},
		Timeout: 2 * time.Second,
		Now:     r.clock.now,
		Log:     r.log.add,
	}
	n := Node{ID: testID, Addr: testAddr, Key: r.node.pin, Thermal: lepton, Capture: Continuous, Interval: 150 * time.Millisecond}
	for _, o := range opts {
		o(&cfg, &n)
	}
	r.c, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.c.Add(n); err != nil {
		t.Fatal(err)
	}
	return r
}

// start runs fn in the background; stop cancels it and returns its error.
func (r *rig) start(fn func(ctx context.Context) error) (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fn(ctx) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			r.errsMu.Lock()
			r.errs = append(r.errs, err)
			r.errsMu.Unlock()
			return err
		case <-time.After(5 * time.Second):
			return errors.New("did not stop")
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(2 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// bounded is a context for a call expected to return at once, so a mutant
// that streams instead fails the test rather than hanging it.
func bounded(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}
