package camnode

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/camwire/camwiretest"
)

// fakeElement is the secure element in memory: a synthetic P-256 device
// key behind the same interface, and two counters no method lowers.
type fakeElement struct {
	mu        sync.Mutex
	key       *ecdsa.PrivateKey
	settings  uint64
	record    [32]byte
	image     uint64
	failRaise bool // CommitBundle records but does not raise: a power cut
	nonRising int  // commits the node asked for that would not raise the counter
}

func (e *fakeElement) Public() ([camwire.PointLen]byte, error) {
	return camwiretest.Point(&e.key.PublicKey), nil
}

func (e *fakeElement) Sign(d []byte) ([]byte, error) { return ecdsa.SignASN1(rand.Reader, e.key, d) }

func (e *fakeElement) Settings() (uint64, [32]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.settings, e.record, nil
}

func (e *fakeElement) CommitBundle(c uint64, d [32]byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if c <= e.settings {
		e.nonRising++
		return errors.New("fake element: counter would not rise")
	}
	e.record = d
	if e.failRaise {
		return errors.New("fake element: power cut")
	}
	e.settings = c
	return nil
}

func (e *fakeElement) ClearBundle() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.record = [32]byte{}
	return nil
}

func (e *fakeElement) Image() (uint64, error) { return e.image, nil }

// fakeSource is generated video: one access unit per Read, a little apart.
type fakeSource struct {
	mu      sync.Mutex
	applied []camwire.Settings
}

func (s *fakeSource) Apply(st camwire.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied = append(s.applied, st)
	return nil
}

func (s *fakeSource) last() (camwire.Settings, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.applied) == 0 {
		return camwire.Settings{}, 0
	}
	return s.applied[len(s.applied)-1], len(s.applied)
}

func (s *fakeSource) Read() (camwire.Frame, error) {
	time.Sleep(5 * time.Millisecond)
	return camwire.Frame{Type: camwire.TypeVideo, Payload: []byte{0, 0, 0, 1, 0x65, 0x88}}, nil
}

var testRanges = Ranges{
	Resolutions: []Resolution{{1920, 1080}, {1280, 720}},
	MaxFPS:      30,
	MinKbps:     500,
	MaxKbps:     8000,
	IR:          true,
}

// rig is one node on a loopback port with its hardware faked, and the
// owner, core and enforcer that drive it.
type rig struct {
	t        *testing.T
	el       *fakeElement
	src      *fakeSource
	store    FileStore
	node     *Node
	addr     string
	owner    camwiretest.Passkey
	core     *ecdsa.PrivateKey
	enforcer *ecdsa.PrivateKey
	logs     *logSink
	errs     []error
}

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (l *logSink) add(s string) {
	l.mu.Lock()
	l.lines = append(l.lines, s)
	l.mu.Unlock()
}

func newRig(t *testing.T, button bool) *rig {
	t.Helper()
	r := &rig{
		t:        t,
		el:       &fakeElement{key: camwiretest.NewKey(t)},
		src:      &fakeSource{},
		store:    FileStore{Dir: t.TempDir()},
		owner:    camwiretest.NewPasskey(t),
		core:     camwiretest.NewKey(t),
		enforcer: camwiretest.NewKey(t),
		logs:     &logSink{},
	}
	r.boot(button)
	return r
}

// boot starts (or restarts) the node on the rig's element and store.
func (r *rig) boot(button bool) error {
	r.t.Helper()
	n, err := New(Config{Element: r.el, Store: r.store, Source: r.src, Ranges: testRanges, Button: button, Log: r.logs.add})
	if err != nil {
		r.errs = append(r.errs, err)
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	r.t.Cleanup(func() { ln.Close() })
	go n.Serve(ln)
	r.node, r.addr = n, ln.Addr().String()
	return nil
}

func (r *rig) nodePoint() [camwire.PointLen]byte { return camwiretest.Point(&r.el.key.PublicKey) }

// bundle is an in-range bundle for the rig's node at counter c.
func (r *rig) bundle(c uint64) camwire.Bundle {
	return camwire.Bundle{
		Node:     r.node.Fingerprint(),
		Counter:  c,
		Owner:    r.owner.Owner(),
		Core:     camwiretest.Point(&r.core.PublicKey),
		Enforcer: camwiretest.Point(&r.enforcer.PublicKey),
		Settings: camwire.Settings{Width: 1920, Height: 1080, FPS: 25, BitrateKbps: 4000, IR: camwire.IRAuto, Stream: true},
	}
}

// dial connects with key (nil: no client certificate) and pins the node.
func (r *rig) dial(key *ecdsa.PrivateKey) (*tls.Conn, error) {
	r.t.Helper()
	var cfg *tls.Config
	var err error
	if key == nil {
		cfg = base()
		cfg.InsecureSkipVerify = true
	} else if cfg, err = ClientConfig(key, r.nodePoint()); err != nil {
		r.t.Fatal(err)
	}
	c, err := tls.Dial("tcp", r.addr, cfg)
	if err != nil {
		return nil, err
	}
	r.t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// A TLS 1.3 client learns of a refused certificate on its first read.
	return c, nil
}

// send writes one signed bundle on an enforcer connection, after reading
// the status the node opens with, and reports the next status or the
// connection's end.
func send(c *tls.Conn, p []byte) (camwire.Status, error) {
	if _, err := readStatus(c); err != nil {
		return camwire.Status{}, err
	}
	return sendMore(c, p)
}

func sendMore(c *tls.Conn, p []byte) (camwire.Status, error) {
	if err := camwire.WriteFrame(c, camwire.FromEnforcer, camwire.Shape{}, camwire.Frame{Type: camwire.TypeBundle, Payload: p}); err != nil {
		return camwire.Status{}, err
	}
	return readStatus(c)
}

func readStatus(c *tls.Conn) (camwire.Status, error) {
	f, err := camwire.ReadFrame(c, camwire.ToEnforcer, camwire.Shape{})
	if err != nil {
		return camwire.Status{}, err
	}
	return camwire.ParseStatus(f.Payload)
}

// provision boots the rig with the button held and applies the first
// bundle at counter c from the enforcer.
func (r *rig) provision(c uint64) {
	r.t.Helper()
	conn, err := r.dial(r.enforcer)
	if err != nil {
		r.t.Fatal(err)
	}
	if st, err := send(conn, r.owner.SignBundle(r.t, r.bundle(c))); err != nil || st.Settings != c {
		r.t.Fatalf("first bundle: %v, counter %d", err, st.Settings)
	}
	conn.Close()
}

type ecdsaKey = ecdsa.PrivateKey

func deadline(ms int) time.Time { return time.Now().Add(time.Duration(ms) * time.Millisecond) }

func isClosed(err error) bool { return errors.Is(err, net.ErrClosed) }
