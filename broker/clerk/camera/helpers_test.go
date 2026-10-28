package camera

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
	"github.com/ghbmrk/agentos/broker/clerk/devhost"
	"github.com/ghbmrk/agentos/broker/netguard"
)

// canaryKey is the synthetic client key (A16's camera password): 32 ASCII
// bytes, a valid P-256 scalar. It is a canary, not a credential.
var canaryKey = []byte("camera-client-canary-key-0000001")

const testAddr = "192.168.1.20:7443"

// marker is the pattern every synthetic video payload carries.
const marker = "MARKER-PAYLOAD-7f3a"

func lendCanary(fn func(key []byte) error) error {
	k := append([]byte(nil), canaryKey...)
	defer clear(k)
	return fn(k)
}

// node is a synthetic camera node: the stream port's TLS as CAM-server
// serves it, its device key in memory, and a script per connection.
type node struct {
	key   *ecdsa.PrivateKey
	point [camwire.PointLen]byte
	// serve runs each connection's script after the handshake; i counts
	// connections from 0.
	serve func(i int, c *tls.Conn)

	conns   atomic.Int32
	mu      sync.Mutex
	ln      net.Listener
	clients [][camwire.PointLen]byte
}

func newNode(t *testing.T, serve func(i int, c *tls.Conn)) *node {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return &node{key: k, point: [camwire.PointLen]byte(b), serve: serve}
}

// listen starts the node's port on loopback once and returns its address;
// the guard's Connect sends the pinned address there.
func (n *node) listen(t *testing.T) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.ln == nil {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Error(err)
			return ""
		}
		n.ln = ln
		t.Cleanup(func() { ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go n.accept(c)
			}
		}()
	}
	return n.ln.Addr().String()
}

func (n *node) accept(raw net.Conn) {
	defer raw.Close()
	der, err := x509.CreateCertificate(rand.Reader, template(), template(), &n.key.PublicKey, n.key)
	if err != nil {
		return
	}
	tc := tls.Server(raw, &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{Group},
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: n.key}},
		ClientAuth:       tls.RequireAnyClientCert,
	})
	if err := tc.Handshake(); err != nil {
		return
	}
	cs := tc.ConnectionState()
	if k, ok := cs.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey); ok {
		if b, err := k.Bytes(); err == nil {
			n.mu.Lock()
			n.clients = append(n.clients, [camwire.PointLen]byte(b))
			n.mu.Unlock()
		}
	}
	i := int(n.conns.Add(1)) - 1
	if n.serve != nil {
		n.serve(i, tc)
	}
}

// send writes frames, then holds the connection until the clerk closes it.
func send(frames ...camwire.Frame) func(int, *tls.Conn) {
	return func(_ int, c *tls.Conn) {
		for _, f := range frames {
			if camwire.WriteFrame(c, camwire.ToCore, camwire.Shape{}, f) != nil {
				return
			}
		}
		hold(c)
	}
}

func hold(c *tls.Conn) {
	var b [1]byte
	c.Read(b[:])
}

func video(i int) camwire.Frame {
	return camwire.Frame{Type: camwire.TypeVideo, Payload: []byte(fmt.Sprintf("\x00\x00\x00\x01%s-%d", marker, i))}
}

func status() camwire.Frame {
	return camwire.Frame{Type: camwire.TypeStatus, Payload: camwire.AppendStatus(nil, camwire.Status{Uptime: 7, Settings: 3, Temperature: 4100})}
}

// env is a clerk wired to a synthetic node through the device guard, with
// everything it emits recorded.
type env struct {
	t     *testing.T
	c     *Clerk
	guard *netguard.Policy
	cam   Camera
	dials atomic.Int32
	skew  atomic.Int64 // added to the clock the limit reads

	mu     sync.Mutex
	nodes  map[string]*node // by address
	logs   []string
	events []devhost.Event
	losses []Loss
	frames []camwire.Frame
	admit  bool
}

type option func(*Config)

func newEnv(t *testing.T, n *node, capture Capture, opts ...option) *env {
	t.Helper()
	e := &env{t: t, nodes: map[string]*node{testAddr: n}, admit: true}
	e.guard = netguard.New(netguard.Config{Connect: func(_ context.Context, _, addr string) (net.Conn, error) {
		e.dials.Add(1)
		e.mu.Lock()
		nd := e.nodes[addr]
		e.mu.Unlock()
		if nd == nil {
			return nil, fmt.Errorf("no node")
		}
		return net.Dial("tcp", nd.listen(t))
	}})
	cfg := Config{
		Guard:  e.guard,
		Lend:   lendCanary,
		Sink:   sinkFunc(e.emit),
		Limit:  devhost.Limit{Burst: 4, Window: time.Hour},
		Frames: e.frame,
		Lost: func(l Loss) error {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.losses = append(e.losses, l)
			return nil
		},
		Admit: func(string) bool {
			e.mu.Lock()
			defer e.mu.Unlock()
			return e.admit
		},
		Log: func(m string) {
			e.mu.Lock()
			defer e.mu.Unlock()
			e.logs = append(e.logs, m)
		},
		Now:        func() time.Time { return time.Now().Add(time.Duration(e.skew.Load())) },
		Timeout:    2 * time.Second,
		MinBackoff: 5 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond,
	}
	for _, o := range opts {
		o(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.c = c
	e.cam = Camera{ID: "porch", Addr: netip.MustParseAddrPort(testAddr), Key: n.point, Capture: capture, Silence: time.Second}
	e.pin(e.cam)
	if err := c.Set(e.cam); err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) pin(cm Camera) {
	e.t.Helper()
	p, err := cm.GuardPin()
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.guard.SetPins([]netguard.Pin{p}); err != nil {
		e.t.Fatal(err)
	}
}

type sinkFunc func(devhost.Event) error

func (f sinkFunc) Emit(e devhost.Event) error { return f(e) }

func (e *env) emit(ev devhost.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	return nil
}

func (e *env) frame(_ string, f camwire.Frame) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.frames = append(e.frames, f)
}

func (e *env) count(kind string) (events, coalesced int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Reading.Kind == kind {
			events++
			coalesced += ev.Coalesced
		}
	}
	return
}

func (e *env) nframes() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.frames)
}

// run starts Run in the background and returns its stop and result.
func (e *env) run() (stop func() error) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- e.c.Run(ctx, e.cam.ID) }()
	return func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			e.t.Fatal("Run did not end")
			return nil
		}
	}
}

// everything is every string the clerk let out besides frames: log lines,
// events, losses and STATUS.
func (e *env) everything(errs ...error) []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := append([]string(nil), e.logs...)
	for _, ev := range e.events {
		out = append(out, fmt.Sprintf("%+v %#v", ev, ev))
	}
	for _, l := range e.losses {
		out = append(out, fmt.Sprintf("%+v", l))
	}
	for _, err := range errs {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}
