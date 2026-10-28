package camnode

import (
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camwire"
)

// Source is the camera's capture behind an interface: the hardware encoder
// and the thermal core on the board, generated video in tests.
type Source interface {
	// Apply sets the sensor; it is called only with settings within Ranges.
	Apply(camwire.Settings) error
	// Read blocks for the next frame, video or thermal, node to core.
	Read() (camwire.Frame, error)
}

// Config is what the binary hands the node.
type Config struct {
	Element Element
	Store   Store
	Source  Source
	Ranges  Ranges
	Thermal camwire.Shape // the declared thermal core; zero for none
	Image   [32]byte      // SHA-256 of the running image, for the status record
	// Button reports the board's provisioning button as held at power-on.
	// Held, the node erases its bundle and takes the first bundle offered.
	Button bool
	// Window is how long the first-bundle window stays open after a
	// button start, by the monotonic clock; zero is FirstBundleWindow.
	Window time.Duration
	// Log takes fixed-text events; it is never given peer data or key
	// material. Nil discards them.
	Log func(event string)
}

// Timeouts. The node has a monotonic clock, not a trusted wall clock;
// these only bound how long one peer can hold a connection.
const (
	handshakeTimeout = 10 * time.Second
	writeTimeout     = 10 * time.Second
	settingsIdle     = 2 * time.Minute
	// FirstBundleWindow bounds the window a button start opens, so a node
	// reset and left unprovisioned cannot be claimed by a LAN host later
	// (Security on #3586, finding 1).
	FirstBundleWindow = 10 * time.Minute
)

// Errors New and the settings channel return.
var (
	ErrWindow = errors.New("camnode: no first-bundle window is open")
	ErrRole   = errors.New("camnode: first bundle does not name the client that sent it as the enforcer")
	ErrState  = errors.New("camnode: element and stored bundle disagree")
	// ErrSource is a bundle committed (counter raised, now the node's) that
	// the source then failed to take.
	ErrSource = errors.New("camnode: bundle committed, source failed")
)

type role int

const (
	roleNone role = iota
	roleCore
	roleEnforcer
	roleFirst // a client while the first-bundle window is open
)

// Node is one camera node's server.
type Node struct {
	cfg   Config
	node  [32]byte // Fingerprint of the device key
	tls   *tls.Config
	start time.Time

	mu        sync.Mutex
	bundle    *camwire.Bundle // nil: no owner yet
	window    bool            // the first-bundle window is open until windowEnd
	windowEnd time.Time
	conns     map[*tls.Conn]role
}

// New starts the node from its element and store. With the button held it
// erases the bundle (the device key and counters are kept) and opens the
// first-bundle window; otherwise it loads the committed bundle, if any, and
// applies it.
func New(cfg Config) (*Node, error) {
	s, pt, err := newSigner(cfg.Element)
	if err != nil {
		return nil, err
	}
	n := &Node{cfg: cfg, node: camwire.Fingerprint(pt), start: time.Now(), conns: map[*tls.Conn]role{}}
	if n.tls, err = serverConfig(s, n.admits); err != nil {
		return nil, err
	}
	if cfg.Button {
		if err := cfg.Element.ClearBundle(); err != nil {
			return nil, err
		}
		if err := cfg.Store.Erase(); err != nil {
			return nil, err
		}
		n.window = true
		if cfg.Window <= 0 {
			cfg.Window = FirstBundleWindow
		}
		n.windowEnd = n.start.Add(cfg.Window)
		n.log("button held: bundle erased, first-bundle window open")
		return n, nil
	}
	return n, n.load()
}

// load restores the committed bundle: the stored bytes must hash to the
// element's record, name this node, carry their owner's assertion and be
// within Ranges. A counter below the bundle's is a CommitBundle the power
// cut short, completed here; one above it is refused.
func (n *Node) load() error {
	counter, digest, err := n.cfg.Element.Settings()
	if err != nil {
		return ErrElement
	}
	if digest == ([32]byte{}) {
		n.log("no bundle: every client refused until provisioned")
		return nil
	}
	p, err := n.cfg.Store.Get(digest)
	if err != nil {
		return err
	}
	_, b, err := camwire.ParseSignedBundle(p)
	if err != nil {
		return err
	}
	if b, err = camwire.VerifyFirstBundle(p, n.node, b.Counter-1); err != nil {
		return err
	}
	if counter > b.Counter {
		return ErrState
	}
	if err := n.cfg.Ranges.check(b.Settings, n.cfg.Thermal); err != nil {
		return err
	}
	if counter < b.Counter {
		if err := n.cfg.Element.CommitBundle(b.Counter, digest); err != nil {
			return ErrElement
		}
	}
	if err := n.cfg.Source.Apply(b.Settings); err != nil {
		return err
	}
	n.bundle = &b
	return nil
}

// Fingerprint is the node's device-key fingerprint, as printed on its case.
func (n *Node) Fingerprint() [32]byte { return n.node }

func (n *Node) log(event string) {
	if n.cfg.Log != nil {
		n.cfg.Log(event)
	}
}

// roleOf is the role key holds now.
func (n *Node) roleOf(key [camwire.PointLen]byte) role {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.roleLocked(key)
}

func (n *Node) roleLocked(key [camwire.PointLen]byte) role {
	switch b := n.bundle; {
	case b == nil && n.windowOpen():
		return roleFirst
	case b == nil:
		return roleNone
	case key == b.Core && b.Settings.Stream:
		return roleCore
	case key == b.Enforcer:
		return roleEnforcer
	}
	return roleNone
}

// windowOpen reports whether the first-bundle window is still open.
func (n *Node) windowOpen() bool { return n.window && time.Now().Before(n.windowEnd) }

func (n *Node) admits(key [camwire.PointLen]byte) bool { return n.roleOf(key) != roleNone }

// Serve accepts on ln until it fails. ln is the node's one listener, opened
// by the binary; the node opens nothing else.
func (n *Node) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go n.handle(tls.Server(c, n.tls))
	}
}

func (n *Node) handle(c *tls.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := c.Handshake(); err != nil {
		n.log("handshake refused")
		return
	}
	key, ok := peerPoint(c.ConnectionState())
	if !ok {
		return
	}
	var stale []*tls.Conn
	n.mu.Lock()
	r := n.roleLocked(key)
	if r == roleCore {
		// One stream at a time: a newer connection from the core replaces
		// the older.
		for o, or := range n.conns {
			if or == roleCore {
				stale = append(stale, o)
				delete(n.conns, o)
			}
		}
	}
	if r != roleNone {
		n.conns[c] = r
	}
	n.mu.Unlock()
	closeAll(stale)
	defer n.forget(c)
	switch r {
	case roleCore:
		n.stream(c)
	case roleEnforcer, roleFirst:
		n.settings(c, key, r == roleFirst)
	}
}

func (n *Node) forget(c *tls.Conn) {
	n.mu.Lock()
	delete(n.conns, c)
	n.mu.Unlock()
}

// stream sends the source's frames to the core. The core sends nothing on
// this channel (CAM-wire-12), so any byte from it, or its close, ends the
// connection.
func (n *Node) stream(c *tls.Conn) {
	c.SetDeadline(time.Time{})
	go func() {
		var b [1]byte
		c.Read(b[:])
		c.Close()
	}()
	for {
		f, err := n.cfg.Source.Read()
		if err != nil {
			n.log("source failed")
			return
		}
		c.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := camwire.WriteFrame(c, camwire.ToCore, n.cfg.Thermal, f); err != nil {
			return
		}
	}
}

// settings serves the enforcer's channel: a status record on connect and
// after each bundle applied. Any frame refused ends the connection.
func (n *Node) settings(c *tls.Conn, key [camwire.PointLen]byte, first bool) {
	if n.status(c) != nil {
		return
	}
	for {
		c.SetDeadline(time.Now().Add(settingsIdle))
		f, err := camwire.ReadFrame(c, camwire.FromEnforcer, n.cfg.Thermal)
		if err != nil {
			return
		}
		if f.Type != camwire.TypeBundle {
			// Updates are CAM-server part b2; until then a manifest or an
			// image chunk ends the connection like any frame refused.
			n.log("update refused: not served by this build")
			return
		}
		if err := n.apply(f.Payload, key, first); errors.Is(err, ErrSource) {
			// The counter moved: report it, so the enforcer does not show a
			// refusal that did not happen, then end the channel.
			n.log("bundle committed, source failed")
			n.status(c)
			return
		} else if err != nil {
			n.log("bundle refused")
			return
		}
		n.log("bundle applied")
		if n.status(c) != nil {
			return
		}
		first = false
		if n.roleOf(key) != roleEnforcer {
			return // the new bundle names another enforcer
		}
	}
}

func (n *Node) status(c *tls.Conn) error {
	counter, _, err := n.cfg.Element.Settings()
	if err != nil {
		return ErrElement
	}
	st := camwire.Status{Uptime: uint64(time.Since(n.start) / time.Second), Image: n.cfg.Image, Settings: counter}
	c.SetWriteDeadline(time.Now().Add(writeTimeout))
	return camwire.WriteFrame(c, camwire.ToEnforcer, n.cfg.Thermal, camwire.Frame{Type: camwire.TypeStatus, Payload: camwire.AppendStatus(nil, st)})
}

// apply takes one signed bundle sent by the client whose key is from. The
// first bundle (first set: the window is open) must name from as its
// enforcer; a later one must verify against the pinned owner. A bundle is
// within Ranges, stored, committed to the element (record, then counter)
// and only then given to the source. Connections whose key the bundle no
// longer admits in their role are closed.
func (n *Node) apply(p []byte, from [camwire.PointLen]byte, first bool) error {
	var stale []*tls.Conn
	// Closing sends close_notify, which a stalled peer can hold; never
	// under n.mu, which every handshake takes.
	defer func() { closeAll(stale) }()
	n.mu.Lock()
	defer n.mu.Unlock()
	counter, _, err := n.cfg.Element.Settings()
	if err != nil {
		return ErrElement
	}
	var b camwire.Bundle
	switch {
	case first && !n.windowOpen():
		return ErrWindow
	case first:
		if b, err = camwire.VerifyFirstBundle(p, n.node, counter); err != nil {
			return err
		}
		if b.Enforcer != from {
			return ErrRole
		}
	case n.bundle == nil || from != n.bundle.Enforcer:
		return ErrPin
	default:
		if b, err = camwire.VerifyBundle(p, camwire.Pin{Node: n.node, Owner: n.bundle.Owner, Counter: counter}); err != nil {
			return err
		}
	}
	if err := n.cfg.Ranges.check(b.Settings, n.cfg.Thermal); err != nil {
		return err
	}
	d := sha256.Sum256(p)
	if err := n.cfg.Store.Put(p); err != nil {
		return err
	}
	if err := n.cfg.Element.CommitBundle(b.Counter, d); err != nil {
		return ErrElement
	}
	n.bundle, n.window = &b, false
	if err := n.cfg.Store.Keep(d); err != nil {
		n.log("old bundles not removed")
	}
	for c, was := range n.conns {
		key, ok := peerPoint(c.ConnectionState())
		now := n.roleLocked(key)
		if !ok || now == roleNone || (now != was && !(was == roleFirst && now == roleEnforcer && key == from)) {
			stale = append(stale, c)
			delete(n.conns, c)
			continue
		}
		n.conns[c] = now
	}
	if err := n.cfg.Source.Apply(b.Settings); err != nil {
		return ErrSource
	}
	return nil
}

func closeAll(cs []*tls.Conn) {
	for _, c := range cs {
		c.Close()
	}
}
