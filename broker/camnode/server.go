// Package camnode is the camera node's server (CAM-node part b,
// CAM-server, #3513; SPEC DEV-2, DEV-3, NET-2 Cameras, NET-4, KRN-2,
// A16): one TLS 1.3 port on which the core's pinned key gets the stream
// and the enforcer's pinned key gets the settings channel, the
// owner-signed settings bundle applied through the secure element's
// counter, and the button window that takes the first bundle.
//
// The server opens no connection of its own (TestNoOutboundDial): it only
// accepts on the listener it is handed.
package camnode

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/camnode/se"
	"github.com/ghbmrk/agentos/broker/camwire"
)

// ProvisionWindow is how long after a button boot the first bundle is
// taken. The button proves presence at power-on; the window keeps a node
// left unprovisioned from staying open to whoever reaches it later.
const ProvisionWindow = 10 * time.Minute

// Timeouts on one connection.
const (
	handshakeTimeout = 10 * time.Second
	settingsIdle     = 5 * time.Minute
	frameWrite       = 10 * time.Second
	statusEvery      = 30 * time.Second
)

// Source is the camera behind the server: the hardware encoder's H.264
// and the thermal core, merged into one frame sequence (part b2).
type Source interface {
	// Apply sets the source to s, which Ranges.Check has passed.
	Apply(s camwire.Settings) error
	// Next blocks for the next video or thermal frame.
	Next(ctx context.Context) (camwire.Frame, error)
}

// Config is what the node's binary hands the server.
type Config struct {
	Element se.Element
	Store   Store
	Ranges  Ranges
	Source  Source
	// ButtonHeld is the board's button as read at power-on.
	ButtonHeld bool
	// Image is the running image's SHA-256, for the status record.
	Image [32]byte
	// Log takes one line per event. Lines are fixed text and this
	// package's own error strings; nothing from a peer, and nothing from
	// the element but its fixed errors.
	Log func(string)
	// Now is a monotonic clock; time.Now if nil.
	Now func() time.Time
}

// Server is one node's server.
type Server struct {
	c     Config
	node  [32]byte
	tls   *tls.Config
	start time.Time

	mu sync.Mutex
	// bundle is the bundle in force; ok is false before the first.
	bundle camwire.Bundle
	ok     bool
	// window is open until windowEnd, or until the first bundle lands.
	window    bool
	windowEnd time.Time
	// stream is the live stream connection, which a new one replaces.
	stream net.Conn
}

// New boots the server's state: a button boot resets a provisioned node
// and opens the first-bundle window; any other boot loads the stored
// bundle, which must verify against the element.
func New(c Config) (*Server, error) {
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Log == nil {
		c.Log = func(string) {}
	}
	c.Element = se.Locked(c.Element)
	s := &Server{c: c, start: c.Now()}
	var err error
	if s.node, err = se.Fingerprint(c.Element); err != nil {
		return nil, err
	}
	signer, err := se.NewSigner(c.Element)
	if err != nil {
		return nil, err
	}
	if s.tls, err = serverConfig(signer, s.role); err != nil {
		return nil, err
	}
	pin, pinned, err := c.Element.OwnerPin()
	if err != nil {
		return nil, err
	}
	switch {
	case c.ButtonHeld:
		if pinned {
			if err := reset(c.Element, c.Store); err != nil {
				return nil, err
			}
			c.Log("button reset: bundle and owner pin erased")
		}
		s.window, s.windowEnd = true, s.start.Add(ProvisionWindow)
		c.Log("first-bundle window open")
	case pinned:
		b, _, err := loadBundle(c.Element, c.Store, s.node, pin)
		if err != nil {
			c.Log("no stored bundle verifies; every client refused until a button reset")
			break
		}
		s.bundle, s.ok = b, true
		if err := c.Source.Apply(b.Settings); err != nil {
			c.Log("source refused the stored settings")
		}
	default:
		c.Log("not provisioned; every client refused until a button boot")
	}
	return s, nil
}

// role is what key may do now.
func (s *Server) role(key [camwire.PointLen]byte) Role {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.ok && key == s.bundle.Core && s.bundle.Settings.Stream:
		return Core
	case s.ok && key == s.bundle.Enforcer:
		return Enforcer
	case !s.ok && s.window && s.c.Now().Before(s.windowEnd):
		return Provisioner
	}
	return None
}

// Serve accepts on l until it fails; each connection runs on its own.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

// handle runs one connection: the handshake, then the one channel its key
// is pinned to.
func (s *Server) handle(raw net.Conn) {
	conn := tls.Server(raw, s.tls)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := conn.Handshake(); err != nil {
		s.c.Log("handshake refused")
		return
	}
	conn.SetDeadline(time.Time{})
	key, err := peerKey(conn.ConnectionState())
	if err != nil {
		s.c.Log("handshake refused")
		return
	}
	switch s.role(key) {
	case Core:
		s.serveStream(conn, key)
	case Enforcer:
		s.serveSettings(conn, key)
	case Provisioner:
		s.serveFirst(conn, key)
	default:
		s.c.Log("client key lost its role during the handshake")
	}
}

// serveStream sends the core the status record, then frames from the
// source, with the status record again every statusEvery. Any byte from
// the core ends it (camwire CAM-wire-12), as does a bundle that moves the
// core key or turns the stream off.
func (s *Server) serveStream(conn *tls.Conn, key [camwire.PointLen]byte) {
	s.mu.Lock()
	if s.stream != nil {
		s.stream.Close()
	}
	s.stream = conn
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.stream == conn {
			s.stream = nil
		}
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		var b [1]byte
		conn.Read(b[:]) // any byte, or the end, ends the stream
		cancel()
		conn.Close()
	}()
	var last time.Time
	for ctx.Err() == nil {
		if s.role(key) != Core {
			return
		}
		if now := s.c.Now(); now.Sub(last) >= statusEvery {
			if err := s.write(conn, camwire.ToCore, camwire.Frame{Type: camwire.TypeStatus, Payload: s.status()}); err != nil {
				return
			}
			last = now
		}
		f, err := s.c.Source.Next(ctx)
		if err != nil {
			if ctx.Err() == nil {
				s.c.Log("source ended the stream")
			}
			return
		}
		if f.Type != camwire.TypeVideo && f.Type != camwire.TypeThermal {
			s.c.Log("source frame type refused")
			return
		}
		s.mu.Lock()
		thermal := s.bundle.Settings.Thermal
		s.mu.Unlock()
		if f.Type == camwire.TypeThermal && !thermal {
			continue
		}
		if err := s.write(conn, camwire.ToCore, f); err != nil {
			return
		}
	}
}

// write sends one frame within frameWrite. camwire checks its type,
// direction and cap, so the server sends only what the wire allows.
func (s *Server) write(conn *tls.Conn, d camwire.Direction, f camwire.Frame) error {
	conn.SetWriteDeadline(time.Now().Add(frameWrite))
	err := camwire.WriteFrame(conn, d, s.c.Ranges.Thermal, f)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		s.c.Log("frame not sent: " + err.Error())
	}
	return err
}

// status is the node's status record.
func (s *Server) status() []byte {
	s.mu.Lock()
	ctr := s.bundle.Counter // the element's settings counter once committed
	s.mu.Unlock()
	up := s.c.Now().Sub(s.start)
	return camwire.AppendStatus(nil, camwire.Status{
		Uptime:   uint64(up / time.Second),
		Image:    s.c.Image,
		Settings: ctr,
	})
}

// serveSettings reads bundles from the enforcer and answers each applied
// one with the status record. A refused bundle, any other frame and any
// codec error end the connection without a reason: which check failed is
// not the sender's to learn. Image updates are part b2; until then a
// manifest ends the connection too.
func (s *Server) serveSettings(conn *tls.Conn, key [camwire.PointLen]byte) {
	for {
		conn.SetReadDeadline(time.Now().Add(settingsIdle))
		f, err := camwire.ReadFrame(conn, camwire.FromEnforcer, camwire.Shape{})
		if err != nil {
			if !errors.Is(err, io.EOF) {
				s.c.Log("settings channel ended: " + err.Error())
			}
			return
		}
		if s.role(key) != Enforcer || f.Type != camwire.TypeBundle {
			s.c.Log("settings frame refused")
			return
		}
		if err := s.apply(f.Payload, nil); err != nil {
			s.c.Log("bundle refused: " + err.Error())
			return
		}
		if err := s.write(conn, camwire.ToEnforcer, camwire.Frame{Type: camwire.TypeStatus, Payload: s.status()}); err != nil {
			return
		}
		if s.role(key) != Enforcer {
			return // the bundle moved the enforcer's key
		}
	}
}

// serveFirst takes one bundle in the first-bundle window, which must name
// the provisioner's own key as the enforcer's; the window then closes.
func (s *Server) serveFirst(conn *tls.Conn, key [camwire.PointLen]byte) {
	conn.SetReadDeadline(time.Now().Add(settingsIdle))
	f, err := camwire.ReadFrame(conn, camwire.FromEnforcer, camwire.Shape{})
	if err != nil || f.Type != camwire.TypeBundle {
		s.c.Log("first-bundle frame refused")
		return
	}
	if err := s.apply(f.Payload, &key); err != nil {
		s.c.Log("first bundle refused: " + err.Error())
		return
	}
	s.c.Log("first bundle taken; window closed")
	s.write(conn, camwire.ToEnforcer, camwire.Frame{Type: camwire.TypeStatus, Payload: s.status()})
}

// errProvisioner is a first bundle that names another key as the
// enforcer's than the one that sent it.
var errProvisioner = errors.New("camnode: first bundle does not name its sender as the enforcer")

// errWindow is a first bundle after the window closed.
var errWindow = errors.New("camnode: first-bundle window closed")

// apply verifies and commits one signed bundle; first is the
// provisioner's key for a first bundle, nil otherwise. The settings must
// pass the declared ranges before the element's counter moves, so a
// bundle the node cannot run burns no counter. It holds s.mu throughout,
// so applies are serial and the element sees one caller.
func (s *Server) apply(p []byte, first *[camwire.PointLen]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctr, err := s.c.Element.Counter(se.Settings)
	if err != nil {
		return err
	}
	var b camwire.Bundle
	if first != nil {
		if s.ok || !s.window || !s.c.Now().Before(s.windowEnd) {
			return errWindow
		}
		if b, err = camwire.VerifyFirstBundle(p, s.node, ctr); err != nil {
			return err
		}
		if b.Enforcer != *first {
			return errProvisioner
		}
	} else {
		if !s.ok {
			return errNoBundle
		}
		pin := camwire.Pin{Node: s.node, Owner: s.bundle.Owner, Counter: ctr}
		if b, err = camwire.VerifyBundle(p, pin); err != nil {
			return err
		}
	}
	if err := s.c.Ranges.Check(b.Settings); err != nil {
		return err
	}
	if err := commit(s.c.Element, s.c.Store, b, p, first != nil); err != nil {
		return err
	}
	old := s.bundle
	s.bundle, s.ok, s.window = b, true, false
	if err := s.c.Source.Apply(b.Settings); err != nil {
		s.c.Log("source refused the new settings")
	}
	if s.stream != nil && (b.Core != old.Core || !b.Settings.Stream) {
		s.stream.Close()
	}
	return nil
}
