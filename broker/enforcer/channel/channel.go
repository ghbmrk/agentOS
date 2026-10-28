// Package channel is the enforcer's end of the enforcer channel (SPEC
// NET-2 Channel, Safety devices, Drones, DEV-2; briefs/ENF.md slice d).
//
// The core reaches the enforcer only here. A connection opens with the
// core's hello, from the pinned channel sub-key and bound to the
// connection's TLS exporter, and refused if the key is revoked (KEY-7);
// the enforcer answers with its own. After that every frame goes through
// wire.Decode, the one parser, and only three kinds act: a device command,
// a closed-list tightening (through broker/enforcer/policy's Tighten, which
// classifies it) and a read. Heads and key-change entries are kept for the
// head-copy store, a proposal link is only counted, and a device
// challenge's answer goes back to the device that asked. Anything else
// ends the connection and is logged.
//
// A safety-list device takes reads and, only when the signed policy names
// it, its one secure-direction command (Table). Every kind is rate-limited,
// and a burst pauses the whole channel until the owner resumes it on the
// enforcer's page (Resume); nothing on the channel resumes it. Every
// request is logged, and a channel command that turns a heater off or shuts
// a valve texts the owner.
//
// It is enforcer code: it imports the standard library, broker/kernel/key
// through the policy, and the enforcer's own packages only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package channel

import (
	"crypto/ed25519"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Policy is the policy engine the channel asks: broker/enforcer/policy's
// Engine. The daemon (slice l) serialises it with the page.
type Policy interface {
	Current() policy.Document
	Tighten(op policy.Op, nowMS int64) error
	Secure(device, cmd string, nowMS int64) error
	Export() ([]byte, error)
}

// Radio is the confined radio host's narrow command interface (slice k),
// which every channel command goes through (NET-2 Confined radio stacks).
type Radio interface {
	Do(device string, v wire.Verb, level uint8) error
	State(device string) ([]byte, error)
}

// Heads is the head-copy store (slice h): it keeps every head and
// key-change entry the kernel sends (STO-1, KEY-7).
type Heads interface {
	Head(wire.Head) error
	Entry(wire.Entry) error
}

// Alerts is the enforcer's texts and light (slice h). The channel calls it
// when a command turned a heater off or shut a valve, and when a burst
// paused the channel.
type Alerts interface {
	SafetyOff(device string, v wire.Verb)
	Paused()
}

// Config is what a channel is built from. Core, Key, Revoked, Policy,
// Radio, Alerts and Log are required, so no command acts unlogged and no
// safety command goes untexted (NET-2); a nil read source refuses that
// read.
type Config struct {
	// Core is the kernel's channel sub-key, pinned at enrolment.
	Core ed25519.PublicKey
	// Key is the enforcer's own channel key.
	Key ed25519.PrivateKey
	// Revoked reports whether a key is revoked in the key-change entries
	// the enforcer holds (KEY-7; slice h's revocation set).
	Revoked func(ed25519.PublicKey) bool

	Policy Policy
	Radio  Radio
	Heads  Heads
	Alerts Alerts
	// Fingerprint is a safety-list device's secret's fingerprint (slice
	// r). Its type holds a hash and nothing else, so no read can return
	// the secret.
	Fingerprint func(device string) ([wire.HashLen]byte, bool)
	// Traffic is a device's traffic summary (slice i).
	Traffic func(device string) ([]byte, error)
	// Answer hands the core's answer to a device challenge back to the
	// device that asked (slice k).
	Answer func(id uint64, data []byte)
	// Log takes one line per request and refusal.
	Log func(Event)
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Limits overrides DefaultLimits per kind.
	Limits map[Kind]Limit
	// Paused is the state the daemon kept across a restart.
	Paused bool
}

// Event is one log line. Every field is the enforcer's own words or a
// token the wire already checked; nothing else of the peer's is in it.
type Event struct {
	At     time.Time
	Kind   Kind
	ID     uint64
	Device string
	What   string // the verb, tightening or read, in fixed words
	Code   wire.Code
	Reason string // fixed text
}

// Errors Serve and the push methods return.
var (
	ErrConfig    = errors.New("channel: config incomplete")
	ErrHello     = errors.New("channel: hello refused")
	ErrRevoked   = errors.New("channel: the core's channel key is revoked")
	ErrNoSession = errors.New("channel: no core connected")
	ErrBusy      = errors.New("channel: too many challenges outstanding")
)

// MaxOutstanding caps the device challenges waiting for an answer.
const MaxOutstanding = 64

// Channel is the enforcer's end. One Channel serves every connection the
// daemon accepts from the core, so a pause outlives a reconnect.
type Channel struct {
	cfg Config

	mu          sync.Mutex
	paused      bool
	buckets     map[Kind]*bucket
	outstanding map[uint64]bool
	session     *session
}

type session struct {
	mu sync.Mutex
	w  io.Writer
}

// New checks cfg and returns a channel.
func New(cfg Config) (*Channel, error) {
	if len(cfg.Core) != ed25519.PublicKeySize || len(cfg.Key) != ed25519.PrivateKeySize ||
		cfg.Revoked == nil || cfg.Policy == nil || cfg.Radio == nil || cfg.Alerts == nil || cfg.Log == nil {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Channel{cfg: cfg, paused: cfg.Paused, buckets: map[Kind]*bucket{}, outstanding: map[uint64]bool{}}
	now := cfg.Now()
	for k, l := range DefaultLimits {
		if o, ok := cfg.Limits[k]; ok {
			l = o
		}
		c.buckets[k] = newBucket(l, now)
	}
	return c, nil
}

// Paused reports whether a burst paused the channel.
func (c *Channel) Paused() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paused
}

// Resume unpauses the channel and refills every bucket. Only the
// enforcer's page calls it, after the owner's passkey at home (NET-6,
// slice b); no message on the channel reaches it.
func (c *Channel) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.paused {
		return
	}
	c.paused = false
	now := c.cfg.Now()
	for _, b := range c.buckets {
		b.fill(now)
	}
	c.cfg.Log(Event{At: now, Kind: KindPause, Reason: "resumed by the owner on the page"})
}

// Serve runs one connection from the core: rw is the TLS stream the daemon
// accepted and exporter its wire.ExporterLen bytes under
// wire.ExporterLabel. It returns when the stream ends or a frame is
// refused; the daemon then closes the connection.
func (c *Channel) Serve(rw io.ReadWriter, exporter []byte) error {
	c.mu.Lock()
	c.count(KindHello)
	c.mu.Unlock()

	f, err := wire.ReadFrame(rw, wire.ToEnforcer)
	if err == nil && f.Type != wire.THello {
		err = wire.ErrType
	}
	var m wire.Msg
	if err == nil {
		m, err = wire.Decode(wire.ToEnforcer, f)
	}
	if err == nil {
		err = m.(wire.Hello).Verify(wire.RoleCore, c.cfg.Core, exporter)
	}
	if err != nil {
		return c.refuse(KindHello, 0, "hello refused", ErrHello)
	}
	if c.cfg.Revoked(c.cfg.Core) {
		return c.refuse(KindHello, 0, "the core's channel key is revoked", ErrRevoked)
	}
	mine, err := wire.SignHello(wire.RoleEnforcer, c.cfg.Key, exporter)
	if err != nil {
		return err
	}
	s := &session{w: rw}
	if err := s.send(mine); err != nil {
		return err
	}
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	c.cfg.Log(Event{At: c.cfg.Now(), Kind: KindHello, Reason: "core connected"})
	defer func() {
		c.mu.Lock()
		if c.session == s {
			c.session = nil
		}
		c.mu.Unlock()
	}()

	for {
		f, err := wire.ReadFrame(rw, wire.ToEnforcer)
		if err == io.EOF {
			return nil
		}
		var m wire.Msg
		if err == nil {
			m, err = wire.Decode(wire.ToEnforcer, f)
		}
		if err == nil && f.Type == wire.THello {
			err = wire.ErrType // one hello per connection
		}
		if err != nil {
			return c.refuse(KindFrame, 0, err.Error(), err)
		}
		if c.cfg.Revoked(c.cfg.Core) {
			return c.refuse(KindFrame, 0, "the core's channel key is revoked", ErrRevoked)
		}
		if out := c.handle(m); out != nil {
			if err := s.send(out); err != nil {
				return err
			}
		}
	}
}

// refuse logs a refused frame, counts it, and returns err.
func (c *Channel) refuse(k Kind, id uint64, reason string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cfg.Log(Event{At: c.cfg.Now(), Kind: k, ID: id, Code: wire.Refused, Reason: reason})
	c.count(KindRefused)
	return err
}

func (s *session) send(m wire.Msg) error {
	f, err := wire.Encode(wire.ToCore, m)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return wire.WriteFrame(s.w, wire.ToCore, f)
}

// Challenge sends a device's challenge to the core and waits for its
// answer on the channel, which goes to Config.Answer once.
func (c *Channel) Challenge(id uint64, data []byte) error {
	c.mu.Lock()
	s := c.session
	if s == nil {
		c.mu.Unlock()
		return ErrNoSession
	}
	if !c.outstanding[id] && len(c.outstanding) >= MaxOutstanding {
		c.mu.Unlock()
		return ErrBusy
	}
	c.outstanding[id] = true
	c.mu.Unlock()
	err := s.send(wire.Challenge{ID: id, Data: data})
	if err != nil {
		c.mu.Lock()
		delete(c.outstanding, id)
		c.mu.Unlock()
	}
	return err
}

// Alert sends a text or call the enforcer composed to the kernel for the
// owner line (slice h). The core may drop it; the enforcer's own light,
// page and log are the record (NET-2 Texts and calls).
func (c *Channel) Alert(a wire.Alert) error {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s == nil {
		return ErrNoSession
	}
	return s.send(a)
}
