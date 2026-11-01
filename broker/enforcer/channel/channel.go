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
// it, its one secure-direction command (Table). Every kind is rate-limited
// by the rates the kernel checks before it sends (D-255): a frame outside
// the format, or a burst of any kind past its rate, from the authenticated
// core is a core trip at the enforcer (KRN-12, Cut). After a trip the
// channel answers every request Paused, logging it, while the hello, which
// carries the heartbeat, still connects; at the "core reflashed" step the
// traffic summaries flow again, and everything else waits for the owner's
// passkey restore (D-260, D-262). Refusals, which the kernel cannot
// foresee, have their own rate with no trip: past it, every request is
// refused RateLimited until the rate refills by itself, with no owner
// step. A failed hello is dropped and never trips it. Every request is logged, and a channel command that
// turns a heater off or shuts a valve texts the owner.
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
// when a command turned a heater off or shut a valve.
type Alerts interface {
	SafetyOff(device string, v wire.Verb)
}

// Stage is how far a core trip has lifted (KRN-12 Response, D-260, D-262).
type Stage uint8

const (
	// Open: no core trip is in force.
	Open Stage = iota
	// Tripped: the core is cut. Only the hello, with the heartbeat it
	// carries, gets through; every request is answered Paused.
	Tripped
	// Reflashed: the owner took the "core reflashed" step. Traffic
	// summaries flow again, so the restore's capped backup route has a
	// fresh count; commands, tightenings, other reads and the core's
	// records wait for the passkey restore, which returns the stage to
	// Open.
	Reflashed
)

// Cut is the enforcer's core trip (KRN-12; DECOY-d owns cutting the core
// and lifting the cut). The channel trips it on a frame outside the format
// and on a burst past a rate, and asks it the stage before every request.
// Stage is called under the channel's lock and must not call the channel;
// Trip is called after it is released.
type Cut interface {
	Trip(reason string)
	Stage() Stage
}

// Config is what a channel is built from. Core, Key, Revoked, Policy,
// Radio, Alerts, Cut and Log are required, so no command acts unlogged, no
// safety command goes untexted and no malformed or excessive message goes
// untripped (NET-2); a nil read source refuses that read.
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
	Cut    Cut
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
}

// Event is one log line. Every field is the enforcer's own words or a
// device ID the signed policy holds (another name only as its hash,
// logName); nothing else of the peer's is in it.
type Event struct {
	At     time.Time
	Kind   Kind
	ID     uint64
	Device string
	// Other is a removed pair's second member; Device is its first. Each
	// has its own field because a signed ID may hold any separator a
	// joined string would use (#4066).
	Other  string
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
// daemon accepts from the core, so its rates outlive a reconnect.
type Channel struct {
	cfg Config

	mu          sync.Mutex
	buckets     map[Kind]*bucket
	outstanding map[uint64]bool
	session     *session
	// preAuthQuiet is set while failed hellos are over KindPreAuth's
	// bucket and dropped unlogged.
	preAuthQuiet bool
	// queued holds the Alerts and Answer calls made under mu; release runs
	// them after unlocking, so a sink that sends on the channel cannot
	// deadlock it.
	queued []func()
}

type session struct {
	mu sync.Mutex
	w  io.Writer
}

// New checks cfg and returns a channel.
func New(cfg Config) (*Channel, error) {
	if len(cfg.Core) != ed25519.PublicKeySize || len(cfg.Key) != ed25519.PrivateKeySize ||
		cfg.Revoked == nil || cfg.Policy == nil || cfg.Radio == nil || cfg.Alerts == nil || cfg.Cut == nil || cfg.Log == nil {
		return nil, ErrConfig
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &Channel{cfg: cfg, buckets: map[Kind]*bucket{}, outstanding: map[uint64]bool{}}
	now := cfg.Now()
	for k, l := range DefaultLimits {
		if o, ok := cfg.Limits[k]; ok {
			l = o
		}
		c.buckets[k] = newBucket(l, now)
	}
	return c, nil
}

// Serve runs one connection from the core: rw is the TLS stream the daemon
// accepted and exporter its wire.ExporterLen bytes under
// wire.ExporterLabel. It returns when the stream ends or a frame is
// refused; the daemon then closes the connection.
func (c *Channel) Serve(rw io.ReadWriter, exporter []byte) error {
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
		return c.preAuth("hello refused", ErrHello)
	}
	if c.cfg.Revoked(c.cfg.Core) {
		return c.preAuth("the core's channel key is revoked", ErrRevoked)
	}
	// Only the authenticated core counts toward a trip (#3755).
	c.mu.Lock()
	c.count(KindHello)
	c.release()
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
			if malformed(err) {
				return c.trip(err.Error()+": tripped the core", err)
			}
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
	defer c.release()
	c.cfg.Log(Event{At: c.cfg.Now(), Kind: k, ID: id, Code: wire.Refused, Reason: reason})
	c.count(KindRefused)
	return err
}

// malformed reports whether err is a frame outside the format definition,
// a core trip (NET-2 The channel, D-255): an unknown or misdirected type, a
// length out of bounds or a payload that does not decode, a second hello
// included. A stream that ends mid-frame (wire.ErrShort) is a lost
// connection, not a message, and only ends it.
func malformed(err error) bool {
	return errors.Is(err, wire.ErrType) || errors.Is(err, wire.ErrLength) || errors.Is(err, wire.ErrPayload)
}

// trip logs a refused frame outside the format, trips the core and
// returns err.
func (c *Channel) trip(reason string, err error) error {
	c.mu.Lock()
	defer c.release()
	c.cfg.Log(Event{At: c.cfg.Now(), Kind: KindFrame, Code: wire.Refused, Reason: reason})
	c.queueTrip(reason)
	return err
}

// queueTrip queues Cut.Trip to run after c.mu is released. The caller
// holds c.mu.
func (c *Channel) queueTrip(reason string) {
	c.queued = append(c.queued, func() { c.cfg.Cut.Trip(reason) })
}

// preAuth logs and drops a connection that failed before the core
// authenticated, and returns err. It counts in KindPreAuth's bucket, which
// never trips: anyone who reaches the port can fail a hello, and a trip
// would cut the real core until the owner's restore at home (#3755).
// Past the bucket one line says the drops go unlogged, so a flood cannot
// fill the log; the next line logged after the bucket refills ends that.
func (c *Channel) preAuth(reason string, err error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	if c.buckets[KindPreAuth].take(now) {
		c.preAuthQuiet = false
		c.cfg.Log(Event{At: now, Kind: KindHello, Code: wire.Refused, Reason: reason})
	} else if !c.preAuthQuiet {
		c.preAuthQuiet = true
		c.cfg.Log(Event{At: now, Kind: KindPreAuth, Code: wire.Refused, Reason: "failed hellos over the limit: dropped unlogged until the rate falls; the core is not tripped"})
	}
	return err
}

// release unlocks c.mu and then runs the sink calls queued under it.
func (c *Channel) release() {
	q := c.queued
	c.queued = nil
	c.mu.Unlock()
	for _, f := range q {
		f()
	}
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
