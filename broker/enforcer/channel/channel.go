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
// step. A failed hello is dropped and never trips it. Only the connection
// whose hello was accepted last counts: a frame on an earlier one ends it
// uncounted. Every request is logged, and a channel command that turns a
// heater off or shuts a valve texts the owner.
//
// It is enforcer code: it imports the standard library, broker/kernel/key
// through the policy, and the enforcer's own packages only
// (broker/daemon/arc2_test.go). Its assumptions are in ASSUMPTIONS.md.
package channel

import (
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
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
// Stage is called under the channel's locks, possibly concurrently, and
// must not call the channel; Trip is called after they are released, and
// once it returns Stage reports the trip. Trip is called again for each
// malformed frame of a core already Tripped, so it must be idempotent and
// cheap then, with no write per call (#4606); a Reflashed core's malformed
// frame is a new trip that moves it back to Tripped. Two connections can
// queue Trip at once, so it must be safe under concurrent calls.
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
	// Counts is the enforcer's byte-cap counts as of the request
	// (broker/enforcer/traffic Counter.Counts after a fresh reading), the
	// summary the kernel's check reads (NET-2 Byte caps, #4174).
	Counts func() (wire.Counts, error)
	// Answer hands the core's answer to a device challenge back to the
	// device that asked (slice k), under the radio host's ID for it. It
	// runs on the connection's read loop, outside the channel's lock, and
	// the ID is free for another challenge once it returns.
	Answer func(id uint64, data []byte)
	// Log takes one line per request and refusal. It runs outside the
	// channel's lock, so it may call the channel, and concurrently for
	// several connections (ENF-d-7).
	Log func(Event)
	// Now is the wall clock the log lines and the policy's times read;
	// nil is time.Now. Now and Elapsed are called from several
	// connections at once. No rate reads it, so a step of the wall clock
	// neither refills nor pauses one.
	Now func() time.Time
	// Elapsed is the rate clock (#4507): the enforcer's time since any
	// fixed origin, which must never step back and must keep counting
	// while the box is suspended, as Linux's CLOCK_BOOTTIME does, so the
	// rates refill while the kernel's check, on the core's clock, sees
	// time pass (chancheck KRN-chan-4). Slice l wires CLOCK_BOOTTIME.
	// nil is Go's monotonic reading since New, which never steps back but
	// stops while the box is suspended (ENF-d-10).
	Elapsed func() time.Duration
	// SendTimeout bounds each write to the core; zero is
	// DefaultSendTimeout. A core that stops reading fails its connection
	// instead of holding a caller of Alert or Challenge (#4307).
	SendTimeout time.Duration
}

// DefaultSendTimeout is a write's bound when Config.SendTimeout is zero:
// radio.Host's link timeout (ENF-k-8), a checkpoint, not a measurement.
const DefaultSendTimeout = 10 * time.Second

// Conn is a connection from the core: a stream the channel can put a
// write deadline on. The daemon's *tls.Conn and any net.Conn are.
type Conn interface {
	io.ReadWriter
	SetWriteDeadline(time.Time) error
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
	// Dropped is how many of a cut core's lines went unlogged past
	// KindPaused's bucket since the core's line before this one, so the
	// record keeps how much a cut core tried (#4657). Only the core's own
	// lines and the restore's (Channel.Flush, #4726) carry it, never a
	// failed hello's or the quiet line (#4683). A
	// sink must keep it: the logged lines plus the sum of Dropped are
	// everything the cut core sent (ENF-d-4). CheckSink checks a sink keeps
	// it and every other field (#4709).
	Dropped int
}

// Errors Serve and the push methods return.
var (
	ErrConfig    = errors.New("channel: config incomplete")
	ErrHello     = errors.New("channel: hello refused")
	ErrRevoked   = errors.New("channel: the core's channel key is revoked")
	ErrNoSession = errors.New("channel: no core connected")
	ErrBusy      = errors.New("channel: too many challenges outstanding")
	// ErrOutstanding refuses a challenge whose ID is still waiting for
	// its answer, or whose answer is still being handed over, so the
	// radio host never takes the first's answer for the second's (#3759,
	// #4550).
	ErrOutstanding = errors.New("channel: a challenge with this id is outstanding")
	// ErrSuperseded ends a connection whose frame came after a later
	// connection's hello was accepted (ENF-d-9).
	ErrSuperseded = errors.New("channel: a later connection replaced this one")
)

// MaxOutstanding caps the device challenges waiting for an answer.
const MaxOutstanding = 64

// ChallengeLife is how long, on the rate clock, a device challenge waits
// for its answer. Past it, or once the connection it was sent on is no
// longer the current one, the challenge is over: no answer to it is
// handed over, and its ID and its place under MaxOutstanding are free
// (#4550, ASSUMPTIONS ENF-d-11).
const ChallengeLife = time.Minute

// Channel is the enforcer's end. One Channel serves every connection the
// daemon accepts from the core, so its rates outlive a reconnect.
type Channel struct {
	cfg Config

	// helloMu guards hello, the core's hello rate, alone: the hello is
	// counted without c.mu (countHello).
	helloMu sync.Mutex
	hello   *wire.Bucket
	// tripping counts the trips decided whose Cut.Trip has not returned.
	tripping atomic.Int32

	mu sync.Mutex
	// buckets are the core's request rates, one per request
	// wire.RateKind; refused and preAuthB are the enforcer's own.
	buckets  map[wire.RateKind]*wire.Bucket
	refused  *wire.Bucket
	preAuthB *wire.Bucket
	pausedB  *wire.Bucket
	// challenges are the device challenges not yet over, by the radio
	// host's ID; byWire finds one by the ID its frame carried, which the
	// channel chooses and never reuses (lastWire, counting up from 1),
	// until its answer comes.
	challenges map[uint64]*challenge
	byWire     map[uint64]uint64
	lastWire   uint64
	// session is the connection whose hello the channel accepted last.
	// Only its requests act or count: a frame on any other connection
	// ends that connection uncounted (ENF-d-9).
	session *session
	// preAuthQuiet is set while failed hellos are over KindPreAuth's
	// bucket and dropped unlogged.
	preAuthQuiet bool
	// pausedQuiet is set while a cut core's lines are over KindPaused's
	// bucket and go unlogged (#4558, #4606).
	pausedQuiet bool
	// dropped counts a cut core's lines dropped past KindPaused's bucket
	// since the core's last line logged; the next one carries it
	// (Event.Dropped). It is in memory only: a restart loses it (ENF-d-4).
	dropped int
	// queued holds the Log, Alerts, Answer and Cut.Trip calls made under
	// mu; release runs them after unlocking, so a sink that calls the
	// channel cannot deadlock it.
	queued []func()
}

type session struct {
	mu      sync.Mutex
	w       Conn
	timeout time.Duration
	// stalled is the write error that ended this session's writes: a
	// write past its deadline may have left part of a frame, so nothing
	// more is written and every later send returns it at once (#4307).
	// It is read without mu, so the read loop never waits on a write.
	stalled atomic.Pointer[error]
}

// challenge is one device challenge sent to the core.
type challenge struct {
	wire uint64    // the ID its frame carried
	s    *session  // the connection it was sent on
	at   time.Time // when, on the rate clock
	// answered is set once its answer is taken; it stays until Answer
	// returns, so its ID is not reused while the answer is handed over.
	answered bool
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
	if cfg.SendTimeout <= 0 {
		cfg.SendTimeout = DefaultSendTimeout
	}
	if cfg.Elapsed == nil {
		t0 := time.Now()
		cfg.Elapsed = func() time.Duration { return time.Since(t0) }
	}
	c := &Channel{cfg: cfg, buckets: map[wire.RateKind]*wire.Bucket{}, challenges: map[uint64]*challenge{}, byWire: map[uint64]uint64{}}
	now := c.rateNow()
	c.refused, c.preAuthB, c.pausedB = wire.NewBucket(refusedLimit, now), wire.NewBucket(preAuthLimit, now), wire.NewBucket(pausedLimit, now)
	for _, k := range wire.RateKinds() {
		if k == wire.RateHello {
			c.hello = wire.NewBucket(wire.Rate(k), now)
		} else {
			c.buckets[k] = wire.NewBucket(wire.Rate(k), now)
		}
	}
	return c, nil
}

// Serve runs one connection from the core: rw is the TLS stream the daemon
// accepted and exporter its wire.ExporterLen bytes under
// wire.ExporterLabel. It returns when the stream ends or a frame is
// refused; the daemon then closes the connection.
func (c *Channel) Serve(rw Conn, exporter []byte) error {
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
	mine, err := wire.SignHello(wire.RoleEnforcer, c.cfg.Key, exporter)
	if err != nil {
		return err
	}
	c.countHello()
	// This connection becomes the session before the enforcer's hello is
	// written, and s.mu is held until it is, so no challenge or alert
	// goes ahead of it. A kernel that has read the enforcer's hello knows
	// no frame of an earlier connection counts after it (ENF-d-9).
	s := &session{w: rw, timeout: c.cfg.SendTimeout}
	s.mu.Lock()
	c.mu.Lock()
	c.session = s
	c.mu.Unlock()
	err = s.write(mine)
	s.mu.Unlock()
	defer func() {
		c.mu.Lock()
		if c.session == s {
			c.session = nil
		}
		c.mu.Unlock()
	}()
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.logCut(Event{At: c.cfg.Now(), Kind: KindHello, Reason: "core connected"})
	c.release()

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
		// A core that stopped reading gets no request acted on whose
		// answer it could not read; the connection ends.
		if err := s.failed(); err != nil {
			return err
		}
		out, err := c.handle(s, m)
		if err != nil {
			return err
		}
		if out != nil {
			if err := s.send(out); err != nil {
				return err
			}
		}
	}
}

// rateNow is the time every rate reads: the enforcer's elapsed time
// (Config.Elapsed), never its wall clock (#4507). The buckets also never
// let it step back (wire.Bucket).
func (c *Channel) rateNow() time.Time { return rateEpoch.Add(c.cfg.Elapsed()) }

// rateEpoch is the rate clock's zero; only differences of it are read.
var rateEpoch = time.Unix(0, 0)

// countHello counts an authenticated hello as it arrives. Only the
// authenticated core counts toward a trip (#3755), and only while it is
// not already cut: after a trip its reconnects take their rate but trip
// nothing more (ENF-d-4). It holds helloMu, never c.mu, so no radio,
// policy or source call a request makes under c.mu can delay the count
// past the kernel check's MaxLate (#4508, KRN-chan-3).
func (c *Channel) countHello() {
	c.helloMu.Lock()
	open := c.stage() == Open
	trip := !c.hello.Take(c.rateNow()) && open
	var at time.Time
	if trip {
		c.tripping.Add(1)
		at = c.cfg.Now() // the line's time is the decision's (#4572)
	}
	c.helloMu.Unlock()
	if trip {
		reason := "burst of " + string(KindHello) + " past the rate: tripped the core"
		c.cfg.Cut.Trip(reason)
		c.tripping.Add(-1)
		// The line goes through log like the core's other lines, so it
		// carries a count pending since a restore (#4708). Only the line
		// waits for c.mu; the count and the trip above never do.
		c.mu.Lock()
		c.log(Event{At: at, Kind: KindTrip, What: string(KindHello), Reason: reason})
		c.release()
	}
}

// stage is the cut's stage, or Tripped while a trip the channel decided
// has not yet returned from Cut.Trip: from the decision on, no request
// acts (ENF-d-4).
func (c *Channel) stage() Stage {
	if c.tripping.Load() > 0 {
		return Tripped
	}
	return c.cfg.Cut.Stage()
}

// refuse logs a refused frame, counts it, and returns err.
func (c *Channel) refuse(k Kind, id uint64, reason string, err error) error {
	c.mu.Lock()
	defer c.release()
	c.logCut(Event{At: c.cfg.Now(), Kind: k, ID: id, Code: wire.Refused, Reason: reason})
	c.countRefused()
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
// returns err. A frame from a core already tripped still calls Cut.Trip,
// but its line goes under KindPaused's bucket like the core's other lines
// (logCut), so cycling connections cannot fill the log (#4606); at the
// Reflashed stage it trips the core again, and that line is always logged.
func (c *Channel) trip(reason string, err error) error {
	c.mu.Lock()
	defer c.release()
	st := c.stage()
	again := st != Open && st != Reflashed
	c.queueTrip(reason)
	e := Event{At: c.cfg.Now(), Kind: KindFrame, Code: wire.Refused, Reason: reason}
	if !again || c.logPaused(e.At) {
		c.log(e)
	}
	return err
}

// queueTrip queues Cut.Trip to run after c.mu is released, and until it
// returns every request is answered Paused (stage). The caller holds
// c.mu.
func (c *Channel) queueTrip(reason string) {
	c.tripping.Add(1)
	c.queued = append(c.queued, func() { c.cfg.Cut.Trip(reason); c.tripping.Add(-1) })
}

// preAuth logs and drops a connection that failed before the core
// authenticated, and returns err. It counts in KindPreAuth's bucket, which
// never trips: anyone who reaches the port can fail a hello, and a trip
// would cut the real core until the owner's restore at home (#3755).
// Past the bucket one line says the drops go unlogged, so a flood cannot
// fill the log; the next line logged after the bucket refills ends that.
func (c *Channel) preAuth(reason string, err error) error {
	c.mu.Lock()
	defer c.release()
	now := c.cfg.Now()
	if c.preAuthB.Take(c.rateNow()) {
		c.preAuthQuiet = false
		c.logAside(Event{At: now, Kind: KindHello, Code: wire.Refused, Reason: reason})
	} else if !c.preAuthQuiet {
		c.preAuthQuiet = true
		c.logAside(Event{At: now, Kind: KindPreAuth, Code: wire.Refused, Reason: "failed hellos over the limit: dropped unlogged until the rate falls; the core is not tripped"})
	}
	return err
}

// logPaused reports whether a line about a cut core is logged: a request
// a trip paused (#4558), or the core's reconnect, refused frame or frame
// outside the format while it is cut (#4606). They share KindPaused's
// bucket; past it one line says they go unlogged, so a tripped core
// cannot fill the log however it sends them; the next line logged after
// the bucket refills ends that. Each line dropped is counted, and the
// core's next line logged carries the count (#4657, #4683). A trip is
// always logged. The caller holds c.mu.
func (c *Channel) logPaused(now time.Time) bool {
	if c.pausedB.Take(c.rateNow()) {
		c.pausedQuiet = false
		return true
	}
	if !c.pausedQuiet {
		c.pausedQuiet = true
		c.logAside(pausedLine(now, "a cut core's lines over the limit: dropped unlogged until the rate falls"))
	}
	c.dropped++
	return false
}

// pausedLine is a KindPaused line. Every one carries Code wire.Paused, the
// answer the cut core's lines it speaks for were given (#4740).
func pausedLine(at time.Time, reason string) Event {
	return Event{At: at, Kind: KindPaused, Code: wire.Paused, Reason: reason}
}

// Flush logs one KindPaused line carrying the count of a cut core's lines
// dropped unlogged since its last line logged, and ends the quiet, so the
// record has the count at the owner's restore instead of at the core's next
// line (#4726). DECOY-d's restore calls it once it has returned the cut to
// Open; with nothing pending it logs nothing. At any other stage it does
// nothing, so its line never claims a restore while the core is still cut,
// and the quiet and the count wait for the restore (#4740). Its line is not
// the core's, so the logged lines plus the sum of Dropped still equal what
// the cut core sent (ENF-d-4).
func (c *Channel) Flush() {
	c.mu.Lock()
	defer c.release()
	if c.stage() != Open {
		return
	}
	c.pausedQuiet = false
	if c.dropped != 0 {
		c.log(pausedLine(c.cfg.Now(), "the owner restored the core"))
	}
}

// logCut logs e, a line that records no trip, under KindPaused's bucket
// while the core is cut (any stage but Open), and always while it is
// open, where the hello's rate trips a reconnect flood (#4606). The
// caller holds c.mu.
func (c *Channel) logCut(e Event) {
	if c.stage() == Open || c.logPaused(e.At) {
		c.log(e)
	}
}

// log queues one log line to Config.Log, which release hands over after
// c.mu is let go, so a log sink may call the channel (ENF-d-7). The caller
// holds c.mu.
func (c *Channel) log(e Event) {
	e.Dropped, c.dropped = c.dropped, 0
	c.logAside(e)
}

// logAside queues a line that is not the core's own (a failed hello, or
// the quiet line), so it carries no count of the core's dropped lines,
// which stays for the core's next line (#4683). The caller holds c.mu.
func (c *Channel) logAside(e Event) {
	c.queued = append(c.queued, func() { c.cfg.Log(e) })
}

// release unlocks c.mu and then runs the sink calls queued under it, in
// the order they were queued.
func (c *Channel) release() {
	q := c.queued
	c.queued = nil
	c.mu.Unlock()
	for _, f := range q {
		f()
	}
}

func (s *session) send(m wire.Msg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.write(m)
}

// failed is the error that stopped s's writes, if any.
func (s *session) failed() error {
	if p := s.stalled.Load(); p != nil {
		return *p
	}
	return nil
}

// write sends m within s.timeout; the caller holds s.mu. A write past its
// deadline stops the session's writes, so a caller queued behind it
// waits for at most that one write (#4307).
func (s *session) write(m wire.Msg) error {
	if err := s.failed(); err != nil {
		return err
	}
	f, err := wire.Encode(wire.ToCore, m)
	if err != nil {
		return err
	}
	if err := s.w.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		s.stalled.Store(&err)
		return err
	}
	err = wire.WriteFrame(s.w, wire.ToCore, f)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		s.stalled.Store(&err)
	}
	return err
}

// Challenge sends a device's challenge to the core and waits for its
// answer on the channel, which goes to Config.Answer once. The radio host
// chooses id; one not yet over is refused (ErrOutstanding), and an
// answered one is over once Answer returns. The frame carries an ID the
// channel chooses and never reuses, so an answer to a challenge that is
// over, however late, is refused and never handed over as another's:
// each answer belongs to exactly one challenge (#4550).
func (c *Channel) Challenge(id uint64, data []byte) error {
	c.mu.Lock()
	s := c.session
	if s == nil {
		c.mu.Unlock()
		return ErrNoSession
	}
	c.endChallenges()
	if c.challenges[id] != nil {
		c.mu.Unlock()
		return ErrOutstanding
	}
	if len(c.challenges) >= MaxOutstanding {
		c.mu.Unlock()
		return ErrBusy
	}
	c.lastWire++
	ch := &challenge{wire: c.lastWire, s: s, at: c.rateNow()}
	c.challenges[id], c.byWire[ch.wire] = ch, id
	c.mu.Unlock()
	err := s.send(wire.Challenge{ID: ch.wire, Data: data})
	if err != nil {
		// A write can fail after the core has the whole frame, and its
		// answer may already be taken: an answered challenge stays until
		// Answer returns, which then frees it (#4607).
		c.mu.Lock()
		if !ch.answered {
			c.dropChallenge(id, ch)
		}
		c.mu.Unlock()
	}
	return err
}

// over reports whether ch, not answered, is over: sent ChallengeLife ago
// or more, or on a connection that is no longer the current one. The
// caller holds c.mu.
func (c *Channel) over(ch *challenge) bool {
	return ch.s != c.session || c.rateNow().Sub(ch.at) >= ChallengeLife
}

// endChallenges drops every unanswered challenge that is over. The caller
// holds c.mu.
func (c *Channel) endChallenges() {
	for id, ch := range c.challenges {
		if !ch.answered && c.over(ch) {
			c.dropChallenge(id, ch)
		}
	}
}

// dropChallenge drops ch, the challenge with the radio host's ID id, if it
// is still that ID's. The caller holds c.mu.
func (c *Channel) dropChallenge(id uint64, ch *challenge) {
	if c.challenges[id] == ch {
		delete(c.challenges, id)
		delete(c.byWire, ch.wire)
	}
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
