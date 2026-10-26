package withings

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Keeper is the core-side custody of the scale's kl (CLK-1, STO-2): Open
// lends kl from the sealed store for one call and wipes it after
// (clerk.Secrets.DeviceKey), so kl is in memory only while one answer is
// computed. It answers only for the paired scale's MAC string, and for one
// session at a time, so a peer cannot reflect our own challenge back to us
// through a second, concurrent session.
type Keeper struct {
	Open func(fn func(kl []byte) error) error
	// MAC is the paired scale's MAC string, as its challenge carries it.
	MAC string

	once sync.Once
	turn chan struct{}
	mu   sync.Mutex
	owns [][]byte // our recent own challenges, newest last
}

// keptOwns bounds the own challenges a Keeper remembers.
const keptOwns = 16

// ErrNotPaired is a challenge for a scale other than the paired one.
var ErrNotPaired = errors.New("withings: challenge is not from the paired scale")

// ErrReflected is a challenge equal to one of our own.
var ErrReflected = errors.New("withings: challenge is our own, not answered")

// ErrProofUsed is a session's prover asked again or out of order.
var ErrProofUsed = errors.New("withings: proof already given for this session")

func (k *Keeper) init() { k.once.Do(func() { k.turn = make(chan struct{}, 1) }) }

// Prove waits for the Keeper's one turn and returns that session's prover.
// Close gives the turn back; it is safe to call more than once.
func (k *Keeper) Prove(ctx context.Context) (*Proof, error) {
	k.init()
	select {
	case k.turn <- struct{}{}:
		return &Proof{k: k}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Format prints no field, whatever the verb.
func (k *Keeper) Format(f fmt.State, _ rune) { fmt.Fprint(f, "withings.Keeper{kl: sealed}") }

func (k *Keeper) reflected(challenge []byte) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, o := range k.owns {
		if subtle.ConstantTimeCompare(o, challenge) == 1 {
			return true
		}
	}
	return false
}

func (k *Keeper) remember(own []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.owns = append(k.owns, bytes.Clone(own))
	if len(k.owns) > keptOwns {
		k.owns = k.owns[1:]
	}
}

func (k *Keeper) with(mac string, fn func(kl []byte)) error {
	if mac != k.MAC {
		return ErrNotPaired
	}
	return k.Open(func(kl []byte) error {
		fn(kl)
		return nil
	})
}

// Proof is one session's prover: one Answer, then one Check, in that order.
type Proof struct {
	k        *Keeper
	mu       sync.Mutex
	answered []byte
	checked  bool
	closed   bool
}

// Answer answers the scale's challenge once, for the paired scale only, and
// never a challenge we sent ourselves.
func (p *Proof) Answer(challenge []byte, mac string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.answered != nil {
		return nil, ErrProofUsed
	}
	if p.k.reflected(challenge) {
		return nil, ErrReflected
	}
	var out []byte
	if err := p.k.with(mac, func(kl []byte) { out = answerFor(challenge, mac, kl) }); err != nil {
		return nil, err
	}
	p.answered = bytes.Clone(challenge)
	return out, nil
}

// Check checks the scale's answer to our own challenge once, after Answer.
// The own challenge is remembered, so no later session answers it.
func (p *Proof) Check(own []byte, mac string, answer []byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.answered == nil || p.checked || bytes.Equal(own, p.answered) {
		return false
	}
	p.checked = true
	p.k.remember(own)
	ok := false
	if err := p.k.with(mac, func(kl []byte) {
		ok = subtle.ConstantTimeCompare(answerFor(own, mac, kl), answer) == 1
	}); err != nil {
		return false
	}
	return ok
}

// Close ends the session's turn.
func (p *Proof) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		<-p.k.turn
	}
}

// Label is a reading event's data-flow label: always private (PLN-3).
const Label = "private"

// Event is one reading as it goes onto the bus (DEV-8): private, untrusted
// and unverified (DEV-3), and carrying no text from the scale (WBS-5).
type Event struct {
	Device     string
	Label      string
	Unverified bool
	Reading    Reading
}

// Clerk limits.
const (
	// DefaultGap is the least time between two reads put on the bus; reads
	// closer together are coalesced and counted.
	DefaultGap = time.Minute
	// DefaultMaxEvents bounds the events one read puts on the bus; a
	// weigh-in has at most one reading per measure, so one always fits.
	DefaultMaxEvents = 64
)

// Stats counts what the clerk did not put on the bus.
type Stats struct {
	Coalesced int // reads within the gap of the last one
	Deferred  int // readings past MaxEvents, left for the next read
	Others    int // readings of slot 0 or of user slots not the owner's
	Stale     int // owner readings at or below their slot's mark
	Failed    int // reads that ended in an error
}

// Clerk is the core-side Withings clerk (part b of #3272): it proves for the
// scale with the Keeper and puts each read's new owner readings on the bus
// through Emit, at most MaxEvents per read and one read per Gap.
type Clerk struct {
	Keeper *Keeper
	// Owner is the scale's user slots that are the owner's, chosen at
	// connection. Other household members weigh on the same scale; their
	// readings, and slot 0 (the scale did not know who), never leave.
	Owner map[uint32]bool
	// Emit puts one event on the bus.
	Emit func(Event) error
	// Marks is each owner slot's newest reading time already emitted; the
	// scale resends its whole store each time, so only newer ones go out.
	// The host keeps it across restarts (MarksCopy returns it).
	Marks     map[uint32]int64
	Gap       time.Duration
	MaxEvents int
	Now       func() time.Time
	// Log takes one line per read, a fixed phrase and numbers only.
	Log func(string)

	mu    sync.Mutex
	last  time.Time
	stats Stats
}

// Format prints no field, whatever the verb.
func (c *Clerk) Format(f fmt.State, _ rune) { fmt.Fprint(f, "withings.Clerk{}") }

func (c *Clerk) log(format string, args ...any) {
	if c.Log != nil {
		c.Log(fmt.Sprintf(format, args...))
	}
}

func (c *Clerk) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// due takes the read turn unless the last read was within the gap.
func (c *Clerk) due() bool {
	gap := c.Gap
	if gap <= 0 {
		gap = DefaultGap
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !c.last.IsZero() && now.Sub(c.last) < gap {
		c.stats.Coalesced++
		return false
	}
	c.last = now
	return true
}

// Read runs one session on link, if a read is due, and puts its new owner
// readings on the bus. A read within the gap of the last does not connect;
// it is counted as coalesced, and nothing is lost, because the scale keeps
// its store.
func (c *Clerk) Read(ctx context.Context, link Link) (int, error) {
	if !c.due() {
		return 0, nil
	}
	p, err := c.Keeper.Prove(ctx)
	if err != nil {
		return 0, err
	}
	s := &Session{Link: link, Prover: p, Log: c.Log}
	res, err := func() (Result, error) {
		defer p.Close()
		return s.Read(ctx)
	}()
	if err != nil {
		c.mu.Lock()
		c.stats.Failed++
		c.mu.Unlock()
		return 0, err
	}
	return c.deliver(res.Readings)
}

// deliver emits the owner's readings newer than their slot's mark, oldest
// first, whole weigh-ins only, up to MaxEvents. A mark moves past a
// weigh-in only once all its readings are emitted, so a deferred or failed
// one goes out at the next read: delivery is at least once, and the bus
// dedupes on (device, user, time, measure).
func (c *Clerk) deliver(rs []Reading) (int, error) {
	// One weigh-in has at most one reading per measure, so a smaller limit
	// would stall.
	limit := max(c.MaxEvents, len(measures))
	if c.MaxEvents <= 0 {
		limit = DefaultMaxEvents
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Marks == nil {
		c.Marks = map[uint32]int64{}
	}
	var fresh []Reading
	for _, r := range rs {
		switch {
		case r.User == 0 || !c.Owner[r.User]:
			c.stats.Others++
		case r.Time > c.Marks[r.User]:
			fresh = append(fresh, r)
		default:
			c.stats.Stale++
		}
	}
	sent := 0
	for i := 0; i < len(fresh); {
		j := i
		for j < len(fresh) && fresh[j].Time == fresh[i].Time && fresh[j].User == fresh[i].User {
			j++
		}
		if sent+(j-i) > limit {
			c.stats.Deferred += len(fresh) - i
			break
		}
		for _, r := range fresh[i:j] {
			r.Unverified = true
			if err := c.Emit(Event{Device: Declaration.Device, Label: Label, Unverified: true, Reading: r}); err != nil {
				c.log("bus refused a reading, %d sent", sent)
				return sent, err
			}
			sent++
		}
		c.Marks[fresh[i].User] = fresh[i].Time
		i = j
	}
	c.log("put %d readings on the bus", sent)
	return sent, nil
}

// Stats is what the clerk has not put on the bus so far.
func (c *Clerk) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// MarksCopy is the slot marks, for the host to keep.
func (c *Clerk) MarksCopy() map[uint32]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[uint32]int64, len(c.Marks))
	for k, v := range c.Marks {
		out[k] = v
	}
	return out
}
