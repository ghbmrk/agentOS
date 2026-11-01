// Package chancheck is the kernel's check of every message it sends on
// the enforcer channel, before it sends it (NET-2 The channel, D-255,
// #4373): the message must be inside the one format definition and inside
// its kind's rate, both read from broker/enforcer/wire, never a copy, so an
// honest core never sends what the enforcer trips on.
//
// The format check runs the enforcer's own read path over the bytes the
// kernel will write. The rate check keeps one wire.Bucket per kind and
// errs late: the enforcer counts a message somewhere between the moment
// the kernel writes it and the moment its answer is read, so the check
// finds a token at the first and spends it at the second. A message whose
// answer never came is spent when the next connection's hello is
// answered, by which time the enforcer has stopped counting the old
// connection (broker/enforcer/channel ENF-d-9). A hello with no answer, a
// restart and the two boxes' clock rates are covered as ASSUMPTIONS.md
// says.
//
// It is the check only: it does no I/O, holds no key and is safe for
// concurrent use. The kernel's channel client writes exactly the bytes
// Frame returns and reports each answer and each lost connection.
package chancheck

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Margin slows the clock the rate check reads by one part in Margin, so
// the kernel's intervals are never shorter than the enforcer's while the
// two boxes' clock rates differ by less than that (KRN-chan-4).
const Margin = 64

// MaxLate is how long after a connection ends a hello the kernel wrote on
// it, unanswered, may still be counted (KRN-chan-3). It is less than the
// hello rate's burst less one interval, which New rests on (KRN-chan-5).
const MaxLate = 2 * time.Minute

// The check's refusals. Each is fixed text.
var (
	// ErrFormat: the message is outside the format definition; the
	// enforcer would trip on it.
	ErrFormat = errors.New("chancheck: message outside the channel's format")
	// ErrRate: the message is past its kind's rate; the enforcer would
	// trip on it. Its kind has a token again later.
	ErrRate = errors.New("chancheck: message past its kind's rate")
	// ErrWait: a message of this kind is still unanswered.
	ErrWait = errors.New("chancheck: a message of this kind is unanswered")
	// ErrOrder: a connection opens with one hello, and nothing else is
	// sent on it until the enforcer's hello is read.
	ErrOrder = errors.New("chancheck: not the message this connection takes next")
	// ErrTicket: the ticket is not this gate's unanswered one.
	ErrTicket = errors.New("chancheck: no such unanswered message")
)

type conn uint8

const (
	closed  conn = iota // the next message is a connection's hello
	opening             // the hello is written, its answer not yet read
	open                // the enforcer's hello is read
)

// Gate is the check. Its zero value is not usable; call New.
type Gate struct {
	mu    sync.Mutex
	epoch time.Time
	conn  conn
	kinds map[wire.RateKind]*kind
}

type kind struct {
	b *wire.Bucket
	// out is the unanswered message's slot, nil for none.
	out *slot
	// pending messages the enforcer may still count until a later
	// connection's hello is answered: spent then, at that time.
	pending int
}

// Ticket is one message Frame passed, until its answer.
type Ticket struct {
	g *Gate
	s *slot
}

// slot is one unanswered message; a ticket matches by its address.
type slot struct{ k wire.RateKind }

// New is a gate at now, the start of this run of the kernel. An earlier
// run may have sent a full burst of every kind, so New counts one: the
// hello's at now, and each request kind's when the first hello is
// answered (KRN-chan-5). The caller passes time.Now, whose monotonic
// reading never steps (KRN-chan-4).
func New(now time.Time) *Gate {
	g := &Gate{epoch: now, kinds: map[wire.RateKind]*kind{}}
	t := g.clock(now)
	for _, k := range wire.RateKinds {
		l := wire.Rate(k)
		st := &kind{b: wire.NewBucket(l, t)}
		if k == wire.RateHello {
			for range l.Burst {
				st.b.Spend(t)
			}
		} else {
			st.pending = l.Burst
		}
		g.kinds[k] = st
	}
	return g
}

// clock is now on the check's slowed clock (Margin).
func (g *Gate) clock(now time.Time) time.Time {
	d := now.Sub(g.epoch)
	return g.epoch.Add(d - d/Margin)
}

// Frame checks m and returns the bytes to write for it, exactly, and its
// ticket for Answered. A hello must be a connection's first message, and
// any other message waits for the enforcer's hello; one message of each
// kind is unanswered at a time; and the message must be inside its kind's
// rate at now. On a refusal nothing is recorded and nothing may be sent.
func (g *Gate) Frame(m wire.Msg, now time.Time) ([]byte, Ticket, error) {
	b, err := encode(m)
	if err != nil {
		return nil, Ticket{}, err
	}
	k := wire.RateKindOf(m.Type())
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.kinds[k]
	if st == nil {
		return nil, Ticket{}, ErrFormat
	}
	if (k == wire.RateHello) != (g.conn == closed) || k != wire.RateHello && g.conn != open {
		return nil, Ticket{}, ErrOrder
	}
	if st.out != nil {
		return nil, Ticket{}, ErrWait
	}
	if !st.b.Has(g.clock(now)) {
		return nil, Ticket{}, ErrRate
	}
	st.out = &slot{k: k}
	if k == wire.RateHello {
		g.conn = opening
	}
	return b, Ticket{g: g, s: st.out}, nil
}

// encode is m's frame as the kernel writes it, passed through the
// enforcer's own read path: what ReadFrame and Decode take on its side,
// and nothing else, so the bytes cannot be outside the format.
func encode(m wire.Msg) ([]byte, error) {
	if m == nil {
		return nil, ErrFormat
	}
	f, err := wire.Encode(wire.ToEnforcer, m)
	if err != nil {
		return nil, ErrFormat
	}
	var buf bytes.Buffer
	if wire.WriteFrame(&buf, wire.ToEnforcer, f) != nil {
		return nil, ErrFormat
	}
	b := buf.Bytes()
	r := bytes.NewReader(b)
	back, err := wire.ReadFrame(r, wire.ToEnforcer)
	if err != nil || r.Len() != 0 || back.Type != f.Type {
		return nil, ErrFormat
	}
	if _, err := wire.Decode(wire.ToEnforcer, back); err != nil {
		return nil, ErrFormat
	}
	return b, nil
}

// Answered records that t's answer was read at now: for a request, its
// Result or ReadReply; for a hello, the enforcer's verified hello, which
// opens the connection. The enforcer counted the message no later than
// now, so its token is spent at now. The hello's answer also spends every
// pending message at now.
func (g *Gate) Answered(t Ticket, now time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t.g != g || t.s == nil || g.kinds[t.s.k].out != t.s {
		return ErrTicket
	}
	st := g.kinds[t.s.k]
	at := g.clock(now)
	st.b.Spend(at)
	st.out = nil
	if t.s.k == wire.RateHello {
		g.conn = open
		for _, o := range g.kinds {
			for ; o.pending > 0; o.pending-- {
				o.b.Spend(at)
			}
		}
	}
	return nil
}

// Lost records that the connection ended at now, or that the kernel gave
// up on it: every message still unanswered may yet be counted. A request
// is spent when the next hello is answered; a hello, at now plus MaxLate.
// The next message is a new connection's hello.
func (g *Gate) Lost(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	at := g.clock(now)
	for k, st := range g.kinds {
		if st.out == nil {
			continue
		}
		st.out = nil
		if k == wire.RateHello {
			st.b.Spend(at.Add(MaxLate))
		} else {
			st.pending++
		}
	}
	g.conn = closed
}
