// Package capgate is the kernel's stop short of each byte cap (SPEC NET-2
// Byte caps, D-255, #4173): before a send to a capped destination, the
// kernel asks it whether that send could pass the cap the enforcer
// enforces, and refuses the send, asking the owner for a raise, instead of
// letting the enforcer drop it and trip the core (KRN-12).
//
// The count is the enforcer's own, read from its traffic summaries on the
// channel, on the enforcer's day, so a clock difference cannot reset a cap
// early. To it the gate adds every send the count may not hold yet: each
// one reserved after the summary was asked for, and each one reserved
// earlier that had not ended when it was asked for. Which came first, an
// ask, an end or a pause, is told by a sequence the gate issues under its
// lock, never by a clock reading, so a clock that steps back cannot make a
// send look counted or a pre-pause answer look new. Each send reserves its
// size plus one full retry. The total may reach the cap but never pass it
// (wire.PastCap, the enforcer's own test): its group's cap, and, since a
// group can split at the enforcer's midnight, its destination's own.
//
// The clock only ages a count: it is fresh only while its summary was
// asked for no more than twice wire.SummaryInterval ago, by the kernel's
// own monotonic clock, and never when that clock reads earlier than the
// ask. With no fresh count the gate refuses every capped send, so with the
// enforcer down or its summaries paused after a core trip (D-260) the core
// sends nothing capped.
//
// It imports the standard library and broker/enforcer/wire only, for the
// shared format definition's interval and edge (broker/daemon/arc2_test.go,
// coreEnforcer). Its assumptions are in ASSUMPTIONS.md.
package capgate

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// Fresh is the age past which a count is none: twice the summary interval,
// so one lost summary does not make it stale (NET-2 Byte caps).
const Fresh = 2 * wire.SummaryInterval

// Retries is how many full re-sends a reservation covers: one, so a send
// the transport retries once still lands inside the cap.
const Retries = 1

var (
	// ErrNoCount refuses a send with no fresh count for its destination:
	// none yet, too old, a paused summary, or a destination the latest
	// summary names in no group.
	ErrNoCount = errors.New("capgate: no fresh count from the enforcer")
	// ErrSummary refuses a summary that cannot be the latest: asked before
	// a pause, at or before the summary already held (a ticket answers
	// once), on an earlier day, or for a ticket this gate did not issue.
	ErrSummary = errors.New("capgate: summary is older than the one held")
	// ErrGroup refuses a summary that names a destination in two groups.
	ErrGroup = errors.New("capgate: summary names a destination twice")
)

// PastCap is the refusal of a send that could pass a cap: its group's,
// or its destination's own. It carries what the owner is asked to raise
// that cap by.
type PastCap struct {
	Dest  string // the destination the send was for
	Cap   uint64 // the cap it could pass, in IP bytes on the enforcer's day
	Total uint64 // what counts against that cap, this send with its retry included
}

func (e *PastCap) Error() string {
	return fmt.Sprintf("capgate: a send to %s needs %d bytes against a cap of %d; ask the owner to raise it by %d", e.Dest, e.Total, e.Cap, e.Raise())
}

// Raise is the smallest raise that would let the send through.
func (e *PastCap) Raise() uint64 { return e.Total - e.Cap }

// Group is one cap group in a summary: the destinations that share an
// address that day (NET-1), each with its own cap, and the enforcer's
// count of the IP bytes the core sent them, acknowledgements and
// retransmissions included. The group's one cap is the sum of theirs.
type Group struct {
	Dests []Dest
	Count uint64
}

// Dest is one destination in a group and its own daily cap.
type Dest struct {
	Name string
	Cap  uint64
}

// group is a summary's group as the gate holds it.
type group struct {
	cap, count uint64
}

// Ticket is one summary request: the gate that issued it, its place in
// that gate's sequence, which orders it, and the kernel's time it was
// asked for, which only ages its count.
type Ticket struct {
	g   *Gate
	seq uint64
	at  time.Time
}

// Send is one reserved send, held until it ends.
type Send struct {
	r *reservation
}

type reservation struct {
	dest   string
	bytes  uint64 // size times (1 + Retries)
	ended  bool
	endSeq uint64 // the gate's sequence at End: every ask up to it came first
}

// Gate holds the latest fresh summary and the sends it may not hold. It
// is safe for concurrent use. The zero value is not usable; use New.
type Gate struct {
	mu     sync.Mutex
	now    func() time.Time
	seq    uint64    // the last ask issued; asks are 1, 2, 3...
	paused uint64    // the sequence at the last pause: no ask up to it counts
	held   uint64    // the held summary's ask
	asked  time.Time // and its time, which only ages the count
	day    uint32
	group  map[string]*group // by destination; nil while there is no count
	own    map[string]uint64 // each destination's own cap
	active map[*reservation]struct{}
}

// New is a gate with no count, on the clock now (time.Now in production;
// its monotonic reading is what ages a count).
func New(now func() time.Time) *Gate {
	return &Gate{now: now, active: map[*reservation]struct{}{}}
}

// Ask is called before a summary request is written, so every send that
// ends after the enforcer takes its count ends after the ask.
func (g *Gate) Ask() Ticket {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seq++
	return Ticket{g: g, seq: g.seq, at: g.now()}
}

// Summary takes the enforcer's answer to t: its day and its cap groups.
// It replaces the groups held, so groups that merged mid-day count as one.
func (g *Gate) Summary(t Ticket, day uint32, groups []Group) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if t.g != g || t.seq <= g.paused || t.seq <= g.held || day < g.day {
		return ErrSummary
	}
	by, own := map[string]*group{}, map[string]uint64{}
	for _, in := range groups {
		gr := &group{count: in.Count}
		for _, d := range in.Dests {
			if _, dup := by[d.Name]; dup {
				return ErrGroup
			}
			var ok bool
			if gr.cap, ok = add(gr.cap, d.Cap); !ok {
				return ErrGroup
			}
			by[d.Name], own[d.Name] = gr, d.Cap
		}
	}
	g.held, g.asked, g.day, g.group, g.own = t.seq, t.at, day, by, own
	for r := range g.active {
		if r.ended && r.endSeq < t.seq {
			delete(g.active, r) // ended before the ask: in the count
		}
	}
	return nil
}

// Paused is called when a summary request meets the pause the enforcer
// keeps after a core trip until the "core reflashed" step (D-260, D-262):
// answered Paused, or known to be paused. The count held is none, and so
// is any answer to a request asked before this call. A request the
// enforcer drops unanswered needs no call: its count ages out at Fresh.
func (g *Gate) Paused() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.paused = g.seq
	g.group, g.own = nil, nil
}

// Reserve is the check before a send of size IP bytes to dest. It
// reserves size plus one retry and returns the send, to be ended with End;
// or it refuses with ErrNoCount, or with *PastCap, which asks the owner
// for a raise. A refused send reserves nothing.
//
// It checks both sides of the enforcer's midnight, which can fall inside
// Fresh. On the summary's day, the group's count, the sends it may not
// hold and this one stay within the group's cap. Past midnight counts
// restart but a group can split into any of its members, so this
// destination's own sends since the count stay within its own cap too; as
// each send was checked so, any group the next day forms, its cap the sum
// of its members', holds its members' sends. A send to a destination in no
// group of this summary counts against every group and every destination,
// since the enforcer may count it in any.
func (g *Gate) Reserve(dest string, size uint64) (Send, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if g.group == nil || now.Before(g.asked) || now.Sub(g.asked) > Fresh {
		return Send{}, ErrNoCount
	}
	gr, ok := g.group[dest]
	if !ok {
		return Send{}, ErrNoCount
	}
	need, ok := mul(size, 1+Retries)
	if !ok {
		return Send{}, &PastCap{Dest: dest, Cap: gr.cap, Total: ^uint64(0)}
	}
	total, ok1 := add(gr.count, need) // against the group's cap
	mine, ok2 := need, true           // against dest's own cap
	for r := range g.active {
		rg, in := g.group[r.dest]
		if !in || rg == gr {
			total, ok1 = addOK(total, r.bytes, ok1)
		}
		if !in || r.dest == dest {
			mine, ok2 = addOK(mine, r.bytes, ok2)
		}
	}
	if !ok1 || wire.PastCap(total, gr.cap) {
		return Send{}, &PastCap{Dest: dest, Cap: gr.cap, Total: orMax(total, ok1)}
	}
	if !ok2 || wire.PastCap(mine, g.own[dest]) {
		return Send{}, &PastCap{Dest: dest, Cap: g.own[dest], Total: orMax(mine, ok2)}
	}
	r := &reservation{dest: dest, bytes: need}
	g.active[r] = struct{}{}
	return Send{r: r}, nil
}

// End is called once no byte of a reserved send can still reach the
// enforcer: its connection closed and acknowledged end to end, whether it
// succeeded or not, not merely written. Its bytes
// stay counted until a summary asked for after this call replaces the
// count. A second End keeps the first; a send this gate does not hold
// (another gate's, or one already counted) is left alone.
func (g *Gate) End(s Send) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.active[s.r]; ok && !s.r.ended {
		s.r.ended, s.r.endSeq = true, g.seq
	}
}

func add(a, b uint64) (uint64, bool) { return a + b, a+b >= a }

// addOK adds b to a sum that has not yet overflowed (ok).
func addOK(a, b uint64, ok bool) (uint64, bool) {
	s, fits := add(a, b)
	return s, ok && fits
}

// orMax is a total, or the largest one when it overflowed.
func orMax(total uint64, ok bool) uint64 {
	if !ok {
		return ^uint64(0)
	}
	return total
}

func mul(a, b uint64) (uint64, bool) {
	if a != 0 && (a*b)/a != b {
		return 0, false
	}
	return a * b, true
}
