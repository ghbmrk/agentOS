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
// sends nothing capped; each such refusal names its cause. A send that
// would fit once the sends already ended are counted waits for the next
// summary; only one that cannot asks the owner for a raise.
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
	// ErrNoCount refuses a send with no fresh count for its destination.
	// Each refusal is one of the five causes below, which wrap it, since
	// each asks the owner for a different step (KRN-cap-9).
	ErrNoCount = errors.New("capgate: no fresh count from the enforcer")
	// ErrNoSummary: no summary has been read since the kernel started.
	ErrNoSummary = fmt.Errorf("%w: none read since the kernel started", ErrNoCount)
	// ErrStale: the latest summary was asked for more than Fresh ago, as
	// when the enforcer is down (NET-2 Fails safe: move the cable back).
	ErrStale = fmt.Errorf("%w: the latest is older than twice the summary interval", ErrNoCount)
	// ErrPaused: summaries are paused after a core trip until the "core
	// reflashed" step (D-260, D-262; REC-5).
	ErrPaused = fmt.Errorf("%w: summaries are paused after a core trip", ErrNoCount)
	// ErrNoGroup: the latest summary names the destination in no group,
	// so the enforcer's signed list does not cap it.
	ErrNoGroup = fmt.Errorf("%w: the latest summary names the destination in no group", ErrNoCount)
	// ErrClock: the kernel's clock reads earlier than the latest ask.
	ErrClock = fmt.Errorf("%w: the kernel's clock reads earlier than the ask", ErrNoCount)
	// ErrCounting refuses a send that does not fit now but would once a
	// later summary counts the sends already ended at what they really
	// sent, not at their full reservation: the caller waits for the next
	// summary instead of asking the owner for a raise (KRN-cap-10).
	ErrCounting = errors.New("capgate: sends that ended since the count may make room at the next summary")
	// ErrSummary refuses a summary that cannot be the latest: asked before
	// a pause, at or before the summary already held (a ticket answers
	// once), on an earlier day, or for a ticket this gate did not issue.
	ErrSummary = errors.New("capgate: summary is older than the one held")
	// ErrGroup refuses a summary that names a destination in two groups,
	// or whose group cap, the sum of its members', overflows.
	ErrGroup = errors.New("capgate: summary names a destination twice or a cap that overflows")
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

// Send is one reserved send, held until it ends. It ends only on the
// gate that reserved it.
type Send struct {
	g *Gate
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
	halted bool              // Paused was called after the summary held
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
	g.held, g.asked, g.day, g.group, g.own, g.halted = t.seq, t.at, day, by, own, false
	for r := range g.active {
		if r.ended && r.endSeq < t.seq {
			delete(g.active, r) // ended before the ask: in the count
		}
	}
	return nil
}

// Counts takes the enforcer's ReadCounts answer to t, as
// wire.DecodeCounts reads it, one to one: its day and each group's
// destinations, caps and count. The edge segment's cap and count are not a
// core destination's and are left to the edge fetch's own check.
func (g *Gate) Counts(t Ticket, c wire.Counts) error {
	groups := make([]Group, len(c.Groups))
	for i, cg := range c.Groups {
		ds := make([]Dest, len(cg.Dests))
		for j, d := range cg.Dests {
			ds[j] = Dest{Name: d.Name, Cap: d.Cap}
		}
		groups[i] = Group{Dests: ds, Count: cg.Count}
	}
	return g.Summary(t, c.Day, groups)
}

// Paused is called when a summary request meets the pause the enforcer
// keeps after a core trip until the "core reflashed" step (D-260, D-262):
// answered Paused, or known to be paused. The count held is none, and so
// is any answer to a request asked before this call. A request the
// enforcer drops unanswered needs no call: its count ages out at Fresh.
func (g *Gate) Paused() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.paused, g.halted = g.seq, true
	g.group, g.own = nil, nil
}

// Reserve is the check before a send of size IP bytes to dest. It
// reserves size plus one retry and returns the send, to be ended with its
// End; or it refuses with one of ErrNoCount's causes; with ErrCounting,
// when only sends already ended stand in its way, so the next summary may
// make room; or with *PastCap, which asks the owner for a raise. A refused
// send reserves nothing.
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
	if err := g.fresh(dest); err != nil {
		return Send{}, err
	}
	gr := g.group[dest]
	need, ok := mul(size, 1+Retries)
	if !ok {
		return Send{}, &PastCap{Dest: dest, Cap: gr.cap, Total: ^uint64(0)}
	}
	// Each side sums twice: every send the count may not hold (all), and
	// only those not yet ended (live), which no later count can shrink.
	all, mine := sum{n: gr.count}.plus(need), sum{}.plus(need)
	live, liveMine := all, mine
	for r := range g.active {
		rg, in := g.group[r.dest]
		if !in || rg == gr {
			all = all.plus(r.bytes)
			if !r.ended {
				live = live.plus(r.bytes)
			}
		}
		if !in || r.dest == dest {
			mine = mine.plus(r.bytes)
			if !r.ended {
				liveMine = liveMine.plus(r.bytes)
			}
		}
	}
	if all.past(gr.cap) || mine.past(g.own[dest]) {
		if live.past(gr.cap) {
			return Send{}, &PastCap{Dest: dest, Cap: gr.cap, Total: all.total()}
		}
		if liveMine.past(g.own[dest]) {
			return Send{}, &PastCap{Dest: dest, Cap: g.own[dest], Total: mine.total()}
		}
		return Send{}, ErrCounting
	}
	r := &reservation{dest: dest, bytes: need}
	g.active[r] = struct{}{}
	return Send{g: g, r: r}, nil
}

// fresh is why the gate has no fresh count for dest now, or nil.
func (g *Gate) fresh(dest string) error {
	now := g.now()
	switch {
	case g.halted:
		return ErrPaused
	case g.group == nil:
		return ErrNoSummary
	case now.Before(g.asked):
		return ErrClock
	case now.Sub(g.asked) > Fresh:
		return ErrStale
	}
	if _, ok := g.group[dest]; !ok {
		return ErrNoGroup
	}
	return nil
}

// End is called once no byte of the send can still reach the enforcer:
// its connection closed and acknowledged end to end, whether it succeeded
// or not, not merely written. Its bytes stay counted until a summary asked
// for after this call replaces the count. A second End keeps the first;
// a send already counted, or the zero Send, is left alone.
func (s Send) End() {
	if s.g == nil {
		return
	}
	s.g.mu.Lock()
	defer s.g.mu.Unlock()
	if _, ok := s.g.active[s.r]; ok && !s.r.ended {
		s.r.ended, s.r.endSeq = true, s.g.seq
	}
}

// sum is a running total that remembers whether it overflowed.
type sum struct {
	n    uint64
	over bool
}

func (a sum) plus(b uint64) sum {
	n, ok := add(a.n, b)
	return sum{n: n, over: a.over || !ok}
}

// past is whether the total passes cap, by the enforcer's own test.
func (a sum) past(cap uint64) bool { return a.over || wire.PastCap(a.n, cap) }

// total is the total, or the largest one when it overflowed.
func (a sum) total() uint64 {
	if a.over {
		return ^uint64(0)
	}
	return a.n
}

func add(a, b uint64) (uint64, bool) { return a + b, a+b >= a }

func mul(a, b uint64) (uint64, bool) {
	if a != 0 && (a*b)/a != b {
		return 0, false
	}
	return a * b, true
}
