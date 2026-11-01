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
// (wire.PastCap, the enforcer's own test).
//
// The clock only ages a count: it is fresh only while its summary was
// asked for no more than twice wire.SummaryInterval ago, by the kernel's
// own monotonic clock, and never when that clock reads earlier than the
// ask; with no
// fresh count the gate refuses every capped send, so with the enforcer down
// or its summaries paused after a core trip (D-260) the core sends nothing
// capped.
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

// PastCap is the refusal of a send that could pass its group's cap. It
// carries what the owner is asked to raise the cap by.
type PastCap struct {
	Dest  string // the destination the send was for
	Cap   uint64 // the group's cap, in IP bytes on the enforcer's day
	Total uint64 // the count, the sends it may not hold, and this send with its retry
}

func (e *PastCap) Error() string {
	return fmt.Sprintf("capgate: a send to %s needs %d bytes against a cap of %d; ask the owner to raise it by %d", e.Dest, e.Total, e.Cap, e.Raise())
}

// Raise is the smallest raise that would let the send through.
func (e *PastCap) Raise() uint64 { return e.Total - e.Cap }

// Group is one cap group in a summary: the destinations that share an
// address that day (NET-1), their one cap and the enforcer's count of the
// IP bytes the core sent them, acknowledgements and retransmissions
// included.
type Group struct {
	Dests []string
	Cap   uint64
	Count uint64
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
	seq    uint64 // the last ask issued; asks are 1, 2, 3...
	paused uint64 // the sequence at the last pause: no ask up to it counts
	have   bool
	held   uint64    // the held summary's ask
	asked  time.Time // and its time, which only ages the count
	day    uint32
	group  map[string]*Group // by destination
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
	by := map[string]*Group{}
	for i := range groups {
		gr := groups[i]
		gr.Dests = append([]string(nil), gr.Dests...)
		for _, d := range gr.Dests {
			if _, dup := by[d]; dup {
				return ErrGroup
			}
			by[d] = &gr
		}
	}
	g.have, g.held, g.asked, g.day, g.group = true, t.seq, t.at, day, by
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
	g.have, g.group = false, nil
}

// Reserve is the check before a send of size IP bytes to dest. It
// reserves size plus one retry and returns the send, to be ended with End;
// or it refuses with ErrNoCount, or with *PastCap, which asks the owner
// for a raise. A refused send reserves nothing.
func (g *Gate) Reserve(dest string, size uint64) (Send, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if !g.have || now.Before(g.asked) || now.Sub(g.asked) > Fresh {
		return Send{}, ErrNoCount
	}
	gr, ok := g.group[dest]
	if !ok {
		return Send{}, ErrNoCount
	}
	need, ok := mul(size, 1+Retries)
	total, ok2 := add(gr.Count, need)
	if !ok || !ok2 {
		return Send{}, &PastCap{Dest: dest, Cap: gr.Cap, Total: ^uint64(0)}
	}
	for r := range g.active {
		if rg, in := g.group[r.dest]; in && rg != gr {
			continue // another group's; one in no group counts against every group
		}
		if total, ok = add(total, r.bytes); !ok {
			return Send{}, &PastCap{Dest: dest, Cap: gr.Cap, Total: ^uint64(0)}
		}
	}
	if wire.PastCap(total, gr.Cap) {
		return Send{}, &PastCap{Dest: dest, Cap: gr.Cap, Total: total}
	}
	r := &reservation{dest: dest, bytes: need}
	g.active[r] = struct{}{}
	return Send{r: r}, nil
}

// End is called once no byte of a reserved send can still leave: its
// connection closed and drained, whether it succeeded or not. Its bytes
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

func mul(a, b uint64) (uint64, bool) {
	if a != 0 && (a*b)/a != b {
		return 0, false
	}
	return a * b, true
}
