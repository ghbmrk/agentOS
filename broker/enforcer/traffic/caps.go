package traffic

import (
	"cmp"
	"encoding/json"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// This file is the enforcer's byte-cap count (SPEC NET-2 Byte caps, D-248,
// D-255, #4174): the IP bytes the core sent to each of its internet
// destinations, and the edge's segment to the internet, per day on the
// enforcer's own clock. Destinations that share an address resolved that
// day form one group with one cap, the sum of theirs, and groups that
// merge mid-day add their counts. A count past its cap is an Overrun, a
// trip at the enforcer (KRN-12) that the caller makes, cutting the box it
// came from. Counts is the same count as the kernel reads it on the
// channel, so the kernel's check (broker/kernel/capgate) stops short of the
// enforcer's own number. Its assumptions are ASSUMPTIONS rows ENF-cap-*.

// Caps is the signed list's daily byte caps, in IP bytes (NET-2 Byte
// caps): one per core destination, by its name on the list, and the edge
// segment's one cap.
type Caps struct {
	Core map[string]uint64
	Edge uint64
}

// CapsOf is the caps a signed policy version gives (NET-2 Byte caps): each
// listed destination's, 0 for one with none, and the edge's.
func CapsOf(d policy.Document) Caps {
	out := Caps{Core: make(map[string]uint64, len(d.Destinations)), Edge: d.EdgeCap}
	for _, h := range d.Destinations {
		out.Core[h] = d.Caps[h]
	}
	return out
}

// Reading is one read of the firewall: the IP bytes the core sent to each
// internet address, and the edge's segment to the internet,
// acknowledgements and retransmissions included, since the ruleset load
// numbered Gen, and the addresses each core destination's resolver set
// (nft.AllowSet.Named) holds. Within one Gen a counter only rises. The
// core's allow set is the union of its destinations' resolver sets, so
// Named holds every address the core can reach.
type Reading struct {
	Gen   uint64
	Core  map[netip.Addr]uint64
	Edge  uint64
	Named map[string][]netip.Addr
}

// Box is the box an overrun cuts.
type Box uint8

const (
	BoxCore Box = 1
	BoxEdge Box = 2
)

// group is one cap group on the enforcer's day: its destinations, sorted,
// each one's own cap, their one cap (the sum, saturating) and the bytes
// the core sent them.
type group struct {
	dests []string
	own   []uint64
	cap   uint64
	count uint64
}

// Overrun is a cap passed: a trip at the enforcer that cuts Box. A core
// overrun with no destinations is bytes to an address no destination
// resolved to, which no cap allows.
type Overrun struct {
	Box   Box
	Dests []string
	Cap   uint64
	Count uint64
}

// Day is t's enforcer day: whole days since the Unix epoch, in UTC, so the
// day has no zone or daylight-saving change to get wrong.
func Day(t time.Time) uint32 { return uint32(t.Unix() / 86400) }

// Counter holds the day's counts. It is safe for concurrent use; use
// NewCounter.
type Counter struct {
	mu   sync.Mutex
	now  func() time.Time
	caps Caps
	// retired is the cap of each destination a policy version took off
	// the list today: its bytes so far stay under that cap until the day
	// ends (ASSUMPTIONS ENF-cap-5).
	retired map[string]uint64
	day     uint32

	// dests is every destination the resolver answered with each address
	// while the address stayed in use: it only grows until the address
	// has gone a full day neither resolved nor carrying bytes, so a
	// connection open across midnight stays counted against every
	// destination it could be for (ASSUMPTIONS ENF-cap-3). resolved is
	// the address's latest day of resolution, used is its latest day of
	// resolution or bytes.
	dests    map[netip.Addr]map[string]bool
	resolved map[netip.Addr]uint32
	used     map[netip.Addr]uint32

	gen      uint64
	seen     bool
	last     map[netip.Addr]uint64 // the latest reading, per address
	lastEdge uint64
	bytes    map[netip.Addr]uint64 // today's bytes, per address
	edge     uint64                // today's edge bytes
}

// NewCounter is a counter on the clock now (time.Now in production) with
// caps.
func NewCounter(now func() time.Time, caps Caps) *Counter {
	c := &Counter{now: now, retired: map[string]uint64{}, dests: map[netip.Addr]map[string]bool{},
		resolved: map[netip.Addr]uint32{}, used: map[netip.Addr]uint32{}, last: map[netip.Addr]uint64{}, bytes: map[netip.Addr]uint64{}}
	c.caps = cloneCaps(caps)
	c.day = Day(now())
	return c
}

// SetCaps replaces the caps, as a newly signed policy version sets them.
// The day's counts stay, and a destination taken off the list keeps its
// cap until the day ends.
func (c *Counter) SetCaps(caps Caps) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	for d, n := range c.caps.Core {
		if _, kept := caps.Core[d]; !kept {
			c.retired[d] = n
		}
	}
	c.caps = cloneCaps(caps)
	for d := range c.caps.Core {
		delete(c.retired, d)
	}
}

// Resolved records that the enforcer's own resolver answered dest with
// addr. It adds dest to addr's destinations; none is dropped while addr
// stays in use.
func (c *Counter) Resolved(dest string, addr netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	addr = addr.Unmap()
	if c.dests[addr] == nil {
		c.dests[addr] = map[string]bool{}
	}
	c.dests[addr][dest] = true
	c.resolved[addr], c.used[addr] = c.day, c.day
}

// named adds dest to addr's destinations without marking addr resolved
// today. The caller holds c.mu.
func (c *Counter) named(dest string, addr netip.Addr) {
	if c.dests[addr] == nil {
		c.dests[addr] = map[string]bool{}
	}
	c.dests[addr][dest] = true
}

// Add takes one reading and returns every cap now past. A counter lower
// than the last reading of the same Gen, or any counter after a new Gen,
// restarted, so all of it is new bytes.
func (c *Counter) Add(r Reading) []Overrun {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	fresh := !c.seen || r.Gen != c.gen
	if fresh {
		c.last, c.lastEdge = map[netip.Addr]uint64{}, 0
	}
	c.gen, c.seen = r.Gen, true
	// Every address a resolver set holds is one the allow set may pass, so
	// it carries its destinations from the firewall itself: an address
	// the counter had forgotten, or never heard resolved, is never stray
	// while the core can reach it.
	for d, as := range r.Named {
		for _, a := range as {
			c.named(d, a.Unmap())
		}
	}
	for a, n := range r.Core {
		a = a.Unmap()
		if d := delta(c.last[a], n); d > 0 {
			c.bytes[a] = sat(c.bytes[a], d)
			c.used[a] = c.day
		}
		c.last[a] = n
	}
	c.edge = sat(c.edge, delta(c.lastEdge, r.Edge))
	c.lastEdge = r.Edge
	return c.overruns()
}

func delta(last, n uint64) uint64 {
	if n < last {
		return n // restarted
	}
	return n - last
}

// Counts is the day's counts as the kernel reads them, the body of the
// channel's count read (wire.ReadCounts). The caller adds a reading taken
// at the request first, so the count holds every byte the firewall
// counted before it (ASSUMPTIONS ENF-cap-3).
func (c *Counter) Counts() wire.Counts {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.roll()
	groups, _ := c.groups()
	out := wire.Counts{Day: c.day, Groups: make([]wire.CountGroup, 0, len(groups)), EdgeCap: c.caps.Edge, EdgeCount: c.edge}
	for _, g := range groups {
		wg := wire.CountGroup{Count: g.count}
		for i, d := range g.dests {
			wg.Dests = append(wg.Dests, wire.CountDest{Name: d, Cap: g.own[i]})
		}
		out.Groups = append(out.Groups, wg)
	}
	return out
}

// roll starts a new day when the enforcer's clock reaches one. A clock
// that goes back keeps the later day, so no count restarts early. The
// caller holds c.mu.
func (c *Counter) roll() {
	d := Day(c.now())
	if d <= c.day {
		return
	}
	c.day = d
	clear(c.retired)
	clear(c.bytes)
	c.edge = 0
	for a, u := range c.used {
		if u+1 < d {
			// Neither resolved nor carrying bytes for a full day: its
			// destinations start afresh, and the next reading gives it
			// back every one whose resolver set still holds it.
			delete(c.used, a)
			delete(c.resolved, a)
			delete(c.dests, a)
		}
	}
}

// groups is the day's cap groups and the bytes no destination resolved to.
// The caller holds c.mu.
func (c *Counter) groups() ([]group, uint64) {
	parent := map[string]string{}
	var find func(string) string
	find = func(d string) string {
		if p, ok := parent[d]; ok && p != d {
			r := find(p)
			parent[d] = r
			return r
		}
		parent[d] = d
		return d
	}
	capOf := func(d string) uint64 {
		if n, ok := c.caps.Core[d]; ok {
			return n
		}
		return c.retired[d]
	}
	for d := range c.caps.Core {
		find(d)
	}
	// An address joins its destinations' groups when it was resolved
	// today or carried bytes today.
	live := func(a netip.Addr) bool { return c.resolved[a] == c.day || c.bytes[a] > 0 }
	for a, ds := range c.dests {
		if !live(a) {
			continue
		}
		var first string
		for d := range ds {
			if first == "" {
				first = find(d)
				continue
			}
			parent[find(d)] = first
			first = find(first)
		}
	}
	by := map[string]*group{}
	for d := range parent {
		r := find(d)
		g := by[r]
		if g == nil {
			g = &group{}
			by[r] = g
		}
		g.dests = append(g.dests, d)
		g.cap = sat(g.cap, capOf(d))
	}
	var stray uint64
	for a, n := range c.bytes {
		ds := c.dests[a]
		if len(ds) == 0 {
			stray = sat(stray, n)
			continue
		}
		for d := range ds {
			by[find(d)].count = sat(by[find(d)].count, n)
			break // every destination of a is in one group
		}
	}
	out := make([]group, 0, len(by))
	for _, g := range by {
		slices.Sort(g.dests)
		for _, d := range g.dests {
			g.own = append(g.own, capOf(d))
		}
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b group) int { return cmp.Compare(a.dests[0], b.dests[0]) })
	return out, stray
}

// overruns is every cap past now. The caller holds c.mu.
func (c *Counter) overruns() []Overrun {
	groups, stray := c.groups()
	var out []Overrun
	for _, g := range groups {
		if wire.PastCap(g.count, g.cap) {
			out = append(out, Overrun{Box: BoxCore, Dests: g.dests, Cap: g.cap, Count: g.count})
		}
	}
	if wire.PastCap(stray, 0) {
		out = append(out, Overrun{Box: BoxCore, Count: stray})
	}
	if wire.PastCap(c.edge, c.caps.Edge) {
		out = append(out, Overrun{Box: BoxEdge, Cap: c.caps.Edge, Count: c.edge})
	}
	return out
}

// sat adds without wrapping: a count that would pass 2^64-1 stays there,
// past every cap.
func sat(a, b uint64) uint64 {
	if a+b < a {
		return ^uint64(0)
	}
	return a + b
}

// State is everything a Counter holds besides its clock and caps, so the
// day's counts survive an enforcer restart: a restart that forgot them
// would give the core a second day's cap (ASSUMPTIONS ENF-cap-6). Gen and
// Last are kept too, so a restart under the same loaded ruleset counts
// only the bytes past the last reading; a ruleset load at boot is a new
// Gen and counts all of its counters.
type State struct {
	Day      uint32                  `json:"day"`
	Retired  map[string]uint64       `json:"retired"`
	Dests    map[netip.Addr][]string `json:"dests"`
	Resolved map[netip.Addr]uint32   `json:"resolved"`
	Used     map[netip.Addr]uint32   `json:"used"`
	Gen      uint64                  `json:"gen"`
	Seen     bool                    `json:"seen"`
	Last     map[netip.Addr]uint64   `json:"last"`
	LastEdge uint64                  `json:"last_edge"`
	Bytes    map[netip.Addr]uint64   `json:"bytes"`
	Edge     uint64                  `json:"edge"`
}

// ErrState is a saved state that does not read back as one.
var ErrState = errors.New("traffic: saved byte-cap state malformed")

// Save is the counter's state as bytes to keep on the enforcer's own disk
// after every reading (ASSUMPTIONS ENF-cap-6).
func (c *Counter) Save() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := State{Day: c.day, Retired: maps.Clone(c.retired), Dests: map[netip.Addr][]string{}, Resolved: maps.Clone(c.resolved),
		Used: maps.Clone(c.used), Gen: c.gen, Seen: c.seen, Last: maps.Clone(c.last), LastEdge: c.lastEdge, Bytes: maps.Clone(c.bytes), Edge: c.edge}
	for a, ds := range c.dests {
		s.Dests[a] = slices.Sorted(maps.Keys(ds))
	}
	b, _ := json.Marshal(s) // every field is a plain value
	return b
}

// Restore is a counter on now with caps and the state Save wrote. A saved
// day later than now's is kept, as a clock set back keeps the later day
// (ASSUMPTIONS ENF-cap-2); an earlier one rolls over at once. A state that
// does not read back is ErrState, and the caller must not count from zero
// in its place.
func Restore(now func() time.Time, caps Caps, b []byte) (*Counter, error) {
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, ErrState
	}
	c := NewCounter(now, caps)
	put := func(dst map[netip.Addr]uint64, src map[netip.Addr]uint64) {
		for a, n := range src {
			dst[a.Unmap()] = n
		}
	}
	put(c.last, s.Last)
	put(c.bytes, s.Bytes)
	for a, d := range s.Resolved {
		c.resolved[a.Unmap()] = d
	}
	for a, d := range s.Used {
		c.used[a.Unmap()] = d
	}
	for a, ds := range s.Dests {
		for _, d := range ds {
			c.named(d, a.Unmap())
		}
	}
	for d, n := range s.Retired {
		if _, listed := c.caps.Core[d]; !listed {
			c.retired[d] = n
		}
	}
	c.gen, c.seen, c.lastEdge, c.edge = s.Gen, s.Seen, s.LastEdge, s.Edge
	// The saved day is the counts' day: one before today's rolls over
	// here, clearing them, as it would have at midnight.
	c.day = s.Day
	c.roll()
	return c, nil
}

func cloneCaps(c Caps) Caps {
	out := Caps{Core: make(map[string]uint64, len(c.Core)), Edge: c.Edge}
	for d, n := range c.Core {
		out.Core[d] = n
	}
	return out
}
