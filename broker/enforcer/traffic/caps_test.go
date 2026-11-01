package traffic

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2, KRN-12, A18

// clock is a settable enforcer clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

var (
	addrA  = netip.MustParseAddr("11.0.0.1")
	addrB  = netip.MustParseAddr("11.0.0.2")
	addrC  = netip.MustParseAddr("2001:db8::3")
	noon   = time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	twoCap = Caps{Core: map[string]uint64{"a.example": 100, "b.example": 100}, Edge: 50}
)

func reading(gen uint64, edge uint64, kv ...any) Reading {
	r := Reading{Gen: gen, Core: map[netip.Addr]uint64{}, Edge: edge}
	for i := 0; i < len(kv); i += 2 {
		r.Core[kv[i].(netip.Addr)] = uint64(kv[i+1].(int))
	}
	return r
}

// grp is a count group as the tests read it: its names, cap and count.
type grp struct {
	Dests []string
	Cap   uint64
	Count uint64
}

func groupOf(t *testing.T, cs wire.Counts, dest string) grp {
	t.Helper()
	for _, g := range cs.Groups {
		if slices.Contains(g.Names(), dest) {
			return grp{g.Names(), g.Cap(), g.Count}
		}
	}
	t.Fatalf("no group holds %s in %+v", dest, cs.Groups)
	return grp{}
}

// TestCapEdgeAtTheEnforcer: a group's count at its cap passes and one byte
// past it is an overrun that cuts the core; the edge's segment the same
// with its own cap (NET-2 Byte caps: "traffic past a cap is dropped and is
// a trip at the enforcer", D-255). Mutant: pastCap as >= trips an honest
// core at the cap.
func TestCapEdgeAtTheEnforcer(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	if o := c.Add(reading(1, 50, addrA, 100)); len(o) != 0 {
		t.Fatalf("at the caps: overruns %+v, want none", o)
	}
	o := c.Add(reading(1, 50, addrA, 101))
	if len(o) != 1 || o[0].Box != BoxCore || !slices.Equal(o[0].Dests, []string{"a.example"}) || o[0].Cap != 100 || o[0].Count != 101 {
		t.Fatalf("one byte past a.example's cap: %+v", o)
	}
	o = c.Add(reading(1, 51, addrA, 101))
	if len(o) != 2 || o[1].Box != BoxEdge || o[1].Dests != nil || o[1].Cap != 50 || o[1].Count != 51 {
		t.Fatalf("one byte past the edge's cap: %+v", o)
	}
}

// TestEveryReadByteCountsOnce: the counter takes the firewall's IP bytes
// as they are, acknowledgements and retransmissions included, adding only
// what each reading adds to the last, so a repeated reading counts
// nothing twice and a retransmission's bytes count like any (NET-2: "IP
// bytes sent, acknowledgements and retransmissions included").
func TestEveryReadByteCountsOnce(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	c.Resolved("a.example", addrA)
	c.Add(reading(1, 0, addrA, 40))
	c.Add(reading(1, 0, addrA, 40))
	c.Add(reading(1, 0, addrA, 70)) // a retransmission of 30 bytes
	if g := groupOf(t, c.Counts(), "a.example"); g.Count != 70 {
		t.Fatalf("count %d, want 70", g.Count)
	}
}

// TestCounterRestarts: a ruleset load restarts the firewall's counters
// (ENF-i-2), and a day's count must survive it: after a new Gen, or a
// counter that falls within one, all of the new reading is new bytes.
// Mutant: taking the difference across a Gen undercounts the reload.
func TestCounterRestarts(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	c.Resolved("a.example", addrA)
	c.Add(reading(1, 20, addrA, 60))
	c.Add(reading(2, 5, addrA, 70)) // reloaded: 70 more, 5 more
	c.Add(reading(2, 5, addrA, 10)) // fell within Gen 2: restarted, 10 more
	cs := c.Counts()
	if g := groupOf(t, cs, "a.example"); g.Count != 140 {
		t.Fatalf("count %d, want 60+70+10", g.Count)
	}
	if cs.EdgeCount != 25 {
		t.Fatalf("edge count %d, want 20+5", cs.EdgeCount)
	}
}

// TestGroupsMergeAndAdd: destinations that share an address resolved that
// day form one group whose cap is the sum of theirs, and groups that merge
// mid-day add their counts (NET-2 Byte caps). Mutant: a group keeping the
// larger count instead of the sum lets the merged group pass its cap.
func TestGroupsMergeAndAdd(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	c.Resolved("a.example", addrA)
	c.Resolved("b.example", addrB)
	if o := c.Add(reading(1, 0, addrA, 80, addrB, 90)); len(o) != 0 {
		t.Fatalf("apart, under their caps: %+v", o)
	}
	if cs := c.Counts(); len(cs.Groups) != 2 {
		t.Fatalf("groups %+v, want two", cs.Groups)
	}
	c.Resolved("b.example", addrA) // now shares a.example's address
	g := groupOf(t, c.Counts(), "a.example")
	if !slices.Equal(g.Dests, []string{"a.example", "b.example"}) || g.Cap != 200 || g.Count != 170 {
		t.Fatalf("merged group %+v, want both, cap 200, count 170", g)
	}
	if o := c.Add(reading(1, 0, addrA, 80, addrB, 120)); len(o) != 0 {
		t.Fatalf("merged at its cap: %+v", o)
	}
	o := c.Add(reading(1, 0, addrA, 81, addrB, 120))
	if len(o) != 1 || o[0].Cap != 200 || o[0].Count != 201 {
		t.Fatalf("merged one past: %+v", o)
	}
}

// TestEveryCappedDestinationHasACount: every destination on the signed
// list is in exactly one group, with a zero count before its first byte,
// so the kernel has a count for a destination it has not reached yet
// (capgate: a destination in no group has no count).
func TestEveryCappedDestinationHasACount(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	cs := c.Counts()
	var all []string
	for _, g := range cs.Groups {
		all = append(all, g.Names()...)
		if g.Count != 0 || g.Cap() != 100 {
			t.Fatalf("fresh group %+v", g)
		}
	}
	if !slices.Equal(all, []string{"a.example", "b.example"}) {
		t.Fatalf("destinations %v", all)
	}
	if cs.Day != Day(noon) || cs.EdgeCap != 50 {
		t.Fatalf("counts %+v", cs)
	}
}

// TestTheDayRestartsOnTheEnforcersClock: the count restarts when the
// enforcer's own day changes (NET-2: "per day on its own clock"), and a
// clock set back keeps the later day and its count, so no step of the
// clock restarts a cap early. Mutant: taking Day(now) as it is on a clock
// set back resets the count.
func TestTheDayRestartsOnTheEnforcersClock(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	c.Add(reading(1, 30, addrA, 90))
	clk.t = noon.Add(12*time.Hour - time.Nanosecond)
	if g := groupOf(t, c.Counts(), "a.example"); g.Count != 90 {
		t.Fatalf("before midnight: %d", g.Count)
	}
	clk.t = noon.Add(12 * time.Hour)
	cs := c.Counts()
	if cs.Day != Day(noon)+1 || groupOf(t, cs, "a.example").Count != 0 || cs.EdgeCount != 0 {
		t.Fatalf("after midnight: %+v", cs)
	}
	c.Add(reading(1, 30, addrA, 150)) // 60 more today
	clk.t = noon                      // set back a day
	cs = c.Counts()
	if cs.Day != Day(noon)+1 || groupOf(t, cs, "a.example").Count != 60 {
		t.Fatalf("clock set back: %+v", cs)
	}
}

// TestCarriedOverAddressKeepsItsGroup: a connection that runs past
// midnight to an address not resolved again that day still counts against
// the destinations it last resolved for, not as unknown bytes.
func TestCarriedOverAddressKeepsItsGroup(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	c.Add(reading(1, 0, addrA, 10))
	clk.t = noon.Add(13 * time.Hour)
	if o := c.Add(reading(1, 0, addrA, 60)); len(o) != 0 {
		t.Fatalf("carried over: %+v", o)
	}
	if g := groupOf(t, c.Counts(), "a.example"); g.Count != 50 {
		t.Fatalf("carried over count %d, want 50", g.Count)
	}
}

// TestBytesNoDestinationResolvedToTrip: bytes to an address no
// destination resolved to fit no cap, so they are an overrun with no
// destination, which cuts the core: nothing the core sends is uncounted.
// Mutant: dropping stray bytes lets them pass every cap.
func TestBytesNoDestinationResolvedToTrip(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	o := c.Add(reading(1, 0, addrC, 1))
	if len(o) != 1 || o[0].Box != BoxCore || o[0].Dests != nil || o[0].Count != 1 {
		t.Fatalf("stray byte: %+v", o)
	}
}

// TestRetiredDestinationKeepsItsCap: a policy version that takes a
// destination off the list leaves the bytes already sent to it under the
// cap they were sent under until the day ends, so the change itself trips
// nothing; the next day it is gone.
func TestRetiredDestinationKeepsItsCap(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("b.example", addrB)
	c.Add(reading(1, 0, addrB, 90))
	c.SetCaps(Caps{Core: map[string]uint64{"a.example": 100}, Edge: 50})
	if o := c.Add(reading(1, 0, addrB, 90)); len(o) != 0 {
		t.Fatalf("after b.example left the list: %+v", o)
	}
	if g := groupOf(t, c.Counts(), "b.example"); g.Cap != 100 || g.Count != 90 {
		t.Fatalf("retired group %+v", g)
	}
	clk.t = noon.Add(36 * time.Hour)
	for _, g := range c.Counts().Groups {
		if slices.Contains(g.Names(), "b.example") {
			t.Fatalf("b.example still counted two days later: %+v", g)
		}
	}
}

// TestCountsSaturate: a count never wraps past 2^64-1 back under a cap.
func TestCountsSaturate(t *testing.T) {
	c := NewCounter((&clock{noon}).now, Caps{Core: map[string]uint64{"a.example": ^uint64(0) - 1}})
	c.Resolved("a.example", addrA)
	c.Resolved("a.example", addrB)
	big := ^uint64(0) - 5
	r := Reading{Gen: 1, Core: map[netip.Addr]uint64{addrA: big, addrB: big}}
	if o := c.Add(r); len(o) != 1 || o[0].Count != ^uint64(0) {
		t.Fatalf("saturated: %+v", o)
	}
}

// TestYesterdaysSharedAddressMergesOnlyWhenLive: destinations that shared
// an address yesterday are one group today only while that address is
// live, resolved again today or carrying bytes today (ASSUMPTIONS
// ENF-cap-3); otherwise each keeps its own cap. Mutants: the liveness
// test always true (yesterday's merge kept), or either half negated.
func TestYesterdaysSharedAddressMergesOnlyWhenLive(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	c.Resolved("b.example", addrA)
	if n := len(c.Counts().Groups); n != 1 {
		t.Fatalf("resolved together today: %d groups, want 1", n)
	}
	clk.t = noon.Add(13 * time.Hour) // the next day
	if n := len(c.Counts().Groups); n != 2 {
		t.Fatalf("yesterday's shared address, idle today: %d groups, want 2", n)
	}
	c.Add(reading(1, 0, addrA, 1))
	if g := groupOf(t, c.Counts(), "a.example"); len(g.Dests) != 2 || g.Count != 1 {
		t.Fatalf("yesterday's shared address carrying bytes today: %+v", g)
	}
	clk.t = noon.Add(37 * time.Hour) // a day later, idle
	c.Resolved("b.example", addrA)
	if g := groupOf(t, c.Counts(), "b.example"); len(g.Dests) != 1 {
		t.Fatalf("re-resolved for b.example alone today: %+v", g)
	}
}
