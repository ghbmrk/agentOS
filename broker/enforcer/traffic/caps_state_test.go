package traffic

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
)

// REQ: NET-2, KRN-12, A18

// held is r with names' resolver sets holding addrs, as the firewall
// reports them.
func held(r Reading, names map[string][]netip.Addr) Reading {
	r.Named = names
	return r
}

// TestCapsOfTheSignedList: the counter's caps are the signed version's
// (NET-2 Byte caps): each listed destination's, 0 for one listed with none
// so it may be sent nothing, and the edge's.
func TestCapsOfTheSignedList(t *testing.T) {
	d := policy.Document{Destinations: []string{"a.example", "b.example"}, Caps: map[string]uint64{"a.example": 7}, EdgeCap: 3}
	want := Caps{Core: map[string]uint64{"a.example": 7, "b.example": 0}, Edge: 3}
	if got := CapsOf(d); !reflect.DeepEqual(got, want) {
		t.Fatalf("CapsOf = %+v, want %+v", got, want)
	}
	c := NewCounter((&clock{noon}).now, CapsOf(d))
	c.Resolved("b.example", addrB)
	if o := c.Add(reading(1, 0, addrB, 1)); len(o) != 1 || o[0].Dests[0] != "b.example" {
		t.Fatalf("one byte to a destination listed with no cap: %+v, want an overrun", o)
	}
}

// TestHeldAddressKeepsItsDestinations (#4377 Security release item 1): an
// address a resolver set still holds is one the allow set still passes, so
// a connection to it idle for days, or a client reusing it past its TTL,
// counts against its destination, never as stray bytes that trip an honest
// core: every reading gives it back the destinations whose sets hold it.
// Once no set holds it and it has idled a full day, it is forgotten as
// before. Mutant: Reading.Named ignored.
func TestHeldAddressKeepsItsDestinations(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	sets := map[string][]netip.Addr{"a.example": {addrA}}
	c.Add(held(reading(1, 0, addrA, 10), sets))
	for range 3 {
		clk.t = clk.t.Add(24 * time.Hour)
		if o := c.Add(held(reading(1, 0, addrA, 10), sets)); len(o) != 0 {
			t.Fatalf("idle and held: %+v", o)
		}
	}
	if o := c.Add(held(reading(1, 0, addrA, 15), sets)); len(o) != 0 {
		t.Fatalf("held address sending after three idle days: %+v, want no trip", o)
	}
	if g := groupOf(t, c.Counts(), "a.example"); g.Count != 5 {
		t.Fatalf("its bytes: %+v, want 5 on a.example", g)
	}
	// A load drops a.example's answer: no set holds the address now.
	c.Add(held(reading(2, 0, addrA, 0), nil))
	clk.t = clk.t.Add(48 * time.Hour)
	if o := c.Add(held(reading(2, 0, addrA, 1), nil)); len(o) != 1 || o[0].Dests != nil {
		t.Fatalf("bytes to a forgotten address no set holds: %+v, want a stray overrun", o)
	}
}

// TestResolverSetsGiveDestinations: the firewall's resolver sets alone
// give an address its destinations, so bytes to an address the counter
// never heard resolved (it restarted after the answer, or missed it) count
// against the destination whose set holds it, and against both when two
// sets do. Being held is not being resolved today, so a held address
// merges groups only while it carries bytes. Mutant: Named ignored trips
// an honest core as stray.
func TestResolverSetsGiveDestinations(t *testing.T) {
	c := NewCounter((&clock{noon}).now, twoCap)
	sets := map[string][]netip.Addr{"a.example": {addrA}, "b.example": {addrA, addrB}}
	if o := c.Add(held(reading(1, 0, addrB, 60), sets)); len(o) != 0 {
		t.Fatalf("bytes to a set's address never heard resolved: %+v", o)
	}
	if g := groupOf(t, c.Counts(), "b.example"); len(g.Dests) != 1 || g.Count != 60 {
		t.Fatalf("held, idle addrA merges nothing: %+v", g)
	}
	if o := c.Add(held(reading(1, 0, addrB, 60, addrA, 1), sets)); len(o) != 0 {
		t.Fatalf("shared address: %+v", o)
	}
	if g := groupOf(t, c.Counts(), "a.example"); len(g.Dests) != 2 || g.Count != 61 || g.Cap != 200 {
		t.Fatalf("addrA in both sets, carrying bytes: %+v, want one group of both", g)
	}
}

// TestCountsSurviveARestart (NET-2 Byte caps: the day's count is on the
// enforcer's own clock, and no restart gives the core a second day's cap):
// a counter restored from its saved state counts on from where it was,
// trips at the same byte, and counts a ruleset reloaded at boot (a new
// Gen) from zero on top of the day's bytes; it never counts the same
// counter twice. Mutants: Restore dropping Bytes passes a cap a second
// time; dropping Gen or Last counts a counter twice and trips an honest
// core.
func TestCountsSurviveARestart(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("a.example", addrA)
	sets := map[string][]netip.Addr{"a.example": {addrA}}
	c.Add(held(reading(4, 20, addrA, 90), sets))
	saved := c.Save()

	// The daemon restarts; the ruleset stays loaded, its counters rising.
	r, err := Restore(clk.now, twoCap, saved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.Counts(), c.Counts()) {
		t.Fatalf("restored counts %+v, want %+v", r.Counts(), c.Counts())
	}
	if o := r.Add(held(reading(4, 20, addrA, 100), sets)); len(o) != 0 {
		t.Fatalf("same Gen, at the cap: %+v", o)
	}
	if o := r.Add(held(reading(4, 20, addrA, 101), sets)); len(o) != 1 {
		t.Fatalf("same Gen, one byte past: %+v, want an overrun", o)
	}

	// A power cut: the ruleset is loaded again at boot, its counters at 0.
	r, _ = Restore(clk.now, twoCap, saved)
	if o := r.Add(held(reading(5, 30, addrA, 10), sets)); len(o) != 0 {
		t.Fatalf("new Gen, at the cap: %+v", o)
	}
	if o := r.Add(held(reading(5, 31, addrA, 11), sets)); len(o) != 2 {
		t.Fatalf("new Gen, one byte past each cap: %+v, want the core's and the edge's", o)
	}

	// Restored on a later day the counts start afresh; restored on a clock
	// set back, the saved day and its counts stay.
	clk.t = noon.Add(24 * time.Hour)
	if r, _ = Restore(clk.now, twoCap, saved); groupOf(t, r.Counts(), "a.example").Count != 0 || r.Counts().Day != Day(clk.t) {
		t.Fatalf("restored the next day: %+v", r.Counts())
	}
	clk.t = noon.Add(-48 * time.Hour)
	if r, _ = Restore(clk.now, twoCap, saved); groupOf(t, r.Counts(), "a.example").Count != 90 || r.Counts().Day != Day(noon) {
		t.Fatalf("restored on a clock set back: %+v", r.Counts())
	}

	for _, bad := range [][]byte{nil, []byte("{"), []byte(`{"bytes":{"not an address":1}}`)} {
		if _, err := Restore(clk.now, twoCap, bad); !errors.Is(err, ErrState) {
			t.Errorf("Restore(%q): %v, want ErrState", bad, err)
		}
	}
}

// TestRestoreKeepsTheRetiredCaps: a destination a version took off the
// list today keeps its cap across a restart (ASSUMPTIONS ENF-cap-5), unless
// the caps it restarts with list it again.
func TestRestoreKeepsTheRetiredCaps(t *testing.T) {
	clk := &clock{noon}
	c := NewCounter(clk.now, twoCap)
	c.Resolved("b.example", addrB)
	c.Add(reading(1, 0, addrB, 80))
	only := Caps{Core: map[string]uint64{"a.example": 100}}
	c.SetCaps(only)
	r, err := Restore(clk.now, only, c.Save())
	if err != nil {
		t.Fatal(err)
	}
	if o := r.Add(reading(1, 0, addrB, 100)); len(o) != 0 {
		t.Fatalf("retired b.example at its old cap after a restart: %+v", o)
	}
	if r, _ = Restore(clk.now, Caps{Core: map[string]uint64{"a.example": 100, "b.example": 5}}, c.Save()); groupOf(t, r.Counts(), "b.example").Cap != 5 {
		t.Fatalf("listed again: %+v", r.Counts())
	}
}
