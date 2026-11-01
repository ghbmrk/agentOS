package capgate

// REQ: NET-2, KRN-12, A18

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// clock is the kernel's clock in the simulator.
type clock struct{ t time.Time }

func (c *clock) now() time.Time       { return c.t }
func (c *clock) step(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *clock                { return &clock{t: time.Unix(1_800_000_000, 0)} }
func gate(c *clock) *Gate             { return New(c.now) }
func capped(cp, count uint64, dests ...string) []Group {
	return []Group{{Dests: dests, Cap: cp, Count: count}}
}

// enforcer is the fake enforcer's counter for one group: it counts every
// IP byte the core sends the group on its day, and trips past the cap with
// the shared edge test, as the real one does (NET-2 Byte caps, #4174).
type enforcer struct {
	cap, count uint64
	tripped    bool
}

func (e *enforcer) pass(n uint64) {
	e.count += n
	if wire.PastCap(e.count, e.cap) {
		e.tripped = true
	}
}

// The count is fresh at exactly twice the summary interval after it was
// asked for, and none one nanosecond later (NET-2 Byte caps).
func TestFreshAtExactlyTwiceTheSummaryInterval(t *testing.T) {
	if Fresh != 2*wire.SummaryInterval {
		t.Fatalf("Fresh = %v, want twice wire.SummaryInterval (%v)", Fresh, wire.SummaryInterval)
	}
	c := newClock()
	g := gate(c)
	tk := g.Ask()
	c.step(wire.SummaryInterval / 2) // the answer's travel time does not age it
	if err := g.Summary(tk, 7, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	c.step(2*wire.SummaryInterval - wire.SummaryInterval/2)
	s, err := g.Reserve("backup", 10)
	if err != nil {
		t.Fatalf("at exactly 2×%v: %v, want fresh", wire.SummaryInterval, err)
	}
	g.End(s)
	c.step(time.Nanosecond)
	if _, err := g.Reserve("backup", 10); !errors.Is(err, ErrNoCount) {
		t.Fatalf("one ns past 2×%v: %v, want ErrNoCount", wire.SummaryInterval, err)
	}
	// One lost summary does not make it stale: the next one, a single
	// interval later, makes it fresh again.
	tk = g.Ask()
	if err := g.Summary(tk, 7, capped(1000, 40, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 10); err != nil {
		t.Fatalf("after the next summary: %v", err)
	}
}

// No count, no capped send: before the first summary, and for a
// destination the summary names in no group.
func TestNoCountRefuses(t *testing.T) {
	c := newClock()
	g := gate(c)
	if _, err := g.Reserve("backup", 1); !errors.Is(err, ErrNoCount) {
		t.Fatalf("before any summary: %v", err)
	}
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("mail", 1); !errors.Is(err, ErrNoCount) {
		t.Fatalf("destination in no group: %v", err)
	}
}

// At each cap edge (one byte under, at and over), with bytes in flight
// from a send the count may not hold and one retry of the new send, timed
// at exactly twice the summary interval: the kernel lets the first two
// through and the enforcer never trips, and it refuses the third, asking
// for a raise of one byte, with no trip (A18, D-255).
func TestCapEdges(t *testing.T) {
	const cp, size, inflight = 10_000, 1_000, 1_000
	for _, tc := range []struct {
		name string
		off  int64 // total minus the cap
	}{{"one byte under", -1}, {"at", 0}, {"one byte over", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			// count + in flight + size with its retry = cap + off
			count := uint64(int64(cp-inflight-size*(1+Retries)) + tc.off)
			total := uint64(int64(cp) + tc.off)
			c := newClock()
			g := gate(c)
			e := &enforcer{cap: cp, count: count}
			// The first summary, and a send reserved under it that is still
			// in flight when the next summary is asked for.
			if err := g.Summary(g.Ask(), 3, capped(cp, count, "backup")); err != nil {
				t.Fatal(err)
			}
			first, err := g.Reserve("backup", inflight/(1+Retries))
			if err != nil {
				t.Fatal(err)
			}
			tk := g.Ask() // the enforcer has counted none of it yet
			if err := g.Summary(tk, 3, capped(cp, e.count, "backup")); err != nil {
				t.Fatal(err)
			}
			e.pass(inflight / 2) // it reaches the enforcer after the count
			e.pass(inflight / 2) // and its one retry
			g.End(first)
			c.step(Fresh) // exactly twice the summary interval after the ask
			s, err := g.Reserve("backup", size)
			if tc.off > 0 {
				var pc *PastCap
				if !errors.As(err, &pc) {
					t.Fatalf("total %d over cap %d: err %v, want *PastCap", total, cp, err)
				}
				if pc.Cap != cp || pc.Total != total || pc.Raise() != 1 || pc.Dest != "backup" {
					t.Fatalf("refusal %+v, want cap %d total %d raise 1", pc, cp, total)
				}
			} else {
				if err != nil {
					t.Fatalf("total %d against cap %d refused: %v", total, cp, err)
				}
				e.pass(size) // the send
				e.pass(size) // and its one retry
				g.End(s)
			}
			if e.tripped {
				t.Fatalf("enforcer tripped at %d of %d", e.count, cp)
			}
		})
	}
}

// The edges themselves, unrounded: a lone send whose size plus its retry
// lands one byte under, at and one byte over the cap.
func TestCapEdgesExact(t *testing.T) {
	for _, tc := range []struct {
		count uint64
		ok    bool
	}{{9_799, true}, {9_800, true}, {9_801, false}} {
		c := newClock()
		g := gate(c)
		tk := g.Ask()
		if err := g.Summary(tk, 1, capped(10_000, tc.count, "backup")); err != nil {
			t.Fatal(err)
		}
		c.step(Fresh)
		e := &enforcer{cap: 10_000, count: tc.count}
		_, err := g.Reserve("backup", 100)
		if tc.ok != (err == nil) {
			t.Fatalf("count %d + 200: err %v, want ok=%v", tc.count, err, tc.ok)
		}
		if err == nil {
			e.pass(100)
			e.pass(100)
		}
		if e.tripped {
			t.Fatalf("count %d: enforcer tripped", tc.count)
		}
	}
}

// What the kernel sent since the count was asked for is added, and a send
// that ended before it was asked for is not added twice.
func TestSentSinceTheCount(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	a, err := g.Reserve("backup", 200) // 400 reserved
	if err != nil {
		t.Fatal(err)
	}
	b, err := g.Reserve("backup", 200) // 800 reserved
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 101); err == nil { // 1002
		t.Fatal("send past the cap with two sends since the count let through")
	}
	g.End(a)
	g.End(b)
	c.step(time.Second)
	// A summary asked for after both ended holds them: the enforcer counted
	// 400 (one of them retried), and only that count stands.
	if err := g.Summary(g.Ask(), 1, capped(1000, 600, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 200); err != nil { // 600 + 400
		t.Fatalf("ended sends counted twice: %v", err)
	}
}

// Destinations in one group share its cap and count, so a send to one adds
// to the other's total (NET-2: destinations that share an address form one
// group; groups that merge mid-day add their counts).
func TestGroupSharesItsCap(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, []Group{{Dests: []string{"backup"}, Cap: 1000}, {Dests: []string{"mail"}, Cap: 1000}}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 400); err != nil {
		t.Fatal(err)
	}
	// Mid-day the two share an address: one group, caps and counts summed.
	if err := g.Summary(g.Ask(), 1, []Group{{Dests: []string{"backup", "mail"}, Cap: 2000, Count: 0}}); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("mail", 600); err != nil { // 800 + 1200
		t.Fatalf("at the merged cap: %v", err)
	}
	if _, err := g.Reserve("mail", 1); err == nil {
		t.Fatal("send past the merged cap let through")
	}
	if err := g.Summary(g.Ask(), 1, []Group{{Dests: []string{"backup"}}, {Dests: []string{"backup"}}}); !errors.Is(err, ErrGroup) {
		t.Fatalf("destination in two groups: %v", err)
	}
}

// The enforcer's day decides the count: a new day's count replaces the old
// one, the sends since its ask still added; an earlier day's, or an answer
// to an older request, is refused.
func TestEnforcersDay(t *testing.T) {
	c := newClock()
	g := gate(c)
	old := g.Ask()
	c.step(time.Second)
	if err := g.Summary(g.Ask(), 5, capped(1000, 990, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 10); err == nil {
		t.Fatal("past the cap on day 5")
	}
	if err := g.Summary(old, 5, capped(1000, 0, "backup")); !errors.Is(err, ErrSummary) {
		t.Fatalf("an older request's answer: %v", err)
	}
	if err := g.Summary(g.Ask(), 4, capped(1000, 0, "backup")); !errors.Is(err, ErrSummary) {
		t.Fatalf("an earlier day: %v", err)
	}
	if _, err := g.Reserve("backup", 10); err == nil {
		t.Fatal("a refused summary replaced the count")
	}
	tk := g.Ask()
	s, err := g.Reserve("backup", 0) // a zero-byte probe reserves nothing past the cap
	if err != nil {
		t.Fatal(err)
	}
	g.End(s)
	if err := g.Summary(tk, 6, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 500); err != nil {
		t.Fatalf("day 6's count: %v", err)
	}
}

// After a core trip the enforcer answers summary requests Paused (D-260)
// until the "core reflashed" step (D-262). A paused summary is no fresh
// count: every capped send is refused, an answer to a request asked before
// the pause is refused, and only a summary asked for after it, as the
// reflashed core's first, makes a count fresh again.
func TestPausedSummaryIsNoCount(t *testing.T) {
	c := newClock()
	g := gate(c)
	before := g.Ask()
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 10); err != nil {
		t.Fatal(err)
	}
	g.Paused()
	if _, err := g.Reserve("backup", 10); !errors.Is(err, ErrNoCount) {
		t.Fatalf("after a paused summary: %v, want ErrNoCount", err)
	}
	c.step(time.Second)
	if err := g.Summary(before, 1, capped(1000, 0, "backup")); !errors.Is(err, ErrSummary) {
		t.Fatalf("an answer asked for before the pause: %v", err)
	}
	if _, err := g.Reserve("backup", 10); !errors.Is(err, ErrNoCount) {
		t.Fatalf("pre-pause answer revived the count: %v", err)
	}
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	// The sends reserved before the pause still count against the cap.
	if _, err := g.Reserve("backup", 491); err == nil { // 20 + 982
		t.Fatal("a send reserved before the pause was forgotten")
	}
	if _, err := g.Reserve("backup", 490); err != nil { // 20 + 980
		t.Fatalf("after the resumed summary: %v", err)
	}
}

// A size whose reservation or total overflows is past any cap.
func TestOverflowIsPastCap(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, capped(^uint64(0), 2, "backup")); err != nil {
		t.Fatal(err)
	}
	var pc *PastCap
	if _, err := g.Reserve("backup", ^uint64(0)/2+1); !errors.As(err, &pc) {
		t.Fatalf("overflowing size: %v", err)
	}
	if _, err := g.Reserve("backup", ^uint64(0)/2); !errors.As(err, &pc) {
		t.Fatalf("overflowing total: %v", err)
	}
}
