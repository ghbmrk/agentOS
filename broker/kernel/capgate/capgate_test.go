package capgate

// REQ: NET-2, KRN-12, A18

import (
	"errors"
	"math/rand"
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

// The usual order: a summary is asked for, a send ends (its bytes reach
// the enforcer after the count was taken), then the answer lands. The
// count does not hold that send, so it stays added; so does one that ends
// at the very instant of the ask. Timed at exactly twice the interval.
func TestEndBetweenAskAndAnswer(t *testing.T) {
	for _, gap := range []time.Duration{time.Millisecond, 0} {
		c := newClock()
		g := gate(c)
		e := &enforcer{cap: 1000}
		if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
			t.Fatal(err)
		}
		s, err := g.Reserve("backup", 300) // 600 reserved
		if err != nil {
			t.Fatal(err)
		}
		c.step(time.Second)
		tk := g.Ask()
		c.step(gap)
		e.pass(300) // the send, after the enforcer took its count
		e.pass(300) // and its retry
		g.End(s)
		if err := g.Summary(tk, 1, capped(1000, 0, "backup")); err != nil {
			t.Fatal(err)
		}
		c.step(Fresh - gap)                                 // exactly twice the interval after tk
		if _, err := g.Reserve("backup", 250); err == nil { // 600 + 500
			e.pass(500)
			t.Fatalf("end %v after the ask forgotten: let through, enforcer at %d of 1000, tripped=%v", gap, e.count, e.tripped)
		}
		if _, err := g.Reserve("backup", 200); err != nil { // 600 + 400
			t.Fatalf("end %v after the ask: %v", gap, err)
		}
	}
}

// A clock that reads earlier than the ask (one stepped back, or with no
// monotonic reading) never makes a count fresh (Security point 1).
func TestClockBeforeTheAskIsNoCount(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	c.step(-time.Nanosecond)
	if _, err := g.Reserve("backup", 10); !errors.Is(err, ErrNoCount) {
		t.Fatalf("clock before the ask: %v, want ErrNoCount", err)
	}
}

// A send still in flight to a destination the next summary puts in no
// group counts against every group, since the enforcer may count it in
// any (Security point 2: its connection spans the enforcer's midnight and
// its address now resolves only for another destination).
func TestSendInNoGroupCountsEverywhere(t *testing.T) {
	c := newClock()
	g := gate(c)
	e := &enforcer{cap: 100}
	if err := g.Summary(g.Ask(), 1, capped(100, 0, "x", "y")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("x", 50); err != nil { // 100 reserved, in flight
		t.Fatal(err)
	}
	if err := g.Summary(g.Ask(), 2, capped(100, 0, "y")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("y", 1); err == nil {
		e.pass(100)
		e.pass(2)
		t.Fatalf("x's bytes forgotten: let through, enforcer at %d of 100, tripped=%v", e.count, e.tripped)
	}
	if _, err := g.Reserve("x", 1); !errors.Is(err, ErrNoCount) {
		t.Fatalf("x is in no group: %v", err)
	}
}

// A second End keeps the first end time, so a late duplicate cannot hold a
// send's bytes past the summary that holds them, nor, the other way, make a
// send that ended after an ask look as if it ended before it.
func TestSecondEndKeepsTheFirst(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	s, err := g.Reserve("backup", 250) // 500 reserved
	if err != nil {
		t.Fatal(err)
	}
	c.step(time.Second)
	tk := g.Ask()
	c.step(time.Second)
	g.End(s) // ended after tk: tk's count does not hold it
	c.step(time.Second)
	g.End(s) // a duplicate must not move the end
	if err := g.Summary(tk, 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Reserve("backup", 251); err == nil { // 500 + 502
		t.Fatal("send forgotten")
	}
	// A summary asked after the first End but before the duplicate holds it.
	c2 := newClock()
	g2 := gate(c2)
	if err := g2.Summary(g2.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	s2, _ := g2.Reserve("backup", 250)
	c2.step(time.Second)
	g2.End(s2)
	c2.step(time.Second)
	tk2 := g2.Ask()
	c2.step(time.Second)
	g2.End(s2) // late duplicate, after tk2
	if err := g2.Summary(tk2, 1, capped(1000, 500, "backup")); err != nil {
		t.Fatal(err)
	}
	if _, err := g2.Reserve("backup", 250); err != nil { // 500 + 500: held once
		t.Fatalf("duplicate End moved the end past the ask: %v", err)
	}
}

// Sends in flight count against their own group's cap and no other's:
// one byte over is refused with no trip, exactly at the cap passes, timed
// at exactly twice the interval after the count's ask (Potency point 1).
func TestInFlightCountsOnlyInItsGroup(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 1, []Group{{Dests: []string{"a"}, Cap: 1000}, {Dests: []string{"b"}, Cap: 1000}}); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if _, err := g.Reserve("a", 10); err != nil { // 400 in flight to a
			t.Fatal(err)
		}
	}
	if _, err := g.Reserve("b", 200); err != nil { // 400 in flight to b
		t.Fatal(err)
	}
	c.step(Fresh)
	e := &enforcer{cap: 1000, count: 400}          // b's bytes, all counted at b's group
	if _, err := g.Reserve("b", 301); err == nil { // 400 + 602
		e.pass(602)
		t.Fatalf("b's own in-flight send skipped: enforcer at %d, tripped=%v", e.count, e.tripped)
	}
	if _, err := g.Reserve("b", 300); err != nil { // 400 + 600: a's bytes are not b's
		t.Fatalf("another group's sends counted against b: %v", err)
	}
	if _, err := g.Reserve("a", 300); err != nil { // 400 + 600
		t.Fatalf("b's sends counted against a: %v", err)
	}
}

// After a pause the enforcer's day still never goes back.
func TestEarlierDayAfterPause(t *testing.T) {
	c := newClock()
	g := gate(c)
	if err := g.Summary(g.Ask(), 5, capped(1000, 0, "backup")); err != nil {
		t.Fatal(err)
	}
	g.Paused() // asked after the pause below, so only the day can refuse it
	if err := g.Summary(g.Ask(), 4, capped(1000, 0, "backup")); !errors.Is(err, ErrSummary) {
		t.Fatalf("an earlier day after a pause: %v", err)
	}
	if err := g.Summary(g.Ask(), 5, capped(1000, 0, "backup")); err != nil {
		t.Fatalf("the same day after a pause: %v", err)
	}
}

// A request asked before the pause is refused even on the same clock
// reading, and one asked after it counts on that reading too: the gate's
// sequence orders them, not the clock.
func TestAskAtThePauseInstant(t *testing.T) {
	c := newClock()
	g := gate(c)
	tk := g.Ask()
	g.Paused()
	if err := g.Summary(tk, 1, capped(1000, 0, "backup")); !errors.Is(err, ErrSummary) {
		t.Fatalf("asked at the pause instant: %v", err)
	}
	if err := g.Summary(g.Ask(), 1, capped(1000, 0, "backup")); err != nil {
		t.Fatalf("asked after the pause: %v", err)
	}
}

// Security repro 1 (KRN-cap-2): a send that ends after an ask, on a clock
// stepped back between them, stays added to that ask's count, so the
// enforcer never passes its cap.
func TestBackwardClockCannotForgetASend(t *testing.T) {
	c := newClock()
	g := gate(c)
	e := &enforcer{cap: 100}
	if err := g.Summary(g.Ask(), 1, capped(100, 0, "x")); err != nil {
		t.Fatal(err)
	}
	tk := g.Ask() // the enforcer takes its count now: 0
	s, err := g.Reserve("x", 25)
	if err != nil {
		t.Fatal(err)
	}
	e.pass(50) // the send and its retry, after the count
	c.step(-10 * time.Minute)
	g.End(s) // reads earlier than tk
	if err := g.Summary(tk, 1, capped(100, 0, "x")); err != nil {
		t.Fatal(err)
	}
	c.step(10*time.Minute + time.Second)          // past the ask again, inside Fresh
	if _, err := g.Reserve("x", 26); err == nil { // 50 + 52
		e.pass(52)
		t.Fatalf("send forgotten: enforcer at %d of %d, tripped=%v", e.count, e.cap, e.tripped)
	}
	if _, err := g.Reserve("x", 25); err != nil { // 50 + 50: at the cap
		t.Fatalf("at the cap: %v", err)
	}
}

// Security repro 2 (KRN-cap-6): an answer to a request asked before the
// pause is refused even when the clock stepped back between the ask and
// the pause.
func TestBackwardClockCannotRevivePrePauseAnswer(t *testing.T) {
	c := newClock()
	g := gate(c)
	tk := g.Ask() // before the trip
	c.step(-10 * time.Minute)
	g.Paused()
	if err := g.Summary(tk, 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
		t.Fatalf("pre-pause answer after Paused: %v, want ErrSummary", err)
	}
	c.step(10*time.Minute + time.Second)
	if _, err := g.Reserve("x", 10); !errors.Is(err, ErrNoCount) {
		t.Fatalf("pre-pause count used after the pause: %v", err)
	}
}

// Every ordering the gate makes (an end against an ask, an ask against a
// pause, an ask against the held one) gives the same answer whether the
// clock moves forward, stands still or steps back between the events: the
// clock only ages a count (KRN-cap-1, -2, -5, -6).
func TestOrderIsTheGatesNotTheClock(t *testing.T) {
	for _, d := range []time.Duration{time.Second, 0, -10 * time.Minute, -48 * time.Hour} {
		// fresh brings the clock back to just after tk, so only order decides.
		fresh := func(c *clock, tk Ticket) { c.t = tk.at.Add(time.Second) }

		// An end after the ask stays added; an end before it is in the count.
		c := newClock()
		g := gate(c)
		if err := g.Summary(g.Ask(), 1, capped(1000, 0, "x")); err != nil {
			t.Fatal(err)
		}
		before, _ := g.Reserve("x", 100) // 200
		after, _ := g.Reserve("x", 100)  // 200
		c.step(d)
		g.End(before)
		c.step(d)
		tk := g.Ask()
		c.step(d)
		g.End(after)
		c.step(d)
		if err := g.Summary(tk, 1, capped(1000, 200, "x")); err != nil {
			t.Fatalf("step %v: %v", d, err)
		}
		fresh(c, tk)
		if _, err := g.Reserve("x", 301); err == nil { // 200 + 200 + 602
			t.Fatalf("step %v: an end after the ask was taken as counted", d)
		}
		if _, err := g.Reserve("x", 300); err != nil { // 200 + 200 + 600
			t.Fatalf("step %v: an end before the ask was counted twice: %v", d, err)
		}

		// An answer to an earlier ask after a later one is held is refused,
		// and so is a second answer to the same ask.
		c = newClock()
		g = gate(c)
		first := g.Ask()
		c.step(d)
		second := g.Ask()
		c.step(d)
		if err := g.Summary(second, 1, capped(1000, 0, "x")); err != nil {
			t.Fatalf("step %v: %v", d, err)
		}
		if err := g.Summary(first, 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
			t.Fatalf("step %v: an earlier ask after a later one: %v", d, err)
		}
		if err := g.Summary(second, 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
			t.Fatalf("step %v: a second answer to one ask: %v", d, err)
		}

		// An ask before the pause is refused; one after it counts.
		c = newClock()
		g = gate(c)
		pre := g.Ask()
		c.step(d)
		g.Paused()
		c.step(d)
		post := g.Ask()
		c.step(d)
		if err := g.Summary(pre, 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
			t.Fatalf("step %v: an ask before the pause: %v", d, err)
		}
		if err := g.Summary(post, 1, capped(1000, 0, "x")); err != nil {
			t.Fatalf("step %v: an ask after the pause: %v", d, err)
		}
		fresh(c, post)
		if _, err := g.Reserve("x", 10); err != nil {
			t.Fatalf("step %v: after the pause: %v", d, err)
		}
	}
}

// A ticket only answers on the gate that issued it, and the zero Ticket
// on none.
func TestTicketOfAnotherGate(t *testing.T) {
	c := newClock()
	g1, g2 := gate(c), gate(c)
	for range 5 {
		g2.Ask() // g2 is further along its sequence
	}
	if err := g1.Summary(g1.Ask(), 1, capped(1000, 0, "x")); err != nil {
		t.Fatal(err)
	}
	if _, err := g1.Reserve("x", 100); err != nil { // 200 in flight
		t.Fatal(err)
	}
	if err := g1.Summary(g2.Ask(), 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
		t.Fatalf("another gate's ticket: %v", err)
	}
	if err := g1.Summary(Ticket{}, 1, capped(1000, 0, "x")); !errors.Is(err, ErrSummary) {
		t.Fatalf("the zero Ticket: %v", err)
	}
}

// End with another gate's send leaves it in flight on its own gate and
// touches nothing of it, so the two gates' locks never share a write
// (run under -race); End of the zero Send is a no-op.
func TestEndOfAnotherGatesSend(t *testing.T) {
	c := newClock()
	g1, g2 := gate(c), gate(newClock())
	if err := g1.Summary(g1.Ask(), 1, capped(1000, 0, "x")); err != nil {
		t.Fatal(err)
	}
	s, err := g1.Reserve("x", 250) // 500
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 1000 {
			_ = g1.Summary(g1.Ask(), 1, capped(1000, 0, "x"))
		}
	}()
	g2.End(s)
	g2.End(Send{})
	<-done
	if _, err := g1.Reserve("x", 251); err == nil { // 500 + 502
		t.Fatal("another gate's End made g1 forget its send")
	}
	g1.End(s)
	if err := g1.Summary(g1.Ask(), 1, capped(1000, 500, "x")); err != nil {
		t.Fatal(err)
	}
	if _, err := g1.Reserve("x", 250); err != nil { // 500 + 500: held once
		t.Fatalf("after its own End: %v", err)
	}
}

// Random interleavings of reserve, partial emission, end, ask, answers in
// any order and duplicated, pauses, day rollover and group merges, with a
// clock that steps forward and back, against a fake enforcer that trips
// past its cap with wire.PastCap: it never trips (Security model test).
func TestModelNeverTrips(t *testing.T) {
	type send struct {
		s      Send
		dest   string
		budget uint64 // bytes it may still emit
	}
	type req struct {
		tk        Ticket
		processed bool
		paused    bool
		day       uint32
		groups    []Group
	}
	dests := []string{"a", "b", "c"}
	for seed := int64(0); seed < 2000; seed++ {
		r := rand.New(rand.NewSource(seed))
		c := newClock()
		g := gate(c)
		caps := map[string]uint64{}
		groupOf := map[string]int{}
		for i, d := range dests {
			caps[d], groupOf[d] = uint64(50+r.Intn(200)), i
		}
		count := map[int]uint64{}
		day, paused := uint32(1), false
		var sends []*send
		var reqs []*req
		capOf := func(gi int) (s uint64) {
			for d, x := range groupOf {
				if x == gi {
					s += caps[d]
				}
			}
			return s
		}
		groupsNow := func() (out []Group) {
			by := map[int]*Group{}
			for _, d := range dests {
				gi := groupOf[d]
				if by[gi] == nil {
					by[gi] = &Group{Count: count[gi], Cap: capOf(gi)}
				}
				by[gi].Dests = append(by[gi].Dests, d)
			}
			for _, gr := range by {
				out = append(out, *gr)
			}
			return out
		}
		for step := 0; step < 400; step++ {
			switch r.Intn(10) {
			case 0, 1:
				d := dests[r.Intn(3)]
				size := uint64(1 + r.Intn(60))
				if s, err := g.Reserve(d, size); err == nil {
					sends = append(sends, &send{s: s, dest: d, budget: size * (1 + Retries)})
				}
			case 2, 3:
				if len(sends) > 0 {
					ss := sends[r.Intn(len(sends))]
					if ss.budget > 0 {
						n := uint64(1 + r.Intn(int(ss.budget)))
						ss.budget -= n
						gi := groupOf[ss.dest]
						count[gi] += n
						if wire.PastCap(count[gi], capOf(gi)) {
							t.Fatalf("seed %d step %d: trip: group %d at %d of %d", seed, step, gi, count[gi], capOf(gi))
						}
					}
				}
			case 4:
				if len(sends) > 0 {
					i := r.Intn(len(sends))
					g.End(sends[i].s) // no byte of it leaves after End
					sends = append(sends[:i], sends[i+1:]...)
				}
			case 5:
				reqs = append(reqs, &req{tk: g.Ask()})
			case 6:
				for _, q := range reqs { // the enforcer takes the oldest request's count
					if !q.processed {
						q.processed, q.paused, q.day, q.groups = true, paused, day, groupsNow()
						break
					}
				}
			case 7:
				if len(reqs) > 0 {
					i := r.Intn(len(reqs))
					if q := reqs[i]; q.processed {
						if q.paused {
							g.Paused()
						} else {
							_ = g.Summary(q.tk, q.day, q.groups)
						}
						if r.Intn(4) != 0 { // sometimes delivered again
							reqs = append(reqs[:i], reqs[i+1:]...)
						}
					}
				}
			case 8:
				c.step(time.Duration(r.Intn(80)-30) * time.Second) // forward or back
				if r.Intn(30) == 0 {
					day++
					count = map[int]uint64{}
				}
				if r.Intn(20) == 0 {
					paused = !paused
				}
			case 9:
				if ga, gb := groupOf["a"], groupOf["b"]; r.Intn(10) == 0 && ga != gb {
					count[ga] += count[gb] // groups merge mid-day: counts add
					delete(count, gb)
					for d, x := range groupOf {
						if x == gb {
							groupOf[d] = ga
						}
					}
				}
			}
		}
	}
}
