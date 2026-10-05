package pubid

// REQ: OSS-6

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// offsets are the clock errors the model draws from: a clock kept in
// local time, every 7 hours from -71h to +71h (steps back onto the day
// before an off day among them), steps back of days to months, steps
// ahead, and a clock far ahead.
var offsets = func() []time.Duration {
	o := []time.Duration{
		-10 * 24 * time.Hour, -26 * 24 * time.Hour, -40 * 24 * time.Hour, -60 * 24 * time.Hour,
		5 * 24 * time.Hour, 10 * 24 * time.Hour, 40 * 24 * time.Hour, 100 * 365 * 24 * time.Hour,
	}
	for h := -71; h <= 71; h += 7 {
		o = append(o, time.Duration(h)*time.Hour)
	}
	return o
}()

type simItem struct {
	queued   time.Time // true time
	wait     int       // the drawn delay
	restarts int       // broker restarts during the wait
	changed  bool      // the clock was changed during the wait
	left     bool
}

// The guarantee (DECISIONS.md, OSS-6 clock), over random clocks, off
// spans and restarts: an item with delay k leaves no sooner than
// (k-1-r)*20h after it was queued, r being the broker restarts during its
// wait (G1, G2); with no clock change during its wait, no sooner than k-1
// days and the release time, as with a right clock; no day gets two
// batches (G4); and once the clock is right for good, every item leaves.
func TestOSS6ClockModel(t *testing.T) {
	for seed := uint64(0); seed < 24; seed++ {
		simulate(t, seed)
	}
}

func simulate(t *testing.T, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 7))
	g := newRig(t, 0)
	real := g.c.t
	restart := func() {
		start := real
		g.mono = func() time.Duration { return real.Sub(start) }
		g.reopen(t)
		g.p.cfg.Rand = cryptoish{r}
	}
	restart()
	var off time.Duration
	items := map[string]*simItem{}
	published := map[string]bool{}
	seen, steady, offUntil := 0, 0, -1
	const hours = 100 * 24
	for h := 0; h < hours+20*24; h++ {
		real = real.Add(time.Hour)
		change := h < hours && r.IntN(40) == 0
		if change || h == hours { // the clock is right for good from here
			off = 0
			if change && r.IntN(3) != 0 {
				off = offsets[r.IntN(len(offsets))]
			}
			for _, it := range items {
				it.changed = it.changed || !it.left
			}
		}
		g.c.t = real.Add(off)
		if h < hours && h > offUntil && r.IntN(150) == 0 {
			offUntil = h + 20 + r.IntN(40) // the box is off
		}
		if h <= offUntil {
			continue
		}
		if h == offUntil+1 || r.IntN(50) == 0 {
			restart()
			for _, it := range items {
				if !it.left {
					it.restarts++
				}
			}
		}
		if h < hours && r.IntN(6) == 0 && g.p.Len() < MaxQueue {
			name := fmt.Sprintf("%d-%d", seed, h)
			seenBefore, daysBefore := g.p.st.Seen, slices.Clone(g.p.st.Days)
			if err := g.p.Queue("artifact", []byte(name)); err == nil {
				// The drawn delay: the stored wait, less the day added when
				// no release had counted today yet.
				k := g.p.st.Items[len(g.p.st.Items)-1].Wait
				if day(g.c.t) != seenBefore || !slices.Contains(daysBefore, seenBefore) {
					k--
				}
				items[name] = &simItem{queued: real, wait: k}
			}
		}
		must(t, g.p.Release())
		for ; seen < len(g.out.got); seen++ {
			b := g.out.got[seen]
			if published[b.day] {
				t.Fatalf("seed %d: day %s published twice", seed, b.day)
			}
			published[b.day] = true
			for _, raw := range b.batch {
				name := string(raw[32:])
				it := items[name]
				it.left = true
				el := real.Sub(it.queued)
				if el < time.Duration(it.wait-1-it.restarts)*20*time.Hour {
					t.Fatalf("seed %d: %s left after %v, wait %d, %d restarts", seed, name, el, it.wait, it.restarts)
				}
				if !it.changed {
					steady++
					if el < time.Duration(it.wait-1)*24*time.Hour+DefaultReleaseAt {
						t.Fatalf("seed %d: %s left after %v under a steady clock, wait %d", seed, name, el, it.wait)
					}
				}
			}
		}
	}
	if steady == 0 {
		t.Fatalf("seed %d: no item waited under a steady clock", seed)
	}
	if n := g.p.Len(); n != 0 {
		t.Fatalf("seed %d: %d items never left", seed, n)
	}
}

// cryptoish feeds delay draws from the test's seeded source.
type cryptoish struct{ r *rand.Rand }

func (c cryptoish) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c.r.Uint32())
	}
	return len(p), nil
}

// L3 round 5 MUST 1, as probed: day 6 is an off day; a 2-day item queued
// at 23:59 on day 10; day 11 counts; the clock steps back to 23:59 on day
// 5, and 05:00 on day 6 comes. A step after a jump only rebuilds the chain,
// so day 6 does not count and the item does not leave early. The floor is
// kept out of it: every monotonic reading here is a day apart.
func TestOSS6StepBackOntoAnOffDay(t *testing.T) {
	g := newRig(t, 1) // every delay is 2 days
	for d := 1; d <= 10; d++ {
		if d != 6 {
			g.day(d, 6*time.Hour)
			must(t, g.p.Release())
		}
	}
	g.day(10, 23*time.Hour+59*time.Minute)
	must(t, g.p.Queue("artifact", []byte("a")))
	g.day(11, 5*time.Hour)
	must(t, g.p.Release())
	g.day(5, 23*time.Hour+59*time.Minute)
	must(t, g.p.Release())
	g.day(6, 5*time.Hour)
	must(t, g.p.Release())
	for d := 11; d <= 12; d++ {
		g.day(d, 11*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 0 {
		t.Fatalf("left early on %s", g.out.got[0].day)
	}
	g.day(13, 6*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 1 {
		t.Fatal("did not leave once the chain was rebuilt")
	}
}

// G1: within one broker process, a clock moved on a day every 5 hours
// still counts at most one day per 20 hours of monotonic time.
func TestOSS6MonotonicFloor(t *testing.T) {
	g := newRig(t, 2) // every delay is 3 days
	real := g.c.t
	start := real
	g.mono = func() time.Duration { return real.Sub(start) }
	g.reopen(t)
	g.warm(t, g.p)
	clock := g.c.t
	must(t, g.p.Queue("artifact", []byte("a")))
	queued := real
	for i := 0; i < 200 && len(g.out.got) == 0; i++ {
		real = real.Add(time.Hour)
		if i%5 == 0 {
			clock = clock.Add(24 * time.Hour)
		}
		g.c.t = clock.Add(real.Sub(queued) % time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 1 {
		t.Fatal("never left")
	}
	if el := real.Sub(queued); el < 2*20*time.Hour {
		t.Fatalf("left after %v of monotonic time", el)
	}
}

// G3: a box off on alternate days, or two days in a row, keeps counting a
// day each time it is on; off for three days in a row, the first two days
// it sees after only rebuild the chain.
func TestOSS6OffDaysKeepCounting(t *testing.T) {
	g := newRig(t, 2) // every delay is 3 days
	must(t, g.p.Queue("artifact", []byte("a")))
	for _, d := range []int{2, 4, 7} { // off on 1, 3, 5 and 6
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 1 {
		t.Fatalf("off days stopped the count: %+v", g.out.got)
	}
	must(t, g.p.Queue("artifact", []byte("b")))
	for _, d := range []int{11, 12} { // off on 8, 9 and 10
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	for _, d := range []int{13, 14} {
		g.day(d, 12*time.Hour)
		must(t, g.p.Release())
	}
	if len(g.out.got) != 1 {
		t.Fatalf("a four-day move counted: %+v", g.out.got)
	}
	g.day(15, 12*time.Hour)
	must(t, g.p.Release())
	if len(g.out.got) != 2 {
		t.Fatal("did not count again once the chain was rebuilt")
	}
}
