package pubid

// REQ: OSS-6

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// offsets are the clock errors the model draws from: right, a clock kept
// in local time, a day either way, steps back of days to months, steps
// ahead, and a clock far ahead.
var offsets = []time.Duration{
	0, -5 * time.Hour, 4 * time.Hour, 10 * time.Hour, -24 * time.Hour, 24 * time.Hour,
	-10 * 24 * time.Hour, -26 * 24 * time.Hour, -40 * 24 * time.Hour, -60 * 24 * time.Hour,
	2 * 24 * time.Hour, 5 * 24 * time.Hour, 10 * 24 * time.Hour, 40 * 24 * time.Hour,
	100 * 365 * 24 * time.Hour,
}

type simItem struct {
	queued  time.Time // true time
	qOff    time.Duration
	wait    int
	jumps   int           // clock changes during the wait that moved the day on by exactly one
	forward time.Duration // how far clock changes during the wait moved it on, each up to two days
	left    bool
}

// The clock model as one property, over random clocks: an item queued
// with a delay of k days leaves no sooner than k-1 days and the release
// time after it was queued (as with a right clock: queued just before
// midnight, it leaves at the release time k days later), less how far
// clock changes moved the clock on during its wait (each counted up to two
// days) and a day for each change that moved the day on by exactly one.
// Nothing else, no change back, ahead or far ahead, shortens it. No day gets two
// batches, and once the clock is right for good every item leaves (L3
// round 4 on #163).
func TestOSS6ClockModel(t *testing.T) {
	for seed := uint64(0); seed < 24; seed++ {
		simulate(t, seed)
	}
}

func simulate(t *testing.T, seed uint64) {
	r := rand.New(rand.NewPCG(seed, 7))
	g := newRig(t, 0)
	g.p.cfg.Rand = cryptoish{r}
	real := g.c.t
	var off time.Duration
	items := map[string]*simItem{}
	published := map[string]bool{}
	seen, steady := 0, 0
	const hours = 100 * 24
	for h := 0; h < hours+20*24; h++ {
		real = real.Add(time.Hour)
		change := h < hours && r.IntN(40) == 0
		if change || h == hours { // the clock is right for good from here
			old, was := day(real.Add(off)), off
			off = 0
			if change && r.IntN(3) != 0 {
				off = offsets[r.IntN(len(offsets))]
			}
			if d := min(off-was, 48*time.Hour); d > 0 {
				for _, it := range items {
					if !it.left {
						it.forward += d
					}
				}
			}
			if n := day(real.Add(off)); n != old {
				if a, _ := time.Parse("2006-01-02", old); day(a.AddDate(0, 0, 1)) == n {
					for _, it := range items {
						if !it.left {
							it.jumps++
						}
					}
				}
			}
		}
		g.c.t = real.Add(off)
		if h < hours && r.IntN(6) == 0 && g.p.Len() < MaxQueue {
			name := fmt.Sprintf("%d-%d", seed, h)
			seenBefore, daysBefore := g.p.st.Seen, slices.Clone(g.p.st.Days)
			if err := g.p.Queue("artifact", []byte(name)); err == nil {
				// The drawn delay: the stored wait, less the day added when
				// no release had seen today yet.
				k := g.p.st.Items[len(g.p.st.Items)-1].Wait
				if day(g.c.t) != seenBefore || !slices.Contains(daysBefore, seenBefore) {
					k--
				}
				items[name] = &simItem{queued: real, qOff: off, wait: k}
			}
		}
		if r.IntN(50) == 0 {
			g.reopen(t)
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
				floor := time.Duration(it.wait-1-it.jumps)*24*time.Hour + DefaultReleaseAt - it.forward
				if el < floor {
					t.Fatalf("seed %d: %s left after %v, wait %d, %d one-day jumps, moved on %v",
						seed, name, el, it.wait, it.jumps, it.forward)
				}
				if it.jumps == 0 && it.forward == 0 {
					steady++
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
