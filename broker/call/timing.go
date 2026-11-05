package call

import (
	"slices"
	"time"
)

// Spread is a set of turn times as the flip-phone note §2.4 reports them:
// the median with the 95th and 99th percentiles beside it.
type Spread struct {
	N             int
	P50, P95, P99 time.Duration
}

// Percentiles takes the nearest-rank percentiles of ds, ignoring zeros
// (a turn that played nothing has no time).
func Percentiles(ds []time.Duration) Spread {
	var v []time.Duration
	for _, d := range ds {
		if d > 0 {
			v = append(v, d)
		}
	}
	if len(v) == 0 {
		return Spread{}
	}
	slices.Sort(v)
	rank := func(p int) time.Duration {
		i := (p*len(v) + 99) / 100 // ceil(p/100 * n)
		return v[max(i, 1)-1]
	}
	return Spread{N: len(v), P50: rank(50), P95: rank(95), P99: rank(99)}
}

// Timing is the call's spread of first audio (any clip or sentence) and of
// first content, each measured from the end of the owner's speech.
func (r Report) Timing() (audio, content Spread) {
	var a, c []time.Duration
	for _, t := range r.Turns {
		a = append(a, t.FirstAudio)
		c = append(c, t.FirstContent)
	}
	return Percentiles(a), Percentiles(c)
}
