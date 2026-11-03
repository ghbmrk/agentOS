package attention

import (
	"math"
	"time"
)

// Silent failures before standing keys (D-309, KEY-5). Silent failures per
// errand come to roughly steps x error rate x the share of failures nobody
// notices, so a key that takes the owner out of each step waits until the
// clerk is seen to catch its own failures. The measure comes only from the
// log: each effect with the clerk's own check of its resulting state
// (OWN-13), and each owner correction of an effect. A failure the owner
// never noticed either is invisible, so the measured rate is a lower bound
// on the true one; the settle window below gives the owner time to notice.

// Outcome is one effect a clerk ran, or the owner's later correction of
// it, as the log holds it. Every field comes from the kernel and the
// clerk, never from a planner.
type Outcome struct {
	Clerk string
	// Step is the effect's log ID; a second correction of one step
	// counts once.
	Step string
	// Ran is when the effect ran; it places the effect in the window.
	Ran time.Time
	// Flagged: the clerk's own check of the resulting state reported the
	// effect failed or unconfirmed (OWN-13).
	Flagged bool
	// Corrected: this record is the owner's correction of the effect (an
	// UNDO, a wrong verdict, OP-7, or a redo), not the effect itself.
	Corrected bool
	// At is when this record was logged.
	At time.Time
}

// Window is how far back the measure looks, and Settle how old an effect
// must be before it counts: a correction can come days after the effect,
// and counting a fresh effect before the owner could correct it would
// lower the rate. Corrections that come later still count.
const (
	Window = 90 * 24 * time.Hour
	Settle = 7 * 24 * time.Hour
)

// record is one clerk's effects, by the UTC day each ran.
type record struct {
	Days map[string]*tally `json:"days"`
	// Corrected names each corrected step, with its day, so a second
	// correction of one step counts once.
	Corrected map[string]string `json:"corrected,omitempty"`
}

type tally struct {
	Effects int `json:"effects"`
	Flagged int `json:"flagged,omitempty"`
	Silent  int `json:"silent,omitempty"`
}

const dayFmt = "2006-01-02"

// Record logs one outcome. An effect counts once, as it ran; a correction
// of an effect its clerk did not flag counts as a silent failure, once
// per step. A flagged effect is already a failure the clerk caught, so its
// correction adds nothing. Outcomes older than Window are dropped.
func (o *Optimizer) Record(x Outcome) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tick(x.At)
	o.tick(x.Ran)
	r := o.st.Clerks[x.Clerk]
	if r == nil {
		r = &record{Days: map[string]*tally{}}
		o.st.Clerks[x.Clerk] = r
	}
	o.prune()
	day := x.Ran.UTC().Format(dayFmt)
	if x.Ran.Before(o.st.Now.Add(-Window)) {
		return o.save()
	}
	t := r.Days[day]
	if t == nil {
		t = &tally{}
		r.Days[day] = t
	}
	switch {
	case !x.Corrected:
		t.Effects++
		if x.Flagged {
			t.Flagged++
		}
	case !x.Flagged:
		if _, seen := r.Corrected[x.Step]; !seen {
			if r.Corrected == nil {
				r.Corrected = map[string]string{}
			}
			r.Corrected[x.Step] = day
			t.Silent++
		}
	}
	return o.save()
}

// tick advances the measure's clock.
func (o *Optimizer) tick(at time.Time) {
	if at.After(o.st.Now) {
		o.st.Now = at
	}
}

// prune drops every day that has left the window, with its corrections.
func (o *Optimizer) prune() {
	cut := o.st.Now.Add(-Window).UTC().Format(dayFmt)
	for _, r := range o.st.Clerks {
		for d := range r.Days {
			if d < cut {
				delete(r.Days, d)
			}
		}
		for s, d := range r.Corrected {
			if d < cut {
				delete(r.Corrected, s)
			}
		}
	}
}

// Measure is one clerk's settled record: effects that ran between Window
// and Settle ago.
type Measure struct {
	// Effects counts the settled effects; Flagged the failures the
	// clerk's own check reported; Silent those only the owner found.
	Effects, Flagged, Silent int
	// Bound is the one-sided 95% upper bound (Wilson score) on the
	// silent-failure rate, Silent over Effects; 1 with no effects.
	Bound float64
	// Ready: Bound is at most Config.MaxSilentPerMille. With no silent
	// failure at the 1% default, that takes at least 268 settled effects.
	Ready bool
}

// Detection is the share of the clerk's known failures its own check
// caught; 1 when none is known.
func (m Measure) Detection() float64 {
	if m.Flagged+m.Silent == 0 {
		return 1
	}
	return float64(m.Flagged) / float64(m.Flagged+m.Silent)
}

// Measure returns clerk's settled record and whether it passes the gate.
func (o *Optimizer) Measure(clerk string) Measure {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.measureLocked(clerk)
}

func (o *Optimizer) measureLocked(clerk string) Measure {
	var m Measure
	if r := o.st.Clerks[clerk]; r != nil {
		lo := o.st.Now.Add(-Window).UTC().Format(dayFmt)
		// A day counts once all of it is Settle old.
		hi := o.st.Now.Add(-Settle).UTC().Add(-24 * time.Hour).Format(dayFmt)
		for d, t := range r.Days {
			if d >= lo && d <= hi {
				m.Effects += t.Effects
				m.Flagged += t.Flagged
				m.Silent += t.Silent
			}
		}
	}
	m.Bound = upper(m.Silent, m.Effects)
	m.Ready = m.Bound*1000 <= float64(o.cfg.MaxSilentPerMille)
	return m
}

// upper is the one-sided 95% Wilson upper bound on s/n. A correction of
// an effect logged before the measure began can make s exceed n; s is
// capped at n, so the bound is then 1 and the gate stays shut.
func upper(s, n int) float64 {
	if n <= 0 {
		return 1
	}
	s = min(s, n)
	const z = 1.6448536269514722
	fn := float64(n)
	p := float64(s) / fn
	z2 := z * z
	return (p + z2/(2*fn) + z*math.Sqrt(p*(1-p)/fn+z2/(4*fn*fn))) / (1 + z2/fn)
}
