package clock

// REQ: TIM-1, KEY-4, CLK-2

import (
	"strings"
	"testing"
	"time"
)

// nts makes the rig's NTP sync NTS-authenticated.
func nts(c *Config) { c.Sync = func() (SyncKind, error) { return SyncedNTS, nil } }

func TestTIM1IntervalSpansBothSourcesWhenTheyDisagree(t *testing.T) {
	for _, skew := range []time.Duration{3 * time.Hour, -3 * time.Hour} {
		r := newRig()
		box := r.wall
		r.carrier = r.carrier.Add(skew)
		g := r.guard(t, nil)
		lo, hi, s := g.Interval(bg)
		if s.State != Disagree {
			t.Fatalf("skew %v: status = %+v", skew, s)
		}
		wantLo, wantHi := box, box.Add(skew)
		if skew < 0 {
			wantLo, wantHi = wantHi, wantLo
		}
		if !lo.Equal(wantLo) || !hi.Equal(wantHi) {
			t.Fatalf("skew %v: interval [%v, %v], want [%v, %v]", skew, lo, hi, wantLo, wantHi)
		}
		// The ends are Earliest and Latest: a widening waits for the start,
		// a narrowing fires at the end (TIM-1; KEY-4 and CLK-2's clerk hold).
		if e, _ := g.Earliest(bg); !e.Equal(lo) {
			t.Fatalf("skew %v: Earliest %v, interval start %v", skew, e, lo)
		}
		if l, _ := g.Latest(bg); !l.Equal(hi) {
			t.Fatalf("skew %v: Latest %v, interval end %v", skew, l, hi)
		}
		// Carried forward on the monotonic clock, it keeps its width.
		r.advance(time.Hour)
		lo2, hi2, _ := g.Interval(bg)
		if hi2.Sub(lo2) != hi.Sub(lo) || !lo2.Equal(lo.Add(time.Hour)) {
			t.Fatalf("skew %v: an hour on, [%v, %v]", skew, lo2, hi2)
		}
	}
}

func TestTIM1IntervalIsNarrowWhileTheyAgree(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(90 * time.Second)
	g := r.guard(t, nil)
	lo, hi, s := g.Interval(bg)
	if s.State != Agreed || !lo.Equal(r.wall) || hi.Sub(lo) != 90*time.Second {
		t.Fatalf("interval [%v, %v], %+v", lo, hi, s)
	}
	r = noCarrier()
	g = r.guard(t, nil)
	if lo, hi, _ := g.Interval(bg); !lo.Equal(hi) {
		t.Fatalf("one source: [%v, %v]", lo, hi)
	}
}

func TestTIM1AuthenticatedTimeBoundsAnOutlierCarrier(t *testing.T) {
	// A fake base station's time hours off widens the interval by at most
	// the tolerance against NTS-authenticated network time, so expiries
	// judged on its end do not fire hours early (issue #5216 item 4).
	for _, skew := range []time.Duration{3 * time.Hour, -3 * time.Hour, 400 * 24 * time.Hour} {
		r := newRig()
		box := r.wall
		r.carrier = r.carrier.Add(skew)
		g := r.guard(t, nts)
		lo, hi, s := g.Interval(bg)
		if s.State != Disagree || !s.Authenticated {
			t.Fatalf("skew %v: status = %+v", skew, s)
		}
		if hi.Sub(box) > DefaultTolerance || box.Sub(lo) > DefaultTolerance {
			t.Fatalf("skew %v: interval [%v, %v] stretched past the tolerance around %v", skew, lo, hi, box)
		}
		if s.Restricted() {
			t.Fatalf("skew %v: an outlier against authenticated time restricts", skew)
		}
		if now, err := g.Now(bg); err != nil || !now.Equal(box) {
			t.Fatalf("skew %v: Now = %v, %v", skew, now, err)
		}
		// The owner still hears of the disagreement, once.
		if txt := r.sent(); len(txt) != 1 || !strings.Contains(txt[0], "authenticated") {
			t.Fatalf("skew %v: texts = %q", skew, txt)
		}
		// Without authentication the same carrier widens it fully.
		g2 := r.guard(t, nil)
		lo, hi, s = g2.Interval(bg)
		if s.Authenticated || hi.Sub(lo) != skew && hi.Sub(lo) != -skew {
			t.Fatalf("skew %v: plain NTP interval [%v, %v], %+v", skew, lo, hi, s)
		}
	}
}

func TestTIM1IntervalLine(t *testing.T) {
	zone := time.FixedZone("x", 2*3600)
	plain := Status{State: Disagree, Skew: 3 * time.Hour, Since: time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC), Verified: true}
	if got := plain.IntervalLine(zone); got != "Time check: box and phone network differ by about 3 hours since 06:00, so holds and timeouts end by both clocks and expiries by either, until they agree." {
		t.Fatalf("line = %q", got)
	}
	auth := plain
	auth.Authenticated = true
	if got := auth.IntervalLine(zone); got != "Time check: phone network differs from authenticated network time by about 3 hours since 06:00; network time stands." {
		t.Fatalf("line = %q", got)
	}
	lost := Status{State: Disagree, Since: plain.Since}
	if got := lost.IntervalLine(zone); got != "Time check: playing safe since 06:00 (saved check unreadable; waiting for phone-network time)." {
		t.Fatalf("line = %q", got)
	}
	for _, st := range []Status{{State: Agreed, Verified: true}, {State: Held, Skew: time.Hour, Verified: true}, {Start: plain.Since}} {
		if got, old := st.IntervalLine(zone), st.Line(zone); got != old {
			t.Fatalf("%v: line = %q, want %q", st.State, got, old)
		}
	}
	for _, st := range []Status{plain, auth, lost} {
		if strings.Contains(st.IntervalLine(zone), "restricted") {
			t.Fatalf("line names the removed mode: %q", st.IntervalLine(zone))
		}
	}
}

func TestTIM1OwnerTextsDescribeTheInterval(t *testing.T) {
	texts := []string{DisagreeText(3 * time.Hour), DisagreeText(3*time.Hour + 4*time.Minute), OutlierText(3 * time.Hour), StateLostText}
	for _, txt := range texts {
		for _, old := range []string{"restricted", "requests won't expire", "pre-allowances", "updates wait"} {
			if strings.Contains(txt, old) {
				t.Errorf("text names the removed mode (%q): %q", old, txt)
			}
		}
		if len(txt) > 306 { // two GSM-7 segments
			t.Errorf("text too long (%d): %q", len(txt), txt)
		}
	}
	if !strings.Contains(texts[0], "both clocks") || !strings.Contains(texts[0], "Codes and STOP work as usual.") {
		t.Errorf("DisagreeText = %q", texts[0])
	}
	if !strings.Contains(texts[2], "about 3 hours") || !strings.Contains(texts[2], "Nothing to do.") {
		t.Errorf("OutlierText = %q", texts[2])
	}
}
