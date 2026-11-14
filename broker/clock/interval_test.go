package clock

// REQ: TIM-1, KEY-4, CLK-2

import (
	"os"
	"path/filepath"
	"strconv"
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

// trackOffset is chronyc tracking with the system clock off its selected
// source by off (field 5, seconds; chronyd slews it out).
func trackOffset(off time.Duration) string {
	return "C0000201,192.0.2.1,2,1791230000.123456789," + strconv.FormatFloat(off.Seconds(), 'f', 6, 64) + ",0.000002,0.000003,-1.234,0.001,0.010,0.012,0.001,64.1,Normal\n"
}

func TestTIM1SlewingNTSDoesNotBoundAnHonestCarrier(t *testing.T) {
	// Security finding 1 on #5754: a forged plain-NTP step at boot leaves the
	// box clock hours off while chronyd selects an NTS source and slews
	// toward it at 500 ppm. The source is authenticated, the clock is not:
	// the honest carrier must still widen the interval, so Earliest is true
	// time and no hold ends early.
	for _, off := range []time.Duration{3 * time.Hour, -3 * time.Hour} {
		r := newRig()
		truth := r.wall
		r.wall = r.wall.Add(off) // box clock off; carrier honest
		offset := off
		g := r.guard(t, func(c *Config) {
			c.Sync = func() (SyncKind, error) {
				return chronySync(bg, chronycOut(trackOffset(offset), srcNTS, authNTS, nil))
			}
		})
		lo, hi, s := g.Interval(bg)
		if s.Authenticated {
			t.Fatalf("offset %v: an unconverged clock counts as authenticated: %+v", off, s)
		}
		wantLo, wantHi := truth, truth.Add(off)
		if off < 0 {
			wantLo, wantHi = wantHi, wantLo
		}
		if !lo.Equal(wantLo) || !hi.Equal(wantHi) {
			t.Fatalf("offset %v: interval [%v, %v], want it to span true time %v and the box clock", off, lo, hi, truth)
		}
		r.advance(DefaultInterval)
		if e, _ := g.Earliest(bg); e.After(truth.Add(DefaultInterval)) {
			t.Fatalf("offset %v: Earliest %v ahead of true time %v", off, e, truth.Add(DefaultInterval))
		}
	}
	// Converged (offset within NTSConverged), the source's authentication
	// stands for the clock.
	r := newRig()
	r.carrier = r.carrier.Add(3 * time.Hour)
	g := r.guard(t, func(c *Config) {
		c.Sync = func() (SyncKind, error) {
			return chronySync(bg, chronycOut(trackOffset(-20*time.Millisecond), srcNTS, authNTS, nil))
		}
	})
	if _, _, s := g.Interval(bg); !s.Authenticated {
		t.Fatalf("converged NTS: %+v", s)
	}
}

// syncAs makes the rig's sync whatever *k says at each check.
func syncAs(k *SyncKind) func(*Config) {
	return func(c *Config) { c.Sync = func() (SyncKind, error) { return *k, nil } }
}

func TestTIM1AuthenticatedOutlierLosingItsCarrierStaysDisagree(t *testing.T) {
	// L3 blocker 1 on #5754: a forged +5h carrier under NTS, then the
	// carrier goes quiet and NTS drops. The disagreement stays in force and
	// STATUS names the wide interval, never "not checked".
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	kind := SyncedNTS
	g := r.guard(t, syncAs(&kind))
	if s := g.Check(bg); s.State != Disagree || !s.Authenticated {
		t.Fatalf("status = %+v", s)
	}
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	r.advance(20 * time.Minute)
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("carrier lost: status = %+v, want the disagreement kept", s)
	}
	kind = NotSynced
	r.advance(20 * time.Minute)
	s := g.Check(bg)
	lo, hi, _ := g.Interval(bg)
	if s.State != Disagree || s.Authenticated || hi.Sub(lo) != 5*time.Hour {
		t.Fatalf("NTS lost: status = %+v, width %v", s, hi.Sub(lo))
	}
	if l := s.IntervalLine(time.UTC); !strings.Contains(l, "differ by about 5 hours") {
		t.Fatalf("line = %q, want the wide interval named", l)
	}
}

func TestTIM1AuthenticatedDisagreementSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	kind := SyncedNTS
	edit := func(c *Config) { syncAs(&kind)(c); c.StatePath = path }
	g := r.guard(t, edit)
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("status = %+v", s)
	}
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	g = r.guard(t, edit)
	if s := g.Check(bg); s.State != Disagree || s.Skew != -5*time.Hour {
		t.Fatalf("after restart: status = %+v, want the disagreement kept", s)
	}
}

func TestTIM1LostStateUnderNTSStaysDisagree(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := noCarrier()
	kind := SyncedNTS
	g := r.guard(t, func(c *Config) { syncAs(&kind)(c); c.StatePath = path })
	for i := range 2 {
		if s := g.Check(bg); s.State != Disagree {
			t.Fatalf("check %d: status = %+v, want the lost check kept until carrier time agrees", i, s)
		}
		r.advance(20 * time.Minute)
	}
	if txt := r.sent(); len(txt) != 1 || txt[0] != StateLostText {
		t.Fatalf("texts = %q", txt)
	}
}
