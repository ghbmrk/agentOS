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
	if got := plain.IntervalLine(zone); got != "Time check: box and phone network differ by about 3 hours since 06:00, so holds and timeouts end by both clocks and expiries by either, until they agree. Nothing to do." {
		t.Fatalf("line = %q", got)
	}
	auth := plain
	auth.Authenticated = true
	if got := auth.IntervalLine(zone); got != "Time check: phone network differs from authenticated network time by about 3 hours since 06:00, so network time stands (a fake phone mast can do this). Nothing to do." {
		t.Fatalf("line = %q", got)
	}
	lost := Status{State: Disagree, Since: plain.Since}
	if got := lost.IntervalLine(zone); got != "Time check: saved check unreadable since 06:00, so holds and timeouts wait until phone-network time or authenticated network time confirms the clock. Nothing to do." {
		t.Fatalf("line = %q", got)
	}
	for _, st := range []Status{{State: Agreed, Verified: true}, {State: Held, Skew: time.Hour, Verified: true}, {Start: plain.Since}} {
		if got, old := st.IntervalLine(zone), st.Line(zone); got != old {
			t.Fatalf("%v: line = %q, want %q", st.State, got, old)
		}
	}
	lostAuth := lost
	lostAuth.Authenticated = true
	for _, st := range []Status{plain, auth, lost, lostAuth} {
		if strings.Contains(st.IntervalLine(zone), "restricted") {
			t.Fatalf("line names the removed mode: %q", st.IntervalLine(zone))
		}
		// UX 1-4 on #5810: every disagreement line ends on its next step.
		if !strings.HasSuffix(st.IntervalLine(zone), " Nothing to do.") {
			t.Errorf("line names no next step: %q", st.IntervalLine(zone))
		}
	}
	// The skew is told in the largest whole unit, from each unit's start.
	for skew, want := range map[time.Duration]string{
		48 * time.Hour: "about 2 days", 2 * time.Hour: "about 2 hours", time.Hour: "about 1 hour",
		-time.Hour: "about 1 hour", 30 * time.Minute: "about 30 minutes",
	} {
		st := plain
		st.Skew = skew
		if got := st.IntervalLine(zone); !strings.Contains(got, "differ by "+want+" since") {
			t.Errorf("skew %v: line = %q, want %q", skew, got, want)
		}
	}
	// A skew of exactly the tolerance agrees, on either sign; a second past
	// it is a disagreement line.
	for _, skew := range []time.Duration{DefaultTolerance, -DefaultTolerance, DefaultTolerance + time.Second, -DefaultTolerance - time.Second} {
		r := newRig()
		r.carrier = r.wall.Add(-skew)
		s := r.guard(t, nil).Check(bg)
		agree := skew == DefaultTolerance || skew == -DefaultTolerance
		if got := s.IntervalLine(zone); (got == "Time check: box and phone network agree.") != agree {
			t.Errorf("skew %v: line = %q", skew, got)
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
	if !strings.Contains(texts[2], "about 3 hours") || !strings.Contains(texts[2], "Nothing to do.") || !strings.Contains(texts[2], "time-zone error") {
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
	// carrier goes quiet and NTS drops. The disagreement stays in force,
	// still bounded by the last NTS sync (#5758); once the box clock steps
	// away from it, STATUS names the wide interval, never "not checked".
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
	if s := g.Check(bg); s.State != Disagree || !s.Authenticated {
		t.Fatalf("NTS lost: status = %+v, want the NTS bound kept", s)
	}
	r.step(-10 * time.Minute)
	s := g.Check(bg)
	lo, hi, _ := g.Interval(bg)
	if s.State != Disagree || s.Authenticated || hi.Sub(lo) != 5*time.Hour+10*time.Minute {
		t.Fatalf("bound lost: status = %+v, width %v", s, hi.Sub(lo))
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
	edit := func(c *Config) {
		syncAs(&kind)(c)
		c.StatePath = path
		c.BootID = func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.boot }
	}
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

func TestTIM1LineNamesAnAuthenticatedOutlier(t *testing.T) {
	// UX blocker 1 on #5754: agentosd's STATUS still renders Line (#5279);
	// for an authenticated outlier it must not say "restricted" beside
	// OutlierText's "Nothing to do".
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	g := r.guard(t, nts)
	s := g.Check(bg)
	if got, want := s.Line(time.UTC), s.IntervalLine(time.UTC); got != want || strings.Contains(got, "restricted") {
		t.Fatalf("Line = %q, want %q", got, want)
	}
}

func TestTIM1NTSChangingDuringADisagreementRealerts(t *testing.T) {
	// UX blocker 2 on #5754 (L3 R1, #5758 R1): the NTS bound lapsing (the
	// box clock steps away from it) while the carrier still disagrees widens
	// the interval to the full skew and holds questions, so the owner told
	// "Nothing to do" hears DisagreeText; NTS returning is told under the cap.
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	kind := SyncedNTS
	g := r.guard(t, syncAs(&kind))
	g.Check(bg)
	kind = SyncedPlain
	r.advance(10 * time.Minute)
	r.step(-10 * time.Minute)
	s := g.Check(bg)
	if lo, hi, _ := g.Interval(bg); s.State != Disagree || s.Authenticated || hi.Sub(lo) != 5*time.Hour+10*time.Minute {
		t.Fatalf("status = %+v, width %v", s, hi.Sub(lo))
	}
	want := []string{OutlierText(-5 * time.Hour), DisagreeText(s.Skew)}
	if got := r.sent(); len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("texts = %q, want %q", got, want)
	}
	// At the cap now (two alerts): NTS returning is not texted, NTS lapsing
	// again is not either, since the owner's last word is DisagreeText.
	kind = SyncedNTS
	r.advance(10 * time.Minute)
	g.Check(bg)
	kind = SyncedPlain
	r.advance(10 * time.Minute)
	r.step(10 * time.Minute)
	g.Check(bg)
	if got := r.sent(); len(got) != 2 {
		t.Fatalf("flapping NTS at the cap: texts = %q", got)
	}
}

func TestTIM1OutlierAfterRebootDoesNotPinTheIntervalToTheFloor(t *testing.T) {
	// Potency blocker 1 on #5754: after a reboot, a fake mast disagreeing
	// from the first check must not hold Earliest at the last boot's floor
	// while converged NTS gives authenticated time.
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	g := rtcGuard(t, r, path, &rtc)
	if s := g.Check(bg); !s.Verified {
		t.Fatalf("boot b0 not verified: %+v", s)
	}
	r.advance(24 * time.Hour)
	g.Check(bg)
	r.reboot(r.wall)
	r.carrier = r.wall.Add(5 * time.Hour)
	g = rtcGuard(t, r, path, &rtc)
	for i := range 7 {
		s := g.Check(bg)
		lo, _, _ := g.Interval(bg)
		if s.State != Disagree || !s.Authenticated {
			t.Fatalf("check %d: status = %+v", i, s)
		}
		if lag := r.wall.Sub(lo); lag > DefaultTolerance || lag < -DefaultTolerance {
			t.Fatalf("check %d: Earliest lags authenticated time by %v", i, lag)
		}
		r.advance(8 * time.Hour)
	}
}

// setCarrier sets the rig's carrier reading (zero: none).
func (r *rig) setCarrier(t time.Time) { r.mu.Lock(); r.carrier = t; r.mu.Unlock() }

func TestTIM1NTSLapseEscalatesEvenAtTheCap(t *testing.T) {
	// UX delta 1 on #5754: an OutlierText that used the day's last alert,
	// then the NTS bound lapses: the owner still hears DisagreeText, since
	// questions are now held.
	r := newRig()
	kind := SyncedNTS
	g := r.guard(t, syncAs(&kind))
	r.setCarrier(r.wall.Add(5 * time.Hour))
	g.Check(bg) // OutlierText: alert 1
	r.setCarrier(r.wall)
	g.Check(bg)
	r.advance(AgreeAfter)
	g.Check(bg) // AgreeText
	r.setCarrier(r.wall.Add(5 * time.Hour))
	g.Check(bg) // OutlierText: alert 2, the cap
	kind = SyncedPlain
	r.advance(10 * time.Minute)
	r.step(-10 * time.Minute)
	g.Check(bg)
	got := r.sent()
	if len(got) != 4 || got[3] != DisagreeText(-5*time.Hour-10*time.Minute) {
		t.Fatalf("texts = %q, want DisagreeText fourth", got)
	}
	if _, err := g.Now(bg); err != ErrRestricted {
		t.Fatalf("Now err = %v", err)
	}
}

func TestTIM1HoldEscalatesToAnOutlierEvenAtTheCap(t *testing.T) {
	// L3 delta 1 on #5754: a hold at the cap that turns into an
	// authenticated disagreement is told, so HeldText is not the owner's
	// last word while the box keeps network time.
	r := newRig()
	g := r.guard(t, nts)
	r.setCarrier(r.wall.Add(5 * time.Hour))
	g.Check(bg) // OutlierText: alert 1
	r.setCarrier(r.wall)
	g.Check(bg)
	r.advance(AgreeAfter)
	g.Check(bg) // AgreeText
	r.setCarrier(time.Time{})
	r.step(2 * time.Hour)
	if s := g.Check(bg); s.State != Held {
		t.Fatalf("status = %+v, want held", s) // HeldText: alert 2, the cap
	}
	r.setCarrier(r.wall.Add(5 * time.Hour))
	s := g.Check(bg)
	got := r.sent()
	if s.State != Disagree || !s.Authenticated || len(got) != 4 || got[3] != OutlierText(s.Skew) {
		t.Fatalf("status = %+v, texts = %q, want OutlierText fourth", s, got)
	}
}

func TestTIM1AuthenticatedOutlierIsToldOnce(t *testing.T) {
	// mutgate on #5754 (clock.go, the `break` after OutlierText): later
	// checks of the same authenticated disagreement, with room under the
	// cap, send nothing more, and never DisagreeText.
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	g := r.guard(t, nts)
	s := g.Check(bg)
	for i := 0; i < 2; i++ {
		r.advance(10 * time.Minute)
		if s2 := g.Check(bg); s2.State != Disagree || !s2.Authenticated {
			t.Fatalf("check %d: status = %+v", i, s2)
		}
	}
	if got := r.sent(); len(got) != 1 || got[0] != OutlierText(s.Skew) {
		t.Fatalf("texts = %q, want only %q", got, OutlierText(s.Skew))
	}
}

// wantSpan fails unless [lo, hi] is [a, b].
func wantSpan(t *testing.T, what string, lo, hi, a, b time.Time) {
	t.Helper()
	if !lo.Equal(a) || !hi.Equal(b) {
		t.Fatalf("%s: interval [%v, %v], want [%v, %v]", what, lo, hi, a, b)
	}
}

func TestTIM1NTSBoundOutlivesTheSync(t *testing.T) {
	// #5758 R2: NTS blocked, then a forged carrier 5 h off. The last
	// converged NTS sync, carried forward on the boot clock, still bounds it:
	// the interval reaches the tolerance plus ntsDrift of the time since, so
	// no expiry fires hours early and no hold waits hours longer.
	for _, skew := range []time.Duration{5 * time.Hour, -5 * time.Hour} {
		r := newRig()
		kind := SyncedNTS
		g := r.guard(t, syncAs(&kind))
		if s := g.Check(bg); s.State != Agreed || !s.Authenticated {
			t.Fatalf("skew %v: status = %+v", skew, s)
		}
		kind = NotSynced
		r.advance(time.Hour)
		r.setCarrier(r.wall.Add(skew))
		lo, hi, s := g.Interval(bg)
		if s.State != Disagree || !s.Authenticated || s.Restricted() {
			t.Fatalf("skew %v: status = %+v", skew, s)
		}
		allow := DefaultTolerance + time.Hour/ntsDrift // 5 min 7.2 s
		if skew > 0 {
			wantSpan(t, "ahead", lo, hi, r.wall, r.wall.Add(allow))
		} else {
			wantSpan(t, "behind", lo, hi, r.wall.Add(-allow), r.wall)
		}
		if got := r.sent(); len(got) != 1 || got[0] != OutlierText(s.Skew) {
			t.Fatalf("skew %v: texts = %q", skew, got)
		}
		// The allowance grows with the boot clock's time since the sync:
		// after 50 days it is 5 min plus 2.4 h, and a carrier inside it
		// widens the interval fully.
		r.advance(50 * 24 * time.Hour)
		lo, hi, _ = g.Interval(bg)
		allow = DefaultTolerance + (50*24*time.Hour+time.Hour)/ntsDrift
		if skew > 0 {
			wantSpan(t, "50 days on", lo, hi, r.wall, r.wall.Add(allow))
		} else {
			wantSpan(t, "50 days on", lo, hi, r.wall.Add(-allow), r.wall)
		}
	}
}

func TestTIM1NTSBoundIsCentredOnAuthenticatedTime(t *testing.T) {
	// The bound is the NTS sync carried forward, not the box clock: a box
	// clock stepped within the allowance moves one end, never the bound, on
	// either side (a carrier ahead fires expiries early, one behind holds
	// waits; Lens B1 on #5893).
	for _, skew := range []time.Duration{5 * time.Hour, -5 * time.Hour} {
		r := newRig()
		kind := SyncedNTS
		g := r.guard(t, syncAs(&kind))
		g.Check(bg)
		kind = SyncedPlain
		r.advance(20 * time.Minute)
		truth := r.wall
		step := 4 * time.Minute
		if skew < 0 {
			step = -step
		}
		r.step(step)
		r.setCarrier(truth.Add(skew))
		lo, hi, s := g.Interval(bg)
		if !s.Authenticated {
			t.Fatalf("skew %v: status = %+v", skew, s)
		}
		allow := DefaultTolerance + 20*time.Minute/ntsDrift
		if skew > 0 {
			wantSpan(t, "carrier ahead", lo, hi, r.wall, truth.Add(allow))
		} else {
			wantSpan(t, "carrier behind", lo, hi, truth.Add(-allow), r.wall)
		}
	}
}

func TestTIM1NTSBoundDiesWithItsBoot(t *testing.T) {
	// Lens B2 on #5893: a saved NTS sync read against a later boot's clock
	// falls short of true time by the earlier boot's uptime and the
	// downtime. A box clock set back to agree with that stale reference (the
	// hardware clock across a power cut) is not authenticated, and an honest
	// carrier widens the interval fully.
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	kind := SyncedNTS
	edit := func(c *Config) {
		syncAs(&kind)(c)
		c.StatePath = path
		c.BootID = func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.boot }
	}
	g := r.guard(t, edit)
	stale := r.wall
	if s := g.Check(bg); !s.Authenticated {
		t.Fatalf("status = %+v", s)
	}
	kind = NotSynced
	r.advance(2 * time.Hour)
	g.Check(bg)
	truth := r.wall.Add(time.Hour) // an hour powered off
	r.reboot(stale)
	r.setCarrier(truth)
	g = r.guard(t, edit)
	lo, hi, s := g.Interval(bg)
	if s.State != Disagree || s.Authenticated {
		t.Fatalf("after reboot: status = %+v", s)
	}
	wantSpan(t, "after reboot", lo, hi, stale, truth)
}

func TestTIM1NTSBoundEndsWhenTheBoxClockLeavesIt(t *testing.T) {
	// A box clock stepped past the allowance from the NTS sync carried
	// forward is no longer authenticated time: the bound lapses, the carrier
	// widens the interval fully and the owner hears DisagreeText (R1).
	allow := DefaultTolerance + 20*time.Minute/ntsDrift
	for _, d := range []time.Duration{allow, -allow, allow + 1, -allow - 1} {
		r := newRig()
		kind := SyncedNTS
		g := r.guard(t, syncAs(&kind))
		g.Check(bg)
		kind = SyncedPlain
		r.advance(20 * time.Minute)
		truth := r.wall
		r.step(d)
		r.setCarrier(truth.Add(5 * time.Hour))
		s := g.Check(bg)
		inside := d == allow || d == -allow
		if s.State != Disagree || s.Authenticated != inside {
			t.Fatalf("step %v: status = %+v", d, s)
		}
		g.Flush()
		want := OutlierText(s.Skew)
		if !inside {
			want = DisagreeText(s.Skew)
			if _, hi, _ := g.Interval(bg); !hi.Equal(truth.Add(5 * time.Hour)) {
				t.Fatalf("step %v: Latest %v, want the carrier's", d, hi)
			}
		}
		if got := r.sent(); len(got) != 1 || got[0] != want {
			t.Fatalf("step %v: texts = %q, want %q", d, got, want)
		}
	}
}

func TestTIM1NTSBoundSurvivesARestartNotAReboot(t *testing.T) {
	// The sync is kept in StatePath for the boot that made it, like the
	// anchor: a broker restart keeps the bound; a reboot, whose boot clock
	// starts again, drops it, so the forged carrier widens fully and the
	// owner told "Nothing to do" hears DisagreeText (R1).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	kind := SyncedNTS
	edit := func(c *Config) {
		syncAs(&kind)(c)
		c.StatePath = path
		c.BootID = func() string { r.mu.Lock(); defer r.mu.Unlock(); return r.boot }
	}
	g := r.guard(t, edit)
	floor := r.wall // the last verified time, which bounds the next boot's Earliest (HW-8)
	g.Check(bg)
	kind = NotSynced
	r.advance(time.Hour)
	r.setCarrier(r.wall.Add(5 * time.Hour))
	if s := g.Check(bg); !s.Authenticated {
		t.Fatalf("status = %+v", s)
	}
	r.advance(time.Minute)
	g = r.guard(t, edit)
	lo, hi, s := g.Interval(bg)
	if !s.Authenticated {
		t.Fatalf("after restart: status = %+v", s)
	}
	wantSpan(t, "after restart", lo, hi, r.wall, r.wall.Add(DefaultTolerance+61*time.Minute/ntsDrift))
	r.reboot(r.wall)
	r.setCarrier(r.wall.Add(5 * time.Hour))
	g = r.guard(t, edit)
	lo, hi, s = g.Interval(bg)
	if s.State != Disagree || s.Authenticated {
		t.Fatalf("after reboot: status = %+v", s)
	}
	wantSpan(t, "after reboot", lo, hi, floor, r.wall.Add(5*time.Hour))
	g.Flush()
	if got := r.sent(); len(got) != 2 || got[1] != DisagreeText(s.Skew) {
		t.Fatalf("texts = %q", got)
	}
}

func TestTIM1OutlierAtTheToleranceEdges(t *testing.T) {
	// Under NTS a carrier exactly the tolerance off agrees; one second
	// further, on either side, is an outlier the NTS bound clamps.
	for _, off := range []time.Duration{DefaultTolerance, -DefaultTolerance, DefaultTolerance + time.Second, -DefaultTolerance - time.Second} {
		r := newRig()
		r.carrier = r.carrier.Add(off)
		g := r.guard(t, nts)
		s := g.Check(bg)
		past := off > DefaultTolerance || off < -DefaultTolerance
		if s.State == Disagree != past || !s.Authenticated {
			t.Fatalf("carrier %v off: status = %+v", off, s)
		}
		g.Flush()
		if got := r.sent(); past != (len(got) == 1 && got[0] == OutlierText(s.Skew)) || !past && len(got) != 0 {
			t.Fatalf("carrier %v off: texts = %q", off, got)
		}
	}
}

func TestTIM1OutlierTextNamesTheSkew(t *testing.T) {
	// OutlierText rounds the skew to its unit at each unit's start.
	for skew, want := range map[time.Duration]string{
		30 * time.Minute:  "by about 30 minutes,",
		-90 * time.Minute: "by about 1 hour,",
		time.Hour:         "by about 1 hour,",
		2 * time.Hour:     "by about 2 hours,",
		-5 * time.Hour:    "by about 5 hours,",
	} {
		if got := OutlierText(skew); !strings.Contains(got, want) {
			t.Fatalf("skew %v: %q, want %q", skew, got, want)
		}
	}
}

func TestTIM1NoStatePathWritesNothing(t *testing.T) {
	// With no StatePath the guard keeps its state in memory only: no save
	// is tried, so none fails.
	r := newRig()
	r.carrier = r.carrier.Add(5 * time.Hour)
	var logs []string
	g := r.guard(t, func(c *Config) {
		nts(c)
		c.Logf = func(f string, a ...any) { logs = append(logs, f) }
	})
	g.Check(bg)
	r.advance(time.Hour)
	g.Check(bg)
	if len(logs) != 0 {
		t.Fatalf("logs = %q", logs)
	}
}
