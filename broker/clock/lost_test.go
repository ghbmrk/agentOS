package clock

// REQ: TIM-1, KEY-8

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lostGuard starts a guard on an unreadable state file with no modem time.
func lostGuard(t *testing.T, r *rig, mod func(*Config)) (*Guard, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "clock.json")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	return r.guard(t, func(c *Config) {
		c.StatePath = path
		if mod != nil {
			mod(c)
		}
	}), path
}

func TestTIM1LostStateWaitsUntilCarrierTimeIsRead(t *testing.T) {
	// TIM-1-interval-fu-d (#5752): the box clock runs hours fast, the state
	// file that held the disagreement is lost, and the modem is absent. The
	// width is unknown, so no widening (a hold, soak or default on timeout)
	// may end on the box clock alone; a narrowing still fires by it.
	r := noCarrier()
	r.wall = r.wall.Add(5 * time.Hour) // box fast; nothing can show it
	g, _ := lostGuard(t, r, nil)
	lo, hi, s := g.Interval(bg)
	if s.State != Disagree || s.Skew != 0 {
		t.Fatalf("status = %+v, want the lost disagreement", s)
	}
	if !lo.IsZero() {
		t.Fatalf("Earliest = %v, want none (widenings wait for carrier time)", lo)
	}
	if !hi.Equal(r.wall) {
		t.Fatalf("Latest = %v, want the box clock %v", hi, r.wall)
	}
	if e, _ := g.Earliest(bg); !e.IsZero() {
		t.Fatalf("Earliest() = %v", e)
	}
	// Still none hours later, with no carrier time read.
	r.advance(3 * time.Hour)
	g.Check(bg)
	if e, _ := g.Earliest(bg); !e.IsZero() {
		t.Fatalf("3 h on: Earliest = %v", e)
	}
	// Carrier time read: it disagrees by the real skew, and the interval
	// spans both clocks as any disagreement does.
	true5 := r.wall.Add(-5 * time.Hour)
	r.setCarrier(true5)
	s = g.Check(bg)
	lo, hi, _ = g.Interval(bg)
	if s.State != Disagree || s.Skew == 0 || !lo.Equal(true5) || !hi.Equal(r.wall) {
		t.Fatalf("carrier read: %+v, interval [%v, %v]", s, lo, hi)
	}
}

func TestTIM1LostStateEndsWhenCarrierAgrees(t *testing.T) {
	r := noCarrier()
	g, _ := lostGuard(t, r, nil)
	g.Check(bg)
	r.setCarrier(r.wall)
	if s := g.Check(bg); s.State != Agreed {
		t.Fatalf("status = %+v", s)
	}
	if lo, hi, _ := g.Interval(bg); !lo.Equal(r.wall) || !hi.Equal(r.wall) {
		t.Fatalf("interval [%v, %v], want the box clock", lo, hi)
	}
}

func TestTIM1LostStateUnderNTSKeepsNetworkTime(t *testing.T) {
	// Converged NTS outranks carrier time (TIM-1-interval-fu-1), so the
	// lost disagreement widens nothing while it holds; it stays a
	// disagreement until carrier time agrees, and once the NTS bound lapses
	// (#5758) the unknown width returns.
	r := noCarrier()
	kind := SyncedNTS
	g, _ := lostGuard(t, r, syncAs(&kind))
	lo, hi, s := g.Interval(bg)
	if s.State != Disagree || !s.Authenticated || !lo.Equal(r.wall) || !hi.Equal(r.wall) {
		t.Fatalf("NTS: %+v, interval [%v, %v]", s, lo, hi)
	}
	kind = SyncedPlain
	r.advance(20 * time.Minute)
	if s = g.Check(bg); !s.Authenticated {
		t.Fatalf("NTS lapsed: %+v, want the NTS bound kept", s)
	}
	r.step(10 * time.Minute)
	s = g.Check(bg)
	if lo, _, _ := g.Interval(bg); s.State != Disagree || !lo.IsZero() {
		t.Fatalf("NTS lapsed: %+v, Earliest %v", s, lo)
	}
}

func TestTIM1LostStateWidthSurvivesARestart(t *testing.T) {
	// The first check saves the disagreement with no skew: a restart in
	// the same boot, or a later boot, still has no carrier reading and
	// must not narrow back to the box clock.
	r := noCarrier()
	g, path := lostGuard(t, r, nil)
	g.Check(bg)
	g.Flush()
	r.advance(time.Minute)
	g2 := r.guard(t, func(c *Config) { c.StatePath = path })
	if lo, _, s := g2.Interval(bg); s.State != Disagree || !lo.IsZero() {
		t.Fatalf("restart: %+v, Earliest %v", s, lo)
	}
	r.reboot(r.wall)
	g3 := r.guard(t, func(c *Config) { c.StatePath = path })
	if lo, _, s := g3.Interval(bg); s.State != Disagree || !lo.IsZero() {
		t.Fatalf("reboot: %+v, Earliest %v", s, lo)
	}
	if n := len(r.sent()); n != 1 {
		t.Fatalf("texts = %q, want the one StateLostText", r.sent())
	}
}

func TestTIM1LostStateLinesSayWhatWaits(t *testing.T) {
	// UX item 4 on #5754: the text and STATUS name what is held and what
	// lifts it, and an authenticated lost check is never "restricted".
	since := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	zone := time.FixedZone("x", 2*3600)
	plain := Status{State: Disagree, Since: since}
	if got := plain.IntervalLine(zone); got != "Time check: saved check unreadable since 06:00, so holds and timeouts wait until phone-network time confirms the clock." {
		t.Fatalf("plain line = %q", got)
	}
	auth := Status{State: Disagree, Since: since, Authenticated: true, Verified: true}
	if got := auth.IntervalLine(zone); got != "Time check: saved check unreadable since 06:00; authenticated network time stands until phone-network time confirms it." {
		t.Fatalf("authenticated line = %q", got)
	}
	if got := auth.Line(zone); got != auth.IntervalLine(zone) {
		t.Fatalf("Line = %q, want the interval line beside an answering Now", got)
	}
	for _, want := range []string{"waiting for time to pass", "authenticated network time", "phone network's time", "Codes and STOP work as usual."} {
		if !strings.Contains(StateLostText, want) {
			t.Errorf("StateLostText lacks %q: %q", want, StateLostText)
		}
	}
}

func TestTIM1PartlyDecodedStateFileLoadsAsLost(t *testing.T) {
	// json.Unmarshal fills the fields before a mistyped one and still fails:
	// none of them is trusted. The file loads as the lost disagreement, not
	// its skew, start or floor (Security F1 on #5810).
	r := noCarrier()
	path := filepath.Join(t.TempDir(), "clock.json")
	future := r.wall.Add(48 * time.Hour)
	raw := fmt.Sprintf(`{"restricted":true,"skew":%d,"since":%q,"floor":%q,"anchored":"yes"}`,
		int64(2*time.Hour), r.wall.Add(-time.Hour).Format(time.RFC3339), future.Format(time.RFC3339))
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	g := r.guard(t, func(c *Config) { c.StatePath = path })
	if s := g.Status(); s.State != Disagree || s.Skew != 0 || !s.Since.IsZero() {
		t.Fatalf("status = %+v, want the lost disagreement (skew 0, no start)", s)
	}
	if _, hi, _ := g.Interval(bg); hi.Equal(future) {
		t.Fatalf("Latest = %v: the partly decoded floor was applied", hi)
	}
}
