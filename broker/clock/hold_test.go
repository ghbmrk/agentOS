package clock

// REQ: TIM-1

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// noCarrier is a rig whose network never sends time (security C1 on #68).
func noCarrier() *rig {
	r := newRig()
	r.carrier = time.Time{}
	return r
}

func TestTIM1StepWithNoCarrierIsHeld(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("first synced check: %+v", s)
	}
	t0 := r.wall
	r.advance(time.Minute)
	r.step(-24 * time.Hour) // spoofed NTP step, nothing to cross-check
	now, err := g.Now(bg)
	if err != nil {
		t.Fatal(err)
	}
	if want := t0.Add(time.Minute); !now.Equal(want) {
		t.Fatalf("Now = %v, want the held %v", now, want)
	}
	s := g.Status()
	if s.State != Held || s.Restricted() || s.Skew != -24*time.Hour {
		t.Fatalf("status = %+v", s)
	}
	if latest, _ := g.Latest(bg); !latest.Equal(t0.Add(time.Minute)) {
		t.Fatalf("Latest = %v", latest)
	}
	if len(r.texts) != 1 || !strings.Contains(r.texts[0], "jumped by about 1 day") {
		t.Fatalf("texts = %q", r.texts)
	}
	if !strings.Contains(s.Line(time.UTC), "held since") {
		t.Fatalf("line = %q", s.Line(time.UTC))
	}
	// Held time keeps counting on the monotonic clock.
	r.advance(time.Hour)
	if now, _ := g.Now(bg); !now.Equal(t0.Add(61 * time.Minute)) {
		t.Fatalf("Now = %v", now)
	}
	if len(r.texts) != 1 {
		t.Fatalf("texts = %q", r.texts)
	}
}

func TestTIM1SmallStepsThatAddUpAreHeld(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	t0 := r.wall
	// 4 minutes every 15: each step is under the tolerance against the last
	// check, but they add up against the anchor.
	var last time.Time
	for i := 0; i < 4; i++ {
		r.advance(DefaultInterval)
		r.step(4 * time.Minute)
		var err error
		if last, err = g.Now(bg); err != nil {
			t.Fatal(err)
		}
	}
	if want := t0.Add(4 * DefaultInterval); !last.Equal(want) {
		t.Fatalf("Now = %v, want held %v (box clock %v)", last, want, r.wall)
	}
	if s := g.Status(); s.State != Held {
		t.Fatalf("status = %+v", s)
	}
}

func TestTIM1HonestSlewIsNotHeld(t *testing.T) {
	// NTP slews at most 500 ppm: 43 s a day. Over ten days that passes the
	// 5-minute tolerance but stays inside the slew allowance.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	for d := 0; d < 10; d++ {
		r.advance(24 * time.Hour)
		r.step(43 * time.Second)
		if s := g.Check(bg); s.State != NetworkOnly {
			t.Fatalf("day %d: %+v", d, s)
		}
	}
}

func TestTIM1AgreeingCarrierReanchors(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	r.step(3 * time.Hour) // NTP step, unconfirmed
	if s := g.Check(bg); s.State != Held {
		t.Fatalf("status = %+v", s)
	}
	// The carrier comes up and agrees with the stepped clock: it was right.
	r.mu.Lock()
	r.carrier = r.wall
	r.mu.Unlock()
	if s := g.Check(bg); s.State != Agreed {
		t.Fatalf("status = %+v", s)
	}
	if now, err := g.Now(bg); err != nil || !now.Equal(r.wall) {
		t.Fatalf("Now = %v, %v", now, err)
	}
	r.advance(AgreeAfter)
	g.Check(bg)
	if len(r.texts) != 2 || r.texts[1] != AgreeText {
		t.Fatalf("texts = %q", r.texts)
	}
}

func TestTIM1HeldThenCarrierDisagreesEscalates(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	t0 := r.wall
	r.step(3 * time.Hour)
	g.Check(bg)
	r.mu.Lock()
	r.carrier = t0 // the carrier sides with the anchor
	r.mu.Unlock()
	g.Check(bg)
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("err = %v", err)
	}
	if len(r.texts) != 2 || !strings.Contains(r.texts[1], "playing safe") {
		t.Fatalf("texts = %q", r.texts)
	}
}

func TestTIM1AllClearsAreCapped(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	g.Check(bg)
	for i := 0; i < 10; i++ {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	clears := 0
	for _, x := range r.texts {
		if x == AgreeText {
			clears++
		}
	}
	if clears != MaxAllClearsPerDay || len(r.texts) != 2*MaxAllClearsPerDay+1 {
		t.Fatalf("texts = %d (%d all-clears)", len(r.texts), clears)
	}
	// The owner's last word is the disagreement, never a stale all-clear.
	if last := r.texts[len(r.texts)-1]; last == AgreeText {
		t.Fatalf("last text = %q", last)
	}
}

func TestTIM1RestrictionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	r.carrier = r.carrier.Add(2 * time.Hour)
	g := r.guard(t, func(c *Config) { c.StatePath = path })
	g.Check(bg)
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	// Restart with no carrier time: still restricted, and no new text.
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	g = r.guard(t, func(c *Config) { c.StatePath = path })
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("after restart: %v", err)
	}
	if len(r.texts) != 1 {
		t.Fatalf("texts = %q", r.texts)
	}
	// Only agreeing carrier time lifts it.
	r.mu.Lock()
	r.carrier = r.wall
	r.mu.Unlock()
	if s := g.Check(bg); s.State != Agreed {
		t.Fatalf("status = %+v", s)
	}
	g = r.guard(t, func(c *Config) { c.StatePath = path })
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	if _, err := g.Now(bg); err != nil {
		t.Fatalf("after lifting and restart: %v", err)
	}
}

func TestTIM1UnreadableStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := noCarrier()
	g := r.guard(t, func(c *Config) { c.StatePath = path })
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("err = %v", err)
	}
}

func TestTIM1AnchorSurvivesRestartWithinBoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := noCarrier()
	boot := "boot-a"
	mod := func(c *Config) { c.StatePath = path; c.BootID = func() string { return boot } }
	g := r.guard(t, mod)
	g.Check(bg)
	t0 := r.wall
	// The broker restarts after a spoofed step: the anchor from before
	// still holds the clock.
	r.step(-6 * time.Hour)
	g = r.guard(t, mod)
	if now, err := g.Now(bg); err != nil || !now.Equal(t0) {
		t.Fatalf("Now = %v, %v; want held %v", now, err, t0)
	}
	// After a reboot the old anchor means nothing; the first synced check
	// anchors afresh.
	boot = "boot-b"
	g = r.guard(t, mod)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("new boot: %+v", s)
	}
}
