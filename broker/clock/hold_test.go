package clock

// REQ: TIM-1

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

func TestTIM1OwnerTextsAreCappedAgainstAFakeCell(t *testing.T) {
	// A fake cell 3 h wrong, then right for 75 minutes, over and over
	// (L3 D4): at most MaxAlertsPerDay alerts in any 24 hours, each with
	// its all-clear; the one that uses up the day says so.
	r := newRig()
	var log []string
	g := r.guard(t, func(c *Config) {
		c.Notify = func(s string) {
			kind := "alert"
			switch s {
			case AgreeText:
				kind = "clear"
			case AgreeLastText:
				kind = "last-clear"
			}
			log = append(log, fmt.Sprintf("%s@%v", kind, r.mono))
		}
	})
	g.Check(bg)
	for elapsed := time.Duration(0); elapsed < 25*time.Hour; elapsed += 3 * time.Hour {
		r.mu.Lock()
		r.carrier = r.wall.Add(3 * time.Hour)
		r.mu.Unlock()
		g.Check(bg)
		r.advance(105 * time.Minute)
		g.Check(bg)
		r.mu.Lock()
		r.carrier = r.wall
		r.mu.Unlock()
		g.Check(bg)
		r.advance(75 * time.Minute)
		g.Check(bg)
	}
	want := []string{"alert@0s", "clear@3h0m0s", "alert@3h0m0s", "last-clear@6h0m0s", "alert@24h0m0s", "clear@27h0m0s"}
	if fmt.Sprint(log) != fmt.Sprint(want) {
		t.Fatalf("texts = %v, want %v", log, want)
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

func TestTIM1WallStepsAreSeenWithRealTime(t *testing.T) {
	// time.Now carries a monotonic reading, and Sub between two such times
	// ignores the wall clock (L3 D1). The guard strips it, so a wall step
	// is visible however Now is supplied.
	var offset atomic.Int64
	g, err := New(Config{
		Synced:  func() (bool, error) { return true, nil },
		Carrier: func(context.Context) (time.Time, error) { return time.Now(), nil },
		Now:     func() time.Time { return time.Now() },
		Elapsed: func() time.Duration { return time.Duration(offset.Load()) },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.Check(bg)
	if at := g.Status().At; strings.Contains(at.String(), "m=") {
		t.Fatalf("status time keeps a monotonic reading: %v", at)
	}
	// Elapsed stands still for an hour of wall time: a wall step of an hour.
	g.cfg.Now = func() time.Time { return time.Now().Round(0).Add(time.Hour) }
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("err = %v", err)
	}
}

func TestTIM1CallerDeadlineDoesNotPoisonSharedCheck(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(time.Hour)
	release := make(chan struct{})
	g := r.guard(t, func(c *Config) {
		c.Carrier = func(ctx context.Context) (time.Time, error) {
			select {
			case <-release:
			case <-ctx.Done():
				return time.Time{}, ctx.Err()
			}
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.carrier, nil
		}
	})
	short, cancel := context.WithTimeout(bg, 5*time.Millisecond)
	defer cancel()
	done := make(chan Status)
	go func() { done <- g.Check(short) }()
	time.Sleep(20 * time.Millisecond) // the leader's deadline has passed
	joined := make(chan Status)
	go func() { joined <- g.Check(bg) }()
	time.Sleep(5 * time.Millisecond)
	close(release)
	if s := <-done; s.State != Disagree {
		t.Fatalf("leader: %+v", s)
	}
	if s := <-joined; s.State != Disagree {
		t.Fatalf("joined: %+v", s)
	}
}

func TestTIM1NotifyMayCheckAgain(t *testing.T) {
	// A notifier that reads the guard (a lapse sweep, say) must not
	// deadlock, and a slow one must not hold other callers (L3 D3).
	r := newRig()
	r.carrier = r.carrier.Add(time.Hour)
	var g *Guard
	slow := make(chan struct{})
	g = r.guard(t, func(c *Config) {
		c.Notify = func(string) {
			_, _ = g.Now(bg)
			<-slow
		}
		c.OnChange = func(Status) { g.Check(bg) }
	})
	go g.Check(bg)
	time.Sleep(20 * time.Millisecond)
	got := make(chan error)
	go func() { _, err := g.Now(bg); got <- err }()
	select {
	case err := <-got:
		if !errors.Is(err, ErrRestricted) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a caller waited on the slow notifier")
	}
	close(slow)
}

func TestTIM1AlertCapSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	mod := func(c *Config) { c.StatePath = path; c.BootID = func() string { return "boot-a" } }
	g := r.guard(t, mod)
	g.Check(bg)
	cycle := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	cycle()
	g = r.guard(t, mod) // restart
	cycle()
	g = r.guard(t, mod)
	cycle() // the cap is used up: no alert, so no all-clear either
	alerts := 0
	for _, x := range r.texts {
		if x != AgreeText && x != AgreeLastText {
			alerts++
		}
	}
	if alerts != MaxAlertsPerDay || r.texts[len(r.texts)-1] != AgreeLastText {
		t.Fatalf("texts = %q", r.texts)
	}
	// After a reboot, the earlier boot's alerts still count by their age.
	mod2 := func(c *Config) { c.StatePath = path; c.BootID = func() string { return "boot-b" } }
	g = r.guard(t, mod2)
	n := len(r.texts)
	r.step(time.Hour)
	g.Check(bg)
	if len(r.texts) != n {
		t.Fatalf("alert after reboot within the day: %q", r.texts[n:])
	}
}
