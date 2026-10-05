package clock

// REQ: TIM-1

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if len(r.sent()) != 1 || !strings.Contains(r.sent()[0], "jumped by about 1 day") {
		t.Fatalf("texts = %q", r.sent())
	}
	if !strings.Contains(s.Line(time.UTC), "held since") {
		t.Fatalf("line = %q", s.Line(time.UTC))
	}
	// Held time keeps counting on the monotonic clock.
	r.advance(time.Hour)
	if now, _ := g.Now(bg); !now.Equal(t0.Add(61 * time.Minute)) {
		t.Fatalf("Now = %v", now)
	}
	if len(r.sent()) != 1 {
		t.Fatalf("texts = %q", r.sent())
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

func TestTIM1StepsLongAfterTheAnchorAreHeld(t *testing.T) {
	// NTP slewing moves the wall and boot clocks together, so time since
	// the anchor buys no allowance (L3 F6): 30 days on, steps that sum past
	// the tolerance are still held.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	r.advance(30 * 24 * time.Hour)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("30 days on, no step: %+v", s)
	}
	r.step(3 * time.Minute)
	g.Check(bg)
	r.step(3 * time.Minute)
	if s := g.Check(bg); s.State != Held {
		t.Fatalf("status = %+v, want held", s)
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
	if len(r.sent()) != 2 || r.sent()[1] != AgreeText {
		t.Fatalf("texts = %q", r.sent())
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
	if len(r.sent()) != 2 || !strings.Contains(r.sent()[1], "playing safe") {
		t.Fatalf("texts = %q", r.sent())
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
			r.mu.Lock()
			log = append(log, fmt.Sprintf("%s@%v", kind, r.mono))
			r.mu.Unlock()
		}
	})
	chk := func() { g.Check(bg); g.Flush() } // label each text with its check's time
	chk()
	for elapsed := time.Duration(0); elapsed < 25*time.Hour; elapsed += 3 * time.Hour {
		r.mu.Lock()
		r.carrier = r.wall.Add(3 * time.Hour)
		r.mu.Unlock()
		chk()
		r.advance(105 * time.Minute)
		chk()
		r.mu.Lock()
		r.carrier = r.wall
		r.mu.Unlock()
		chk()
		r.advance(75 * time.Minute)
		chk()
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
	if len(r.sent()) != 1 {
		t.Fatalf("texts = %q", r.sent())
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
	got := make(chan Status)
	go func() { got <- g.Check(bg) }()
	select {
	case st := <-got:
		if !st.Restricted() {
			t.Fatalf("status = %+v", st)
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
	for _, x := range r.sent() {
		if x != AgreeText && x != AgreeLastText {
			alerts++
		}
	}
	if alerts != MaxAlertsPerDay || r.sent()[len(r.sent())-1] != AgreeLastText {
		t.Fatalf("texts = %q", r.sent())
	}
	// After a reboot, the earlier boot's alerts still count by their age.
	mod2 := func(c *Config) { c.StatePath = path; c.BootID = func() string { return "boot-b" } }
	g = r.guard(t, mod2)
	n := len(r.sent())
	r.step(time.Hour)
	g.Check(bg)
	if len(r.sent()) != n {
		t.Fatalf("alert after reboot within the day: %q", r.sent()[n:])
	}
}

func TestTIM1JoinedCallersDoNotWaitForTexts(t *testing.T) {
	// Callers that joined a check get its result when it is published, not
	// after its owner text has gone out (L3 D3, F7).
	r := newRig()
	r.carrier = r.carrier.Add(time.Hour)
	release, slow := make(chan struct{}), make(chan struct{})
	g := r.guard(t, func(c *Config) {
		c.Carrier = func(context.Context) (time.Time, error) {
			<-release
			r.mu.Lock()
			defer r.mu.Unlock()
			return r.carrier, nil
		}
		c.Notify = func(string) { <-slow }
	})
	defer close(slow)
	go g.Check(bg) // the leader, which will send the text
	time.Sleep(10 * time.Millisecond)
	joined := make(chan Status)
	go func() { joined <- g.Check(bg) }()
	time.Sleep(10 * time.Millisecond)
	close(release)
	select {
	case s := <-joined:
		if !s.Restricted() {
			t.Fatalf("status = %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a joined caller waited on the owner text")
	}
}

func TestTIM1EarliestForMinimumAges(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	g.Check(bg)
	r.advance(10 * time.Minute)
	// A clock pushed 3 minutes forward (inside the tolerance) must not end
	// a hold period early: Earliest answers from the carrier reading.
	r.step(3 * time.Minute)
	got, s := g.Earliest(bg)
	if s.Restricted() || !got.Equal(time.Date(2026, 10, 5, 4, 10, 0, 0, time.UTC)) {
		t.Fatalf("Earliest = %v, %+v", got, s)
	}
	if late, _ := g.Latest(bg); !late.Equal(r.wall) {
		t.Fatalf("Latest = %v, want the box clock %v", late, r.wall)
	}
}

func TestTIM1CrossBootAlertAges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	r.mono = 50 * time.Hour // a long first boot
	boot := "boot-a"
	mod := func(c *Config) { c.StatePath = path; c.BootID = func() string { return boot } }
	g := r.guard(t, mod)
	g.Check(bg)
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	alarm()
	alarm() // the cap is used
	n := len(r.sent())
	// Reboot: the boot clock starts again, and the box clock is set two
	// days ahead. Neither frees the cap.
	boot = "boot-b"
	r.mu.Lock()
	r.mono = time.Minute
	r.wall = r.wall.Add(48 * time.Hour)
	r.carrier = r.wall
	r.mu.Unlock()
	g = r.guard(t, mod)
	g.Check(bg)
	alarm()
	if len(r.sent()) != n {
		t.Fatalf("alert after reboot: %q", r.sent()[n:])
	}
	// After a day of uptime the earlier boot's alerts have aged out.
	r.advance(24 * time.Hour)
	g.Check(bg)
	alarm()
	if len(r.sent()) == n {
		t.Fatal("cap never freed after a day of uptime")
	}
}

func TestTIM1TextsAreFIFOAndOnChangeSupersedes(t *testing.T) {
	r := newRig()
	block := make(chan struct{})
	var mu sync.Mutex
	var got []string
	var changes []State
	first := true
	g := r.guard(t, func(c *Config) {
		c.Notify = func(x string) {
			mu.Lock()
			wait := first
			first = false
			got = append(got, x)
			mu.Unlock()
			if wait {
				<-block
			}
		}
		c.OnChange = func(s Status) { mu.Lock(); changes = append(changes, s.State); mu.Unlock() }
	})
	g.Check(bg) // Agreed: OnChange only
	r.step(time.Hour)
	done := make(chan struct{})
	go func() { g.Check(bg); close(done) }() // disagreement text, held up in Notify
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	// While the text is held up, the clock comes right and goes wrong
	// again: two more changes queue behind it.
	r.step(-time.Hour)
	g.Check(bg)
	r.step(2 * time.Hour)
	g.Check(bg)
	close(block)
	<-done
	g.Flush()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "playing safe") {
		t.Fatalf("texts = %q", got)
	}
	// The Agreed in between was superseded before delivery; the last state
	// always arrives.
	if len(changes) == 0 || changes[len(changes)-1] != Disagree {
		t.Fatalf("changes = %v", changes)
	}
	for i, c := range changes {
		if c == Agreed && i > 0 {
			t.Fatalf("superseded change delivered: %v", changes)
		}
	}
}

func TestTIM1HoldEscalatesEvenAtTheCap(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	// Use up the day's alerts with holds that end on their own.
	for i := 0; i < MaxAlertsPerDay; i++ {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	n := len(r.sent())
	r.step(time.Hour)
	g.Check(bg) // a third hold: capped, no text
	if len(r.sent()) != n {
		t.Fatalf("capped hold texted: %q", r.sent()[n:])
	}
	// A hold already texted escalates even with the cap full.
	r2 := noCarrier()
	g2 := r2.guard(t, nil)
	g2.Check(bg)
	t0 := r2.wall
	r2.step(time.Hour)
	g2.Check(bg) // hold text, 1 of 2
	g2.mu.Lock()
	g2.alerts = append(g2.alerts, stamp{Mono: r2.mono}) // the cap is now full
	g2.mu.Unlock()
	r2.mu.Lock()
	r2.carrier = t0
	r2.mu.Unlock()
	g2.Check(bg)
	if len(r2.sent()) != 2 || !strings.Contains(r2.sent()[1], "playing safe") {
		t.Fatalf("escalation at cap: %q", r2.sent())
	}
}

func TestTIM1HoldEndsWithoutCarrierGetsAllClear(t *testing.T) {
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	r.step(time.Hour)
	g.Check(bg)
	r.step(-time.Hour) // the clock comes back in line; still no carrier
	g.Check(bg)
	r.advance(AgreeAfter)
	g.Check(bg)
	if len(r.sent()) != 2 || r.sent()[1] != HoldEndText {
		t.Fatalf("texts = %q", r.sent())
	}
}

func TestTIM1StateLostHasFixedText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clock.json")
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := noCarrier()
	var logged []string
	g := r.guard(t, func(c *Config) {
		c.StatePath = path
		c.Logf = func(f string, a ...any) { logged = append(logged, fmt.Sprintf(f, a...)) }
	})
	g.Check(bg)
	if len(r.sent()) != 1 || r.sent()[0] != StateLostText {
		t.Fatalf("texts = %q", r.sent())
	}
	if line := g.Status().Line(time.UTC); strings.Contains(line, "about 0") {
		t.Fatalf("line = %q", line)
	}
	if len(logged) == 0 {
		t.Fatal("unreadable state not logged")
	}
}

func TestTIM1AgreementReanchors(t *testing.T) {
	// After carrier time confirms a stepped clock, losing the carrier must
	// not hold the box to the old anchor.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	r.step(3 * time.Hour)
	g.Check(bg) // held
	r.mu.Lock()
	r.carrier = r.wall
	r.mu.Unlock()
	g.Check(bg) // agreed: re-anchored
	r.mu.Lock()
	r.carrier = time.Time{}
	r.mu.Unlock()
	r.advance(time.Minute)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("status = %+v", s)
	}
	if now, _ := g.Now(bg); !now.Equal(r.wall) {
		t.Fatalf("Now = %v, want %v", now, r.wall)
	}
}

func TestTIM1DriftFromAnchorChecksWithRunLive(t *testing.T) {
	// With Run live, stale reads do not check; small steps each under the
	// tolerance since the last check are caught only by the drift-from-
	// anchor test in refresh.
	r := noCarrier()
	tick := make(chan time.Time)
	g := r.guard(t, func(c *Config) { c.Tick = tick })
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	go g.Run(ctx)
	for r.readCount() < 1 {
		time.Sleep(time.Millisecond)
	}
	g.Check(bg)
	t0 := r.wall
	r.step(4 * time.Minute)
	if _, err := g.Now(bg); err != nil {
		t.Fatal(err)
	}
	r.step(4 * time.Minute)
	now, err := g.Now(bg)
	if err != nil || !now.Equal(t0) {
		t.Fatalf("Now = %v, %v; want held %v", now, err, t0)
	}
}

func TestTIM1HonestRebootsAgeAlertsOut(t *testing.T) {
	// Honest clocks, a reboot every 10 hours: alerts still age out a day
	// after they were sent (L3 F1, round 3).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	boot := 0
	mod := func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return fmt.Sprint("boot-", boot) }
	}
	g := r.guard(t, mod)
	g.Check(bg)
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	alarm()
	alarm() // cap used at about 2 h
	n := len(r.sent())
	reboot := func(down time.Duration) {
		g.Flush()
		boot++
		r.mu.Lock()
		r.wall = r.wall.Add(down)
		r.carrier = r.wall
		r.mono = 0
		r.mu.Unlock()
		g = r.guard(t, mod)
		g.Check(bg)
	}
	for i := 0; i < 2; i++ { // 2 h + 2×(8 h up + 2 min down) ≈ 18 h
		r.advance(8 * time.Hour)
		g.Check(bg)
		reboot(2 * time.Minute)
	}
	alarm()
	if len(r.sent()) != n {
		t.Fatalf("cap freed early: %q", r.sent()[n:])
	}
	r.advance(8 * time.Hour) // a day since the alerts
	g.Check(bg)
	alarm()
	if len(r.sent()) == n {
		t.Fatal("honest reboots kept the cap full past a day")
	}
}

func TestTIM1HonestRebootsAgeAlertsOutWithoutCarrier(t *testing.T) {
	// No carrier time, a reboot every 10 hours, a check every 15 minutes:
	// hold alerts still age out a day after they were sent, because each
	// check refreshes the saved boot clock while alerts count (L3 F1,
	// round 4).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := noCarrier()
	boot := 0
	mod := func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return fmt.Sprint("boot-", boot) }
	}
	g := r.guard(t, mod)
	g.Check(bg)
	up := func(d time.Duration) {
		for i := time.Duration(0); i < d; i += 15 * time.Minute {
			r.advance(15 * time.Minute)
			g.Check(bg)
		}
	}
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		up(AgreeAfter)
	}
	alarm()
	alarm() // cap used at about 2 h
	n := len(r.sent())
	if n != 2*MaxAlertsPerDay {
		t.Fatalf("texts = %q", r.sent())
	}
	reboot := func() {
		g.Flush()
		boot++
		r.mu.Lock()
		r.wall = r.wall.Add(2 * time.Minute)
		r.mono = 0
		r.mu.Unlock()
		g = r.guard(t, mod)
		g.Check(bg)
	}
	up(8 * time.Hour)
	reboot()
	up(10 * time.Hour)
	reboot() // about 20 h since the alerts
	alarm()
	if len(r.sent()) != n {
		t.Fatalf("cap freed early: %q", r.sent()[n:])
	}
	up(6 * time.Hour) // a day since the alerts
	alarm()
	if len(r.sent()) == n {
		t.Fatal("honest reboots without carrier kept the cap full past a day")
	}
}

func TestTIM1ImplausibleSavedBootClockKeepsTheCap(t *testing.T) {
	// A state file whose saved boot clock puts an alert more than a day
	// before the save is corrupt (alerts that old are pruned before every
	// save): its alerts count as just sent, so the cap is not freed
	// (security R1 on #68).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	boot := "boot-a"
	mod := func(c *Config) { c.StatePath = path; c.BootID = func() string { return boot } }
	g := r.guard(t, mod)
	g.Check(bg)
	alarm := func() {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(AgreeAfter)
		g.Check(bg)
	}
	alarm()
	alarm()
	g.Flush()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	v["saved_mono"] = int64(1000 * time.Hour)
	if b, err = json.Marshal(v); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	boot = "boot-b"
	r.mu.Lock()
	r.mono = 0
	r.mu.Unlock()
	g = r.guard(t, mod)
	g.Check(bg)
	n := len(r.sent())
	alarm()
	if len(r.sent()) != n {
		t.Fatalf("corrupt saved boot clock freed the cap: %q", r.sent()[n:])
	}
}

func TestTIM1QueuedTextsAreNeverSuperseded(t *testing.T) {
	// A hold text stuck in Notify, then an escalation, then agreement: both
	// alerts reach the owner (L3 F7, round 3).
	r := noCarrier()
	block := make(chan struct{})
	var mu sync.Mutex
	var got []string
	g := r.guard(t, func(c *Config) {
		c.Notify = func(x string) {
			mu.Lock()
			first := len(got) == 0
			got = append(got, x)
			mu.Unlock()
			if first {
				<-block
			}
		}
	})
	g.Check(bg)
	t0 := r.wall
	r.step(time.Hour)
	g.Check(bg) // hold text, stuck
	r.mu.Lock()
	r.carrier = t0
	r.mu.Unlock()
	g.Check(bg) // escalation text, queued
	r.step(-time.Hour)
	g.Check(bg) // agreed: a state change after both
	close(block)
	g.Flush()
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 2 || !strings.Contains(got[0], "jumped") || !strings.Contains(got[1], "playing safe") {
		t.Fatalf("texts = %q", got)
	}
}

func TestTIM1HungNotifierHoldsNoCaller(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(time.Hour)
	hung := make(chan struct{})
	defer close(hung)
	g := r.guard(t, func(c *Config) { c.Notify = func(string) { <-hung } })
	done := make(chan Status)
	go func() { done <- g.Check(bg) }()
	select {
	case s := <-done:
		if !s.Restricted() {
			t.Fatalf("status = %+v", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the checking caller waited on a hung notifier")
	}
}

func TestTIM1NotifierPanicIsContained(t *testing.T) {
	r := newRig()
	var logged []string
	var lmu sync.Mutex
	calls := 0
	g := r.guard(t, func(c *Config) {
		c.Notify = func(string) {
			calls++
			if calls == 1 {
				panic("sms down")
			}
		}
		c.Logf = func(f string, a ...any) { lmu.Lock(); logged = append(logged, fmt.Sprintf(f, a...)); lmu.Unlock() }
	})
	g.Check(bg)
	r.step(time.Hour)
	g.Check(bg) // panics in Notify
	r.step(-time.Hour)
	g.Check(bg)
	r.advance(AgreeAfter)
	g.Check(bg) // the all-clear still goes
	g.Flush()
	lmu.Lock()
	defer lmu.Unlock()
	if calls != 2 || len(logged) != 1 {
		t.Fatalf("calls %d, logged %q", calls, logged)
	}
}
