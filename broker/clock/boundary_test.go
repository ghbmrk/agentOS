package clock

// REQ: TIM-1, HW-8

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTIM1AboutRoundsAtEachUnitsStart(t *testing.T) {
	for d, want := range map[time.Duration]string{
		48 * time.Hour:   "about 2 days",
		2 * time.Hour:    "about 2 hours",
		30 * time.Minute: "about 30 minutes",
		time.Hour:        "about 1 hour",
		-time.Hour:       "about 1 hour",
	} {
		if got := about(d); got != want {
			t.Errorf("about(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTIM1SkewOfExactlyTheToleranceAgrees(t *testing.T) {
	for _, skew := range []time.Duration{DefaultTolerance, -DefaultTolerance} {
		r := newRig()
		r.carrier = r.wall.Add(-skew)
		if s := r.guard(t, nil).Check(bg); s.State != Agreed {
			t.Errorf("skew %v: status = %+v, want agreed", skew, s)
		}
	}
	// One second past the tolerance disagrees on either sign.
	for _, skew := range []time.Duration{DefaultTolerance + time.Second, -DefaultTolerance - time.Second} {
		r := newRig()
		r.carrier = r.wall.Add(-skew)
		if s := r.guard(t, nil).Check(bg); s.State != Disagree {
			t.Errorf("skew %v: status = %+v, want disagree", skew, s)
		}
	}
}

func TestHW8FloorAheadByExactlyTheToleranceIsKept(t *testing.T) {
	// The floor is replaced only when it is more than the tolerance ahead
	// of NTS-verified time (security R1 on #177).
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	rtcGuard(t, r, path, &rtc).Check(bg)
	v := readSaved(t, path)
	ahead := r.wall.Add(DefaultTolerance)
	v.Floor = ahead
	if b, err := json.Marshal(v); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs []string
	r.reboot(r.wall)
	g := r.guard(t, func(c *Config) {
		c.StatePath = path
		c.BootID = func() string { return r.boot }
		c.Logf = func(f string, a ...any) { logs = append(logs, f) }
		nts(c)
	})
	g.Check(bg)
	if got := readSaved(t, path).Floor; !got.Equal(ahead) || len(logs) != 0 {
		t.Fatalf("floor %v, want %v kept; logs %q", got, ahead, logs)
	}
}

func TestTIM1SmallSkewIsNotZoneLike(t *testing.T) {
	// Under 14 minutes is never a time-zone shape, even within a minute of
	// a whole quarter hour (zero).
	for _, d := range []time.Duration{30 * time.Second, -30 * time.Second, 13 * time.Minute} {
		if zoneLike(d) {
			t.Errorf("zoneLike(%v) = true", d)
		}
	}
	if !zoneLike(time.Hour) {
		t.Error("zoneLike(1h) = false")
	}
}

func TestTIM1NewFillsTheClockDefaults(t *testing.T) {
	// Only Synced given: New supplies the box and boot clocks.
	before := time.Now().Round(0)
	g, err := New(Config{Synced: func() (bool, error) { return true, nil }})
	if err != nil {
		t.Fatal(err)
	}
	s := g.Check(bg)
	if s.At.Before(before) || s.At.After(time.Now().Add(time.Second)) {
		t.Fatalf("At = %v, want the system clock near %v", s.At, before)
	}
}

func TestTIM1CheckCancelsTheCarrierContext(t *testing.T) {
	// The carrier read's timeout context is released once the read returns.
	r := newRig()
	var got context.Context
	g := r.guard(t, func(c *Config) {
		c.Carrier = func(ctx context.Context) (time.Time, error) { got = ctx; return r.wall, nil }
	})
	g.Check(bg)
	if got == nil || !errors.Is(got.Err(), context.Canceled) {
		t.Fatalf("carrier context after Check: %v", got)
	}
}

func TestTIM1NowIsReadAfterTheCheck(t *testing.T) {
	// A modem that takes a while to answer: the time returned is the box
	// clock after the check, not before it.
	r := noCarrier()
	g := r.guard(t, func(c *Config) {
		c.Carrier = func(context.Context) (time.Time, error) {
			r.advance(10 * time.Second)
			return time.Time{}, ErrNoNetworkTime
		}
	})
	now, err := g.Now(bg)
	if err != nil || !now.Equal(r.wall) {
		t.Fatalf("Now = %v, %v; want %v", now, err, r.wall)
	}
}

func TestTIM1CarrierNeverReadLeavesTheBoxClock(t *testing.T) {
	// With no carrier time ever read, the interval is the box clock alone,
	// however long the boot has run.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	r.advance(time.Hour)
	if lo, hi, _ := g.Interval(bg); !lo.Equal(r.wall) || !hi.Equal(r.wall) {
		t.Fatalf("interval [%v, %v], want both %v", lo, hi, r.wall)
	}
}

func TestTIM1DriftSinceTheAnchorChecksWithinOneTolerance(t *testing.T) {
	// Two steps, each under the tolerance and checked between: the second
	// jump since the last check is under the tolerance, but the drift from
	// the anchor is not, so refresh checks and the clock is held.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	t0 := r.wall
	r.step(4 * time.Minute)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("after 4 min: %+v", s)
	}
	r.step(4 * time.Minute)
	if now, err := g.Now(bg); err != nil || !now.Equal(t0) {
		t.Fatalf("Now = %v, %v; want held %v", now, err, t0)
	}
}

func TestTIM1NoticesAreNeverDeliveredConcurrently(t *testing.T) {
	// A notifier that checks again queues the next notice; it is delivered
	// only after this one returns, never beside it (L3 F2 on #68).
	r := newRig()
	r.carrier = r.wall.Add(time.Hour)
	var g *Guard
	var depth, most atomic.Int32
	second := make(chan struct{}, 1)
	var did atomic.Bool
	g = r.guard(t, func(c *Config) {
		c.Notify = func(s string) {
			if d := depth.Add(1); d > most.Load() {
				most.Store(d)
			}
			defer depth.Add(-1)
			if s == AgreeText && !did.Swap(true) {
				r.setCarrier(r.wall.Add(time.Hour))
				g.Check(bg)
				select {
				case <-second:
				case <-time.After(200 * time.Millisecond):
				}
				return
			}
			if did.Load() {
				second <- struct{}{}
			}
		}
	})
	g.Check(bg) // disagrees: DisagreeText
	g.Flush()
	r.setCarrier(r.wall)
	g.Check(bg)
	r.advance(AgreeAfter)
	g.Check(bg) // AgreeText, whose notifier disagrees again
	g.Flush()
	if !did.Load() {
		t.Fatal("no all-clear was sent")
	}
	if m := most.Load(); m != 1 {
		t.Fatalf("%d notices delivered at once, want 1", m)
	}
}

func TestHW8StateRecordsTheSavedWallClock(t *testing.T) {
	// The record carries the box clock at the save, which a reboot reads to
	// age saved alerts by the downtime.
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	r.guard(t, func(c *Config) { c.StatePath = path }).Check(bg)
	if got := readSaved(t, path).SavedWall; !got.Equal(r.wall) {
		t.Fatalf("SavedWall = %v, want %v", got, r.wall)
	}
}

func TestHW8UnreadableHardwareClockLearnsNoOffset(t *testing.T) {
	// A failing hardware clock read is skipped quietly: no offset, and no
	// "outside ±14h" line for a clock that was never read.
	path := filepath.Join(t.TempDir(), "clock.json")
	r := newRig()
	rtc := r.wall
	var logs []string
	g := rtcGuard(t, r, path, &rtc, func(c *Config) {
		c.RTC = func() (time.Time, error) { return time.Time{}, errors.New("rtc: no device") }
		c.Logf = func(f string, a ...any) { logs = append(logs, f) }
	})
	g.Check(bg)
	if v := readSaved(t, path); v.HaveOffset || len(logs) != 0 {
		t.Fatalf("offset %v (have %v), logs %q", v.Offset, v.HaveOffset, logs)
	}
}

func TestHW8ReadFileClosesTheFile(t *testing.T) {
	// readFile leaves no descriptor open (garbage collection off, so no
	// finalizer closes one for it).
	fds := func() int {
		es, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Skip("no /proc/self/fd:", err)
		}
		return len(es)
	}
	path := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	before := fds()
	for range 20 {
		if b, err := readFile(path); err != nil || string(b) != "x" {
			t.Fatalf("readFile = %q, %v", b, err)
		}
	}
	if after := fds(); after != before {
		t.Fatalf("%d descriptors open after 20 reads, want %d", after, before)
	}
}

func TestTIM1AHoldRestartsTheAllClearWait(t *testing.T) {
	// The all-clear needs AgreeAfter of agreement since the last hold, not
	// since agreement first began.
	r := noCarrier()
	g := r.guard(t, nil)
	g.Check(bg)
	hold := func() {
		r.step(time.Hour)
		if s := g.Check(bg); s.State != Held {
			t.Fatalf("stepped: %+v", s)
		}
		r.step(-time.Hour)
		g.Check(bg)
	}
	hold()
	r.advance(AgreeAfter / 2)
	g.Check(bg)
	hold()
	r.advance(AgreeAfter/2 + time.Minute)
	g.Check(bg)
	for _, s := range r.sent() {
		if strings.HasPrefix(s, HoldEndText) {
			t.Fatalf("all-clear %q after %v of agreement since the last hold", s, AgreeAfter/2+time.Minute)
		}
	}
	r.advance(AgreeAfter / 2)
	g.Check(bg)
	if got := r.sent(); !strings.HasPrefix(got[len(got)-1], HoldEndText) {
		t.Fatalf("texts %q, want the all-clear last", got)
	}
}

func TestTIM1NowAnswersACancelledContextWithItsError(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if now, err := g.Now(ctx); !errors.Is(err, context.Canceled) || !now.IsZero() {
		t.Fatalf("Now = %v, %v; want the zero time and context.Canceled", now, err)
	}
}
