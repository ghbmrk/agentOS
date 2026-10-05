package clock

// REQ: TIM-1

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// rig is a box clock, a monotonic clock, an NTP flag and a carrier the
// tests move by hand.
type rig struct {
	mu      sync.Mutex
	wall    time.Time
	mono    time.Duration
	synced  bool
	syncErr error
	carrier time.Time // zero: the modem has no network time
	cErr    error
	reads   int
	texts   []string
}

func newRig() *rig {
	t0 := time.Date(2026, 10, 5, 4, 0, 0, 0, time.UTC)
	return &rig{wall: t0, carrier: t0, synced: true}
}

// advance moves real time: wall, monotonic and carrier together.
func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wall = r.wall.Add(d)
	r.mono += d
	if !r.carrier.IsZero() {
		r.carrier = r.carrier.Add(d)
	}
}

// step sets the box's wall clock only, as NTP (or someone spoofing it) does.
func (r *rig) step(d time.Duration) { r.mu.Lock(); r.wall = r.wall.Add(d); r.mu.Unlock() }

func (r *rig) guard(t *testing.T, mod func(*Config)) *Guard {
	t.Helper()
	cfg := Config{
		Now:     func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.wall },
		Elapsed: func() time.Duration { r.mu.Lock(); defer r.mu.Unlock(); return r.mono },
		Synced:  func() (bool, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.synced, r.syncErr },
		Carrier: func(context.Context) (time.Time, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.reads++
			if r.cErr != nil {
				return time.Time{}, r.cErr
			}
			if r.carrier.IsZero() {
				return time.Time{}, ErrNoNetworkTime
			}
			return r.carrier, nil
		},
		Notify: func(s string) { r.mu.Lock(); r.texts = append(r.texts, s); r.mu.Unlock() },
	}
	if mod != nil {
		mod(&cfg)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

var bg = context.Background()

func TestTIM1NetworkAndCarrierAgree(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(90 * time.Second) // within tolerance
	g := r.guard(t, nil)
	s := g.Check(bg)
	if s.State != Agreed || s.Restricted() {
		t.Fatalf("status = %+v, want agreed", s)
	}
	if s.Skew != -90*time.Second {
		t.Fatalf("skew = %v, want -90s (box behind carrier)", s.Skew)
	}
	now, err := g.Now(bg)
	if err != nil || !now.Equal(r.wall) {
		t.Fatalf("Now = %v, %v", now, err)
	}
	if len(r.texts) != 0 {
		t.Fatalf("texts = %q", r.texts)
	}
}

func TestTIM1LargeDisagreementRestricts(t *testing.T) {
	for _, skew := range []time.Duration{-3 * time.Hour, 6 * time.Minute, 400 * 24 * time.Hour} {
		r := newRig()
		r.carrier = r.carrier.Add(skew)
		g := r.guard(t, nil)
		s := g.Check(bg)
		if s.State != Disagree || !s.Restricted() {
			t.Fatalf("skew %v: status = %+v, want restricted", skew, s)
		}
		if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
			t.Fatalf("skew %v: Now err = %v, want ErrRestricted", skew, err)
		}
		if len(r.texts) != 1 {
			t.Fatalf("skew %v: texts = %q, want one", skew, r.texts)
		}
	}
}

func TestTIM1RestrictedEvenWhenNTPUnsynced(t *testing.T) {
	// Offline: the box runs on its own clock; the carrier still checks it.
	r := newRig()
	r.synced = false
	g := r.guard(t, nil)
	if s := g.Check(bg); s.State != CarrierOnly || s.Restricted() {
		t.Fatalf("status = %+v, want carrier only", s)
	}
	r.step(-2 * time.Hour)
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("status = %+v, want disagree", s)
	}
}

func TestTIM1OneSourceIsNotRestricted(t *testing.T) {
	r := newRig()
	r.carrier = time.Time{} // carrier sends no network time
	g := r.guard(t, nil)
	if s := g.Check(bg); s.State != NetworkOnly || s.Restricted() {
		t.Fatalf("status = %+v, want network only", s)
	}
	r.synced = false
	if s := g.Check(bg); s.State != Unchecked || s.Restricted() {
		t.Fatalf("status = %+v, want unchecked", s)
	}
	// No modem at all.
	g = r.guard(t, func(c *Config) { c.Carrier = nil })
	if s := g.Check(bg); s.State != Unchecked {
		t.Fatalf("no modem: status = %+v", s)
	}
	// A modem error is the same as no carrier time, never a disagreement.
	r.synced, r.cErr = true, errors.New("at: timeout")
	g = r.guard(t, nil)
	if s := g.Check(bg); s.State != NetworkOnly {
		t.Fatalf("modem error: status = %+v", s)
	}
	// An NTP read error counts as not synced.
	r.syncErr = errors.New("adjtimex: EPERM")
	if s := g.Check(bg); s.State != Unchecked {
		t.Fatalf("sync error: status = %+v", s)
	}
}

func TestTIM1RecoveryLiftsRestrictionAndTellsOwner(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(time.Hour)
	g := r.guard(t, nil)
	g.Check(bg)
	r.mu.Lock() // the carrier is corrected
	r.carrier = r.wall
	r.mu.Unlock()
	if s := g.Check(bg); s.State != Agreed {
		t.Fatalf("status = %+v", s)
	}
	if _, err := g.Now(bg); err != nil {
		t.Fatal(err)
	}
	if len(r.texts) != 2 || r.texts[1] != AgreeText {
		t.Fatalf("texts = %q", r.texts)
	}
}

func TestTIM1OwnerTextsAreBoundedUnderFlapping(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	for i := 0; i < 20; i++ {
		r.step(time.Hour)
		g.Check(bg)
		r.step(-time.Hour)
		g.Check(bg)
		r.advance(time.Minute)
	}
	// One disagreement text and its all-clear within the quiet period.
	if len(r.texts) != 2 {
		t.Fatalf("texts = %d %q, want 2", len(r.texts), r.texts)
	}
	r.advance(NotifyEvery)
	r.step(time.Hour)
	g.Check(bg)
	if len(r.texts) != 3 {
		t.Fatalf("after quiet period: texts = %q", r.texts)
	}
}

func TestTIM1WallJumpForcesRecheck(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	g.Check(bg)
	reads := r.reads
	// No jump: Now answers from the last check without asking the modem.
	r.advance(time.Minute)
	if _, err := g.Now(bg); err != nil || r.reads != reads {
		t.Fatalf("err %v, reads %d -> %d", err, reads, r.reads)
	}
	// Someone steps the box clock back a day (a spoofed NTP answer, say):
	// the next time-sensitive answer is refused, not given from the old check.
	r.step(-24 * time.Hour)
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("after jump: err = %v", err)
	}
	if r.reads != reads+1 {
		t.Fatalf("modem reads %d, want a re-check", r.reads-reads)
	}
}

func TestTIM1NTPFirstSyncStepIsAcceptedWhenCarrierAgrees(t *testing.T) {
	// At boot the RTC is off; NTP steps it to the right time. The jump
	// triggers a re-check, and the carrier confirms the new time.
	r := newRig()
	r.synced = false
	r.wall = r.wall.Add(-48 * time.Hour)
	g := r.guard(t, nil)
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("boot: %+v", s)
	}
	r.synced = true
	r.step(48 * time.Hour)
	if _, err := g.Now(bg); err != nil {
		t.Fatalf("after NTP step: %v", err)
	}
	if s := g.Status(); s.State != Agreed {
		t.Fatalf("status = %+v", s)
	}
}

func TestTIM1NowChecksFirstWhenNeverChecked(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(-time.Hour)
	g := r.guard(t, nil)
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("err = %v", err)
	}
}

func TestTIM1StaleCheckIsRepeated(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	g.Check(bg)
	reads := r.reads
	r.advance(DefaultInterval + time.Second)
	if _, err := g.Now(bg); err != nil {
		t.Fatal(err)
	}
	if r.reads != reads+1 {
		t.Fatalf("stale status not re-checked")
	}
}

func TestTIM1ToleranceIsConfigurable(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(2 * time.Minute)
	g := r.guard(t, func(c *Config) { c.Tolerance = time.Minute })
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("status = %+v", s)
	}
}

func TestTIM1OwnerTextIsPlain(t *testing.T) {
	r := newRig()
	r.carrier = r.carrier.Add(3*time.Hour + 4*time.Minute)
	g := r.guard(t, nil)
	g.Check(bg)
	txt := r.texts[0]
	if !strings.Contains(txt, "about 3 hours") || len(txt) > 160 {
		t.Fatalf("text = %q (%d chars)", txt, len(txt))
	}
	for skew, want := range map[time.Duration]string{
		7 * time.Minute:       "about 7 minutes",
		26 * time.Hour:        "about 1 day",
		-400 * 24 * time.Hour: "about 400 days",
	} {
		if got := DisagreeText(skew); !strings.Contains(got, want) {
			t.Errorf("DisagreeText(%v) = %q, want %q", skew, got, want)
		}
	}
}

func TestTIM1RunChecksOnInterval(t *testing.T) {
	r := newRig()
	tick := make(chan time.Time)
	g := r.guard(t, func(c *Config) { c.Tick = tick })
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { g.Run(ctx); close(done) }()
	r.step(time.Hour)
	tick <- time.Time{}
	tick <- time.Time{} // second send returns only after the first check ran
	cancel()
	<-done
	if s := g.Status(); s.State != Disagree {
		t.Fatalf("status = %+v", s)
	}
}

func TestTIM1ConfigRequired(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New with no Synced accepted")
	}
}

func TestTIM1LosingTheCarrierDoesNotLiftRestriction(t *testing.T) {
	r := newRig()
	g := r.guard(t, nil)
	r.step(-30 * 24 * time.Hour) // a spoofed NTP answer
	g.Check(bg)
	r.mu.Lock()
	r.carrier = time.Time{} // then the carrier time goes away
	r.mu.Unlock()
	if s := g.Check(bg); s.State != Disagree {
		t.Fatalf("status = %+v, want still restricted", s)
	}
	if _, err := g.Now(bg); !errors.Is(err, ErrRestricted) {
		t.Fatalf("err = %v", err)
	}
	if len(r.texts) != 1 {
		t.Fatalf("texts = %q", r.texts)
	}
}
