// Package clock checks the box's time (SPEC v0.12 TIM-1).
//
// The box's clock is set by network time (NTP) when online. Carrier network
// time, which the modem receives from the mobile network, is the cross-check:
// the two come over different paths, so one spoofed source shows up as a
// disagreement. A large disagreement puts the box into restricted mode for
// time-sensitive checks: Guard.Now refuses to give a time until the sources
// agree again, so a caller deciding whether a code, a grant or update
// metadata has expired fails closed instead of trusting a moved clock.
//
// A check reads both sources. Guard.Now answers from the last check, but
// checks again first when the last one is stale or when the box's wall clock
// has moved against its monotonic clock since then (an NTP step, or someone
// setting the clock), so a step never goes unchecked until the next
// interval. With one source or none the box keeps working on its own clock;
// only a disagreement restricts it (DEP-2, DEP-4: offline is normal), and
// only carrier time that agrees again lifts it.
//
// The package holds no credential and makes no network call; the carrier
// source is the modem driver's (at.Modem.NetworkTime).
package clock

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// State is the outcome of one check.
type State int

const (
	// Unchecked: no check yet, or neither source is available.
	Unchecked State = iota
	// Agreed: NTP has set the clock and carrier time agrees with it.
	Agreed
	// NetworkOnly: NTP has set the clock; the carrier gave no time.
	NetworkOnly
	// CarrierOnly: no NTP (offline); carrier time agrees with the box clock.
	CarrierOnly
	// Disagree: carrier time and the box clock differ by more than the
	// tolerance. Time-sensitive checks are restricted.
	Disagree
)

func (s State) String() string {
	switch s {
	case Agreed:
		return "agreed"
	case NetworkOnly:
		return "network only"
	case CarrierOnly:
		return "carrier only"
	case Disagree:
		return "disagree"
	}
	return "unchecked"
}

// Status is the last check.
type Status struct {
	State State
	// Skew is box clock minus carrier time; zero without carrier time.
	Skew time.Duration
	// At is the box clock when the check ran.
	At time.Time
}

// Restricted reports whether time-sensitive checks must not proceed.
func (s Status) Restricted() bool { return s.State == Disagree }

var (
	// ErrRestricted is returned by Now while the sources disagree.
	ErrRestricted = errors.New("clock: box time and carrier time disagree; time-sensitive checks are restricted")
	// ErrNoNetworkTime is what a carrier source returns when the network
	// has sent no time.
	ErrNoNetworkTime = errors.New("clock: no carrier network time")
)

// Defaults.
const (
	// DefaultTolerance is the largest skew that still counts as agreeing.
	// Carrier time is to the second, but the modem's clock runs on between
	// network updates; minutes of skew are far below any expiry the broker
	// checks (codes, grants, update metadata).
	DefaultTolerance = 5 * time.Minute
	// DefaultInterval is how often Run checks, and how old a check may be
	// before Now checks again.
	DefaultInterval = 15 * time.Minute
	// NotifyEvery bounds the owner texts: at most one disagreement text,
	// and its all-clear, per period, however often the sources flap.
	NotifyEvery = 24 * time.Hour
)

// AgreeText tells the owner a restriction has lifted.
const AgreeText = "The box clock agrees with the phone network again. Time checks are back to normal."

// DisagreeText is the owner text for a disagreement of skew.
func DisagreeText(skew time.Duration) string {
	return fmt.Sprintf("The box clock and the phone network's time differ by %s. Time checks (code, grant and update expiry) are paused until they agree.", about(skew))
}

func about(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	n, unit := int64(d/time.Minute), "minute"
	switch {
	case d >= 48*time.Hour:
		n, unit = int64(d/(24*time.Hour)), "day"
	case d >= 24*time.Hour:
		n, unit = 1, "day"
	case d >= 2*time.Hour:
		n, unit = int64(d/time.Hour), "hour"
	case d >= time.Hour:
		n, unit = 1, "hour"
	}
	if n != 1 {
		unit += "s"
	}
	return fmt.Sprintf("about %d %s", n, unit)
}

// Config sets up a Guard.
type Config struct {
	// Synced reports whether NTP has set the kernel clock (Synced, from
	// adjtimex, on Linux). An error counts as not synced. Required.
	Synced func() (bool, error)
	// Carrier reads carrier network time from the modem; nil without a
	// modem. Any error counts as no carrier time, never as a disagreement.
	Carrier func(context.Context) (time.Time, error)
	// Notify sends a fixed text to the owner; nil sends none.
	Notify func(string)
	// Tolerance is the largest skew that agrees (DefaultTolerance).
	Tolerance time.Duration
	// Interval is Run's period and the staleness bound (DefaultInterval).
	Interval time.Duration
	// Now is the box's wall clock (time.Now); Elapsed is monotonic time
	// since the Guard was made. Tests set both.
	Now     func() time.Time
	Elapsed func() time.Duration
	// Tick replaces Run's ticker in tests.
	Tick <-chan time.Time
}

// Guard keeps the last check and answers time-sensitive callers.
type Guard struct {
	cfg Config

	mu       sync.Mutex
	status   Status
	checked  bool
	mono     time.Duration // Elapsed at the last check
	told     bool          // a disagreement text is outstanding
	lastTold time.Duration // Elapsed when it was sent
	everTold bool
}

// New makes a Guard. Nothing is read until the first Check or Now.
func New(cfg Config) (*Guard, error) {
	if cfg.Synced == nil {
		return nil, errors.New("clock: Synced is required")
	}
	if cfg.Tolerance <= 0 {
		cfg.Tolerance = DefaultTolerance
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Elapsed == nil {
		start := time.Now()
		cfg.Elapsed = func() time.Duration { return time.Since(start) } // monotonic
	}
	return &Guard{cfg: cfg}, nil
}

// Check reads both sources now and records the result.
func (g *Guard) Check(ctx context.Context) Status {
	synced, err := g.cfg.Synced()
	synced = synced && err == nil
	var carrier time.Time
	have := false
	if g.cfg.Carrier != nil {
		if t, err := g.cfg.Carrier(ctx); err == nil && !t.IsZero() {
			carrier, have = t, true
		}
	}
	// Read the box clock after the modem answers, so the modem's latency
	// does not count as skew.
	now, mono := g.cfg.Now(), g.cfg.Elapsed()
	s := Status{At: now}
	switch {
	case have:
		s.Skew = now.Sub(carrier)
		switch {
		case s.Skew > g.cfg.Tolerance || -s.Skew > g.cfg.Tolerance:
			s.State = Disagree
		case synced:
			s.State = Agreed
		default:
			s.State = CarrierOnly
		}
	case synced:
		s.State = NetworkOnly
	}

	g.mu.Lock()
	if !have && g.status.Restricted() {
		// A disagreement ends only when carrier time agrees again: losing
		// the carrier (jammed, unplugged, or a network that stops sending
		// time) must not lift it.
		s.State, s.Skew = Disagree, g.status.Skew
	}
	g.status, g.checked, g.mono = s, true, mono
	text := g.noticeLocked(s, mono)
	g.mu.Unlock()
	if text != "" && g.cfg.Notify != nil {
		g.cfg.Notify(text)
	}
	return s
}

// noticeLocked decides the owner text for a new status: one disagreement
// text per NotifyEvery, and one all-clear for each text sent.
func (g *Guard) noticeLocked(s Status, mono time.Duration) string {
	switch {
	case s.Restricted() && !g.told && (!g.everTold || mono-g.lastTold >= NotifyEvery):
		g.told, g.everTold, g.lastTold = true, true, mono
		return DisagreeText(s.Skew)
	case !s.Restricted() && s.State != Unchecked && g.told:
		g.told = false
		return AgreeText
	}
	return ""
}

// Status is the last check, without reading the sources.
func (g *Guard) Status() Status {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.status
}

// Now is the time for a time-sensitive check, or ErrRestricted while the
// sources disagree. It checks again first when there has been no check,
// the last is older than the interval, or the wall clock has moved against
// the monotonic clock by more than the tolerance since it.
func (g *Guard) Now(ctx context.Context) (time.Time, error) {
	now, mono := g.cfg.Now(), g.cfg.Elapsed()
	g.mu.Lock()
	s, checked, last := g.status, g.checked, g.mono
	g.mu.Unlock()
	jump := now.Sub(s.At) - (mono - last)
	if !checked || mono-last >= g.cfg.Interval || jump > g.cfg.Tolerance || -jump > g.cfg.Tolerance {
		s = g.Check(ctx)
		now = s.At
	}
	if s.Restricted() {
		return time.Time{}, ErrRestricted
	}
	return now, nil
}

// Run checks at once and then every interval until ctx ends.
func (g *Guard) Run(ctx context.Context) {
	tick := g.cfg.Tick
	if tick == nil {
		t := time.NewTicker(g.cfg.Interval)
		defer t.Stop()
		tick = t.C
	}
	g.Check(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			g.Check(ctx)
		}
	}
}
