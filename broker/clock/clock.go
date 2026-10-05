// Package clock checks the box's time (SPEC v0.12 TIM-1).
//
// The box's clock is set by network time (NTP) when online. Carrier network
// time, which the modem receives from the mobile network, is the cross-check:
// the two come over different paths, so one spoofed source shows up as a
// disagreement. A large disagreement puts the box into restricted mode for
// time-sensitive checks: Guard.Now refuses to give a time until the sources
// agree again, so a caller deciding whether a code, a grant or update
// metadata has expired fails closed instead of trusting a moved clock. Only
// carrier time that agrees lifts it, and it survives a restart (StatePath).
//
// The box clock is also held to an anchor: the last check carrier time
// confirmed, or, before any carrier time this boot, the first check after
// NTP synced. A wall clock that has moved from the anchor by more than the
// tolerance (plus the kernel's 500 ppm slew limit) against the monotonic
// clock, with no carrier reading to confirm it, is held: Guard.Now answers
// the anchor carried forward on the monotonic clock, not the moved clock.
// So a spoofed NTP step, or many small ones, never becomes the answer
// without the carrier's word.
//
// Guard.Now answers from the last check, but checks again first when the
// wall clock has moved against the monotonic clock since then, or when the
// last check is stale and no Run loop keeps it fresh. Guard.Latest gives
// expiry checks the latest credible time. With one source or none the box
// keeps working on its own clock (DEP-2, DEP-4: offline is normal).
//
// The package holds no credential and makes no network call; the carrier
// source is the modem driver's (at.Modem.NetworkTime).
package clock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
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
	// Held: the box clock moved from its anchor with no carrier time to
	// confirm it. Now answers the anchor carried forward (Status.Held).
	Held
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
	case Held:
		return "held"
	}
	return "unchecked"
}

// Status is the last check.
type Status struct {
	State State
	// Skew is box clock minus carrier time when restricted, or box clock
	// minus the held time when held; zero otherwise without carrier time.
	Skew time.Duration
	// At is the box clock when the check ran.
	At time.Time
	// Since is the box clock when the current restriction or hold began.
	Since time.Time
	// Held is the anchor carried forward to the check, while held.
	Held time.Time
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
	// DefaultCarrierTimeout bounds one modem read.
	DefaultCarrierTimeout = 5 * time.Second
	// AgreeAfter is how long carrier time must agree before the owner gets
	// the all-clear. The restriction lifts at once; only the text waits, so
	// flapping sources never leave "back to normal" as the last word.
	AgreeAfter = time.Hour
	// MaxAlertsPerDay caps disagreement and hold texts sent in any 24
	// hours, counted across restarts. Every alert sent gets its all-clear,
	// so the owner gets at most 2*MaxAlertsPerDay texts a day however the
	// sources flap (a fake cell included, CH-15) and is never left on a
	// stale alarm. The all-clear that uses up the day's alerts says no more
	// texts will come today (AgreeLastText). Suppressed alerts are not
	// queued; STATUS and the digest show the live state.
	MaxAlertsPerDay = 2
	// slewPPM is the kernel's largest NTP slew rate: a held anchor allows
	// the wall clock this much honest drift on top of the tolerance.
	slewPPM = 500
)

// AgreeText tells the owner a restriction or hold has ended.
const AgreeText = "The box clock agrees with the phone network again. Time checks are back to normal."

// AgreeLastText is the all-clear once the day's alerts are used up, so a
// later disagreement the box does not text about is not a surprise.
const AgreeLastText = "The box clock agrees with the phone network again. Time checks are back to normal. If they disagree again today the box won't text; send STATUS to check."

// DisagreeText is the owner text for a disagreement of skew (at most two
// text segments). It names what the wiring does while restricted (K7).
func DisagreeText(skew time.Duration) string {
	t := fmt.Sprintf("The box clock and the phone network's time differ by %s, so the box is playing safe: pre-allowances with an end date ask you first, requests won't expire, and updates wait. Codes and STOP work as usual.", about(skew))
	if zoneLike(skew) {
		t += " A whole-hour difference is often a time-zone error on one side."
	}
	return t
}

// HeldText is the owner text when the box clock jumps with no phone-network
// time to confirm it.
func HeldText(jump time.Duration) string {
	return fmt.Sprintf("The box clock jumped by %s and no phone-network time confirms it, so the box keeps its own count of time until it can check. Nothing to do.", about(jump))
}

// zoneLike reports a skew within a minute of a whole number of quarter
// hours, the shape of a wrong time zone rather than a moved clock.
func zoneLike(skew time.Duration) bool {
	if skew < 0 {
		skew = -skew
	}
	if skew < 14*time.Minute {
		return false
	}
	r := skew % (15 * time.Minute)
	return r <= time.Minute || r >= 14*time.Minute
}

// Line is the status for the owner's STATUS reply, with times in loc.
func (s Status) Line(loc *time.Location) string {
	switch s.State {
	case Disagree:
		return fmt.Sprintf("Time check: restricted since %s (box and phone network differ by %s).", s.Since.In(loc).Format("15:04"), about(s.Skew))
	case Held:
		return fmt.Sprintf("Time check: box clock held since %s (it jumped by %s, unconfirmed).", s.Since.In(loc).Format("15:04"), about(s.Skew))
	case Agreed:
		return "Time check: box and phone network agree."
	case NetworkOnly:
		return "Time check: network only (no phone-network time)."
	case CarrierOnly:
		return "Time check: phone network only (offline)."
	}
	return "Time check: not checked."
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
	// StatePath, if set, keeps a restriction, a hold's anchor and the
	// outstanding owner text across restarts (0600, written atomically).
	// An unreadable file restricts until carrier time agrees.
	StatePath string
	// Now is the box's wall clock (time.Now). Elapsed is monotonic time
	// that keeps counting across restarts within one boot, and BootID names
	// the boot (on Linux, CLOCK_BOOTTIME and the kernel's boot_id). Tests
	// set all three.
	Now     func() time.Time
	Elapsed func() time.Duration
	BootID  func() string
	// Tick replaces Run's ticker in tests.
	Tick <-chan time.Time
	// CarrierTimeout bounds one carrier read (DefaultCarrierTimeout), so a
	// slow modem cannot hold a time-sensitive caller.
	CarrierTimeout time.Duration
	// OnChange, if set, is called after a check that changed the state, so
	// the wiring can re-run lapse sweeps when a restriction lifts.
	OnChange func(Status)
}

// told is the owner text outstanding.
type told int

const (
	toldNone told = iota
	toldHeld
	toldDisagree
)

// Guard keeps the last check and answers time-sensitive callers.
type Guard struct {
	cfg Config

	mu      sync.Mutex
	status  Status
	checked bool
	mono    time.Duration // Elapsed at the last check

	// The anchor: wall and Elapsed at the last carrier-confirmed check, or
	// at this boot's first synced check before any carrier time.
	anchored   bool
	anchorWall time.Time
	anchorMono time.Duration

	told     told
	agreeAt  time.Duration // Elapsed when carrier agreement resumed
	agreeing bool
	alerts   []stamp // alert texts sent in the last day

	seq      uint64 // checks finished, for ordering their notices
	nmu      sync.Mutex
	notified uint64 // the last check whose notices went out

	// The last carrier reading and Elapsed when it was taken (Latest).
	carrier     time.Time
	carrierMono time.Duration

	running atomic.Int32 // Run loops live
	fmu     sync.Mutex
	flight  *flight // the check in progress, shared by concurrent callers
}

// stamp is when an alert text went: Elapsed within this boot, and the box
// clock for a record from an earlier boot.
type stamp struct {
	Mono time.Duration `json:"mono"`
	Wall time.Time     `json:"wall"`
}

type flight struct {
	done chan struct{}
	s    Status
	n    notice
}

// notice is what a finished check tells the outside, after it is published.
type notice struct {
	seq     uint64
	text    string
	changed bool
}

// New makes a Guard and loads StatePath. Nothing is read from the sources
// until the first Check or Now.
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
	if cfg.CarrierTimeout <= 0 {
		cfg.CarrierTimeout = DefaultCarrierTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// Strip monotonic readings: the guard compares wall clocks with each
	// other, and time.Time.Sub would otherwise use the monotonic clock and
	// never see a wall-clock step (L3 D1 on #68). Elapsed is the monotonic
	// side.
	wall := cfg.Now
	cfg.Now = func() time.Time { return wall().Round(0) }
	if cfg.Elapsed == nil {
		cfg.Elapsed = bootElapsed
	}
	if cfg.BootID == nil {
		cfg.BootID = bootID
	}
	g := &Guard{cfg: cfg}
	g.load()
	return g, nil
}

// Check reads both sources now and records the result. Concurrent calls
// share one read of each source.
func (g *Guard) Check(ctx context.Context) Status {
	g.fmu.Lock()
	if f := g.flight; f != nil {
		g.fmu.Unlock()
		select {
		case <-f.done:
			return f.s
		case <-ctx.Done():
			return g.Status()
		}
	}
	f := &flight{done: make(chan struct{})}
	g.flight = f
	g.fmu.Unlock()
	// The shared check must not inherit this caller's deadline: a short one
	// would poison every joined caller's answer (L3 D2). CarrierTimeout
	// bounds it instead.
	f.s, f.n = g.check(context.WithoutCancel(ctx))
	g.fmu.Lock()
	g.flight = nil
	g.fmu.Unlock()
	close(f.done)
	// Tell the outside only after the result is published, so a slow text
	// or a callback that checks again never holds joined callers (L3 D3).
	g.deliver(f.s, f.n)
	return f.s
}

// deliver sends a check's notices unless a later check's already went.
func (g *Guard) deliver(s Status, n notice) {
	if n.text == "" && !n.changed {
		return
	}
	g.nmu.Lock()
	if n.seq <= g.notified {
		g.nmu.Unlock()
		return
	}
	g.notified = n.seq
	g.nmu.Unlock()
	if n.text != "" && g.cfg.Notify != nil {
		g.cfg.Notify(n.text)
	}
	if n.changed && g.cfg.OnChange != nil {
		g.cfg.OnChange(s)
	}
}

// allowedLocked is how far the wall clock may move from the anchor, against
// the monotonic clock, at mono.
func (g *Guard) allowedLocked(mono time.Duration) time.Duration {
	return g.cfg.Tolerance + (mono-g.anchorMono)/(1e6/slewPPM)
}

func (g *Guard) check(ctx context.Context) (Status, notice) {
	synced, err := g.cfg.Synced()
	synced = synced && err == nil
	var carrier time.Time
	have := false
	if g.cfg.Carrier != nil {
		cctx, cancel := context.WithTimeout(ctx, g.cfg.CarrierTimeout)
		if t, err := g.cfg.Carrier(cctx); err == nil && !t.IsZero() {
			carrier, have = t, true
		}
		cancel()
	}
	// Read the box clock after the modem answers, so the modem's latency
	// does not count as skew.
	now, mono := g.cfg.Now(), g.cfg.Elapsed()
	s := Status{At: now}

	g.mu.Lock()
	prev, wasChecked := g.status, g.checked
	switch {
	case have:
		g.carrier, g.carrierMono = carrier, mono
		s.Skew = now.Sub(carrier)
		switch {
		case s.Skew > g.cfg.Tolerance || -s.Skew > g.cfg.Tolerance:
			s.State = Disagree
		default:
			s.State = CarrierOnly
			if synced {
				s.State = Agreed
			}
			g.anchored, g.anchorWall, g.anchorMono = true, now, mono
		}
	case prev.Restricted():
		// A disagreement ends only when carrier time agrees again: losing
		// the carrier (jammed, unplugged, a network that stops sending time,
		// a module clock reset before the floor) must not lift it.
		s.State, s.Skew = Disagree, prev.Skew
	case g.anchored:
		held := g.anchorWall.Add(mono - g.anchorMono)
		if d := now.Sub(held); d > g.allowedLocked(mono) || -d > g.allowedLocked(mono) {
			s.State, s.Skew, s.Held = Held, d, held
		} else if synced {
			s.State = NetworkOnly
		}
	case synced:
		// This boot's first synced check, before any carrier time.
		s.State = NetworkOnly
		g.anchored, g.anchorWall, g.anchorMono = true, now, mono
	}
	if s.State == Disagree || s.State == Held {
		s.Since = s.At
		if prev.State == s.State && !prev.Since.IsZero() {
			s.Since = prev.Since
		}
	}
	g.status, g.checked, g.mono = s, true, mono
	text := g.noticeLocked(s, mono)
	if !wasChecked || prev.State != s.State || prev.Since != s.Since || text != "" || have {
		g.saveLocked()
	}
	g.seq++
	n := notice{seq: g.seq, text: text, changed: !wasChecked || prev.State != s.State}
	g.mu.Unlock()
	return s, n
}

// noticeLocked decides the owner text for a new status: an alert (a
// disagreement, or a hold) when none is outstanding (a disagreement also
// when only a hold text is), and the all-clear once carrier time has agreed
// for AgreeAfter. A restriction or hold in between resets the wait. Alerts
// are capped at MaxAlertsPerDay; every alert sent gets its all-clear.
func (g *Guard) noticeLocked(s Status, mono time.Duration) string {
	recent := g.alerts[:0]
	for _, a := range g.alerts {
		if mono-a.Mono < 24*time.Hour {
			recent = append(recent, a)
		}
	}
	g.alerts = recent
	room := len(g.alerts) < MaxAlertsPerDay
	alert := func(t told, text string) string {
		g.told = t
		g.alerts = append(g.alerts, stamp{Mono: mono, Wall: s.At})
		return text
	}
	switch s.State {
	case Disagree:
		g.agreeing = false
		if g.told != toldDisagree && room {
			return alert(toldDisagree, DisagreeText(s.Skew))
		}
	case Held:
		g.agreeing = false
		if g.told == toldNone && room {
			return alert(toldHeld, HeldText(s.Skew))
		}
	case Agreed, CarrierOnly:
		if g.told == toldNone {
			return ""
		}
		if !g.agreeing {
			g.agreeing, g.agreeAt = true, mono
		}
		if mono-g.agreeAt < AgreeAfter {
			return ""
		}
		// Every alert sent gets its all-clear (security on #68).
		g.told, g.agreeing = toldNone, false
		if !room {
			return AgreeLastText
		}
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
// sources disagree. While held it is the held time.
func (g *Guard) Now(ctx context.Context) (time.Time, error) {
	now, s := g.refresh(ctx)
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if s.Restricted() {
		return time.Time{}, ErrRestricted
	}
	return now, nil
}

// Latest is the latest credible time: the later of the box clock (the held
// time while held) and the last carrier reading carried forward on the
// monotonic clock. A caller deciding whether something has expired uses
// it, so a clock moved back cannot keep a grant alive (potency PT1 on #68).
// It answers while restricted too; the caller reads the Status.
func (g *Guard) Latest(ctx context.Context) (time.Time, Status) {
	now, s := g.refresh(ctx)
	mono := g.cfg.Elapsed()
	g.mu.Lock()
	c, cm := g.carrier, g.carrierMono
	g.mu.Unlock()
	if !c.IsZero() {
		if t := c.Add(mono - cm); t.After(now) {
			now = t
		}
	}
	return now, s
}

// refresh returns the time to answer and a status current enough to act
// on. It checks again first when there has been no check, when the wall
// clock has moved against the monotonic clock by more than the tolerance
// since the last check or beyond what the anchor allows, or, when no Run
// loop is live, when the last is older than the interval. With Run live a
// stale read answers from the last check, so a burst of callers never
// queues on the modem.
func (g *Guard) refresh(ctx context.Context) (time.Time, Status) {
	now, mono := g.cfg.Now(), g.cfg.Elapsed()
	g.mu.Lock()
	s, checked, last := g.status, g.checked, g.mono
	drifted := false
	if g.anchored && s.State != Held && s.State != Disagree {
		d := now.Sub(g.anchorWall.Add(mono - g.anchorMono))
		drifted = d > g.allowedLocked(mono) || -d > g.allowedLocked(mono)
	}
	g.mu.Unlock()
	jump := now.Sub(s.At) - (mono - last)
	stale := mono-last >= g.cfg.Interval && g.running.Load() == 0
	if !checked || stale || drifted || jump > g.cfg.Tolerance || -jump > g.cfg.Tolerance {
		s = g.Check(ctx)
		now, mono = g.cfg.Now(), g.cfg.Elapsed()
	}
	if s.State == Held {
		g.mu.Lock()
		now = g.anchorWall.Add(mono - g.anchorMono)
		g.mu.Unlock()
	}
	return now, s
}

// Run checks at once and then every interval until ctx ends.
func (g *Guard) Run(ctx context.Context) {
	tick := g.cfg.Tick
	if tick == nil {
		t := time.NewTicker(g.cfg.Interval)
		defer t.Stop()
		tick = t.C
	}
	g.running.Add(1)
	defer g.running.Add(-1)
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

// saved is the state file (security C2 on #68).
type saved struct {
	Restricted bool          `json:"restricted"`
	Skew       time.Duration `json:"skew"`
	Since      time.Time     `json:"since"`
	Told       told          `json:"told"`
	// The anchor, usable only within the boot that recorded it.
	Boot       string        `json:"boot"`
	Anchored   bool          `json:"anchored"`
	AnchorWall time.Time     `json:"anchor_wall"`
	AnchorMono time.Duration `json:"anchor_mono"`
	// Alerts sent in the last day, counted toward MaxAlertsPerDay.
	Alerts []stamp `json:"alerts"`
}

func (g *Guard) load() {
	if g.cfg.StatePath == "" {
		return
	}
	b, err := os.ReadFile(g.cfg.StatePath)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	var v saved
	if err != nil || json.Unmarshal(b, &v) != nil {
		// Fail closed: an unreadable record may have held a restriction.
		g.status = Status{State: Disagree}
		return
	}
	if v.Restricted {
		g.status = Status{State: Disagree, Skew: v.Skew, Since: v.Since}
	}
	g.told = v.Told
	sameBoot := v.Boot != "" && v.Boot == g.cfg.BootID()
	if v.Anchored && sameBoot {
		g.anchored, g.anchorWall, g.anchorMono = true, v.AnchorWall, v.AnchorMono
	}
	// Alerts from an earlier boot are placed on this boot's monotonic clock
	// by their box-clock age; one that would lie in the future counts as
	// sent now, so a clock moved back cannot free the cap.
	mono, wall := g.cfg.Elapsed(), g.cfg.Now()
	for _, a := range v.Alerts {
		if !sameBoot {
			age := wall.Sub(a.Wall)
			if age < 0 {
				age = 0
			}
			a.Mono = mono - age
		}
		g.alerts = append(g.alerts, a)
	}
}

// saveLocked writes the state file. A failed write leaves the old file in
// place.
func (g *Guard) saveLocked() {
	if g.cfg.StatePath == "" {
		return
	}
	v := saved{
		Restricted: g.status.Restricted(), Told: g.told,
		Boot: g.cfg.BootID(), Anchored: g.anchored, AnchorWall: g.anchorWall, AnchorMono: g.anchorMono,
		Alerts: g.alerts,
	}
	if v.Restricted {
		v.Skew, v.Since = g.status.Skew, g.status.Since
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	tmp, err := os.CreateTemp(filepath.Dir(g.cfg.StatePath), ".clock-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(b)
	if serr := tmp.Sync(); werr == nil {
		werr = serr
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil || os.Rename(tmp.Name(), g.cfg.StatePath) != nil {
		_ = os.Remove(tmp.Name())
	}
}
