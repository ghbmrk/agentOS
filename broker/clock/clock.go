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
// tolerance against the boot clock, with no carrier reading to confirm it,
// is held: Guard.Now answers
// the anchor carried forward on the monotonic clock, not the moved clock.
// So a spoofed NTP step, or many small ones, never becomes the answer
// without the carrier's word.
//
// Guard.Now answers from the last check, but checks again first when the
// wall clock has moved against the monotonic clock since then, or when the
// last check is stale and no Run loop keeps it fresh. Guard.Latest gives
// expiry checks the latest credible time, and Guard.Earliest gives
// minimum-age checks the earliest. With one source or none the box
// keeps working on its own clock (DEP-2, DEP-4: offline is normal).
//
// The package holds no credential and makes no network call; the carrier
// source is the modem driver's (at.Modem.NetworkTime).
package clock

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/durable"
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
	// Verified reports that this boot has had verified time: a verified
	// NTP sync (Config.Synced), or carrier time agreeing with a box clock at
	// or after the floor. Until then the box clock came from the host's
	// hardware clock, which Windows keeps in local time (HW-8).
	Verified bool
	// Start is the box clock's reading of when this boot began.
	Start time.Time
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
	// alertWindow is how long a sent alert counts toward MaxAlertsPerDay.
	alertWindow = 24 * time.Hour
	// anchorSlack is the honest wall-vs-boot-clock movement a hold allows on
	// top of the tolerance. NTP slewing moves the wall and boot clocks
	// together, so only steps open a gap (L3 F6 on #68).
	anchorSlack = 5 * time.Second
)

// AgreeText tells the owner a restriction or hold has ended.
const AgreeText = "My clock agrees with the phone network again. Time checks are back to normal."

// AgreeLastText is the all-clear once the day's alerts are used up, so a
// later disagreement the box does not text about is not a surprise.
const AgreeLastText = AgreeText + LastSuffix

// DisagreeText is the owner text for a disagreement of skew (at most two
// text segments). It names what the wiring does while restricted (K7).
func DisagreeText(skew time.Duration) string {
	t := fmt.Sprintf("My clock and the phone network's time differ by %s, so I am playing safe: pre-allowances with an end date ask you first, requests won't expire, and updates wait. Codes and STOP work as usual.", about(skew))
	if zoneLike(skew) {
		t += " A whole-hour difference is often a time-zone error on one side."
	}
	return t
}

// HoldEndText ends a hold that no carrier time confirmed either way: the
// box clock is back in line with the box's own count.
const HoldEndText = "My clock is back in line with my own count of time. Time checks are back to normal."

// LastSuffix ends the all-clear that uses up the day's alerts.
const LastSuffix = " If it happens again today I won't text; send STATUS to check."

// StateLostText is the alert when the saved clock check could not be read
// at start, so a restriction it may have held is kept.
const StateLostText = "I couldn't read my saved clock check, so I am playing safe until the phone network's time confirms the clock: pre-allowances with an end date ask you first, requests won't expire, and updates wait. Codes and STOP work as usual."

// HeldText is the owner text when the box clock jumps with no phone-network
// time to confirm it.
func HeldText(jump time.Duration) string {
	return fmt.Sprintf("My clock jumped by %s and no phone-network time confirms it, so I keep my own count of time until I can check. Nothing to do.", about(jump))
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
	if !s.Verified && s.State != Disagree && s.State != Held {
		return fmt.Sprintf("Time check: not confirmed since start at %s (waiting for network or phone-network time). Nothing to do.", s.Start.In(loc).Format("15:04"))
	}
	switch s.State {
	case Disagree:
		if s.Skew == 0 {
			return fmt.Sprintf("Time check: restricted since %s (saved check unreadable; waiting for phone-network time).", s.Since.In(loc).Format("15:04"))
		}
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

// SyncKind is how an NTP sync was verified.
type SyncKind int

const (
	NotSynced   SyncKind = iota
	SyncedPlain          // at least three unauthenticated sources combined
	SyncedNTS            // the selected source is NTS-authenticated
)

// Config sets up a Guard.
type Config struct {
	// Synced reports a verified NTP sync (Synced: chronyd, through chronyc,
	// HW-8 and security T4, T5). An error counts as not synced. Synced or
	// Sync is required.
	Synced func() (bool, error)
	// Sync, when set, is used instead of Synced and says how the sync was
	// verified (Sync: chronyd). Only an NTS sync verifies a box clock below
	// the saved floor, lowers the floor, or teaches the hardware-clock
	// offset (security R1, L3 on #177); a sync through Synced is plain.
	Sync func() (SyncKind, error)
	// RTC reads the host's hardware clock as the kernel does, as if UTC
	// (RTC, from sysfs, on Linux). At an NTS-verified sync the guard learns its
	// offset from UTC for BootEstimate (potency C1, security T7). Nil
	// learns none. It is never written.
	RTC func() (time.Time, error)
	// HostID names the PC the box runs on (HostID: the firmware's system
	// UUID). The offset is learned only with one and used only on the same
	// PC, since the drive moves between PCs (L3 on #177). Nil learns none.
	HostID func() string
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
	// the wiring can re-run lapse sweeps when a restriction lifts. A change
	// a later one supersedes before it is delivered may be skipped.
	OnChange func(Status)
	// Logf reports state-file faults. Nil is silent.
	Logf func(format string, args ...any)
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

	lost     bool     // the state file was unreadable at start
	queue    []notice // notices in check order, delivered after publish
	draining bool
	drains   sync.WaitGroup // drain goroutines running

	// The last carrier reading and Elapsed when it was taken (Latest).
	carrier     time.Time
	carrierMono time.Duration

	// verified: this boot has had verified time. floor: the latest
	// verified time ever seen, which true time cannot be before; it bounds
	// Latest and Earliest while unverified and only advances (security T3).
	// offset: the hardware clock minus UTC at the last verified sync.
	verified bool
	floor    time.Time
	// belowFloorLogged: an unauthenticated sync below the floor was
	// logged this boot.
	belowFloorLogged bool
	offset           time.Duration
	haveOffset       bool
	offsetHost       string

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
}

// notice is what a finished check tells the outside, after it is published.
type notice struct {
	s       Status
	text    string
	changed bool
}

// New makes a Guard and loads StatePath. Nothing is read from the sources
// until the first Check or Now.
func New(cfg Config) (*Guard, error) {
	if cfg.Sync == nil && cfg.Synced == nil {
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
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	g := &Guard{cfg: cfg}
	g.load()
	g.status.Verified, g.status.Start = g.verified, g.startLocked()
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
	f.s = g.check(context.WithoutCancel(ctx))
	g.fmu.Lock()
	g.flight = nil
	g.fmu.Unlock()
	close(f.done)
	// Tell the outside only after the result is published, and from a
	// goroutine of its own, so a slow or hung text holds no caller, Run
	// included, and a callback may check again (L3 D3, F2 on #68).
	g.drains.Add(1)
	go func() {
		defer g.drains.Done()
		g.drain()
	}()
	return f.s
}

// Flush waits until every notice queued so far has been delivered.
func (g *Guard) Flush() { g.drains.Wait() }

// drain delivers queued notices in check order, one caller at a time. A
// caller that finds another draining leaves its notices to it, so Notify
// may itself check. Texts are never dropped; an OnChange that a later
// queued change supersedes is skipped (L3 F2 on #68).
func (g *Guard) drain() {
	g.mu.Lock()
	if g.draining {
		g.mu.Unlock()
		return
	}
	// Notifier panics are recovered in call, so draining is always reset,
	// and it is reset under the same lock as the last empty-queue check, so
	// no notice queued meanwhile is stranded.
	g.draining = true
	for len(g.queue) > 0 {
		n := g.queue[0]
		g.queue = g.queue[1:]
		superseded := false
		for _, later := range g.queue {
			superseded = superseded || later.changed
		}
		g.mu.Unlock()
		if n.text != "" && g.cfg.Notify != nil {
			g.call(func() { g.cfg.Notify(n.text) })
		}
		if n.changed && !superseded && g.cfg.OnChange != nil {
			g.call(func() { g.cfg.OnChange(n.s) })
		}
		g.mu.Lock()
	}
	g.draining = false
	g.mu.Unlock()
}

// call runs a notifier, logging a panic instead of losing the queue.
func (g *Guard) call(f func()) {
	defer func() {
		if p := recover(); p != nil {
			g.cfg.Logf("clock: notifier panicked: %v", p)
		}
	}()
	f()
}

// allowedLocked is how far the wall clock may move from the anchor, against
// the monotonic clock, at mono.
func (g *Guard) allowedLocked(time.Duration) time.Duration {
	return g.cfg.Tolerance + anchorSlack
}

// syncKind asks Sync, or Synced as plain.
func (g *Guard) syncKind() (SyncKind, error) {
	if g.cfg.Sync != nil {
		return g.cfg.Sync()
	}
	ok, err := g.cfg.Synced()
	if !ok {
		return NotSynced, err
	}
	return SyncedPlain, err
}

func (g *Guard) check(ctx context.Context) Status {
	kind, err := g.syncKind()
	synced := kind != NotSynced && err == nil
	nts := synced && kind == SyncedNTS
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
	s := Status{At: now, Start: now.Add(-mono)}

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
	// Verified time: an NTS-authenticated sync; or a plain NTP sync, or
	// carrier time agreeing (carrier time alone is only a tie-break,
	// security T4), with a box clock at or after the floor, since either
	// can be forged on path (security R1, L3 on #177); never while
	// restricted or held.
	aboveFloor := g.floor.IsZero() || !now.Before(g.floor.Add(-g.cfg.Tolerance))
	carrierOK := have && (s.State == CarrierOnly || s.State == Agreed) && aboveFloor
	syncOK := nts || synced && aboveFloor
	if synced && !syncOK && !g.belowFloorLogged {
		g.cfg.Logf("clock: unauthenticated time %v is behind the saved floor %v; not verified", now, g.floor)
		g.belowFloorLogged = true
	}
	verifiedNow := (syncOK || carrierOK) && s.State != Disagree && s.State != Held
	if verifiedNow {
		g.verified = true
		switch {
		case now.After(g.floor):
			g.floor = now
		case g.floor.Sub(now) > g.cfg.Tolerance:
			// Only authenticated time gets here below the floor: a floor
			// ahead of it is a corrupt or tampered file, never true time.
			g.cfg.Logf("clock: saved floor %v is ahead of verified time %v; replaced", g.floor, now)
			g.floor = now
		}
		if nts {
			g.learnOffsetLocked(now)
		}
	}
	s.Verified = g.verified
	g.status, g.checked, g.mono = s, true, mono
	text := g.noticeLocked(s, mono)
	// While alerts count toward the cap, every check saves, so a reboot
	// finds this boot's uptime no older than the last check (L3 F1, round 4).
	if !wasChecked || prev.State != s.State || prev.Since != s.Since || text != "" || have || len(g.alerts) > 0 || verifiedNow {
		g.saveLocked()
	}
	if changed := !wasChecked || prev.State != s.State; text != "" || changed {
		g.queue = append(g.queue, notice{s: s, text: text, changed: changed})
	}
	g.mu.Unlock()
	return s
}

// noticeLocked decides the owner text for a new status: an alert (a
// disagreement, or a hold) when none is outstanding, a disagreement also
// when only a hold text is, and the all-clear for an outstanding alert once
// the alarm has been over for AgreeAfter: carrier agreement for either, or,
// for a hold, the box clock back in line without a carrier. A restriction
// or hold in between resets the wait. Alerts are capped at MaxAlertsPerDay,
// except a hold's escalation to a disagreement; every alert sent gets its
// all-clear.
func (g *Guard) noticeLocked(s Status, mono time.Duration) string {
	recent := g.alerts[:0]
	for _, a := range g.alerts {
		if mono-a.Mono < alertWindow {
			recent = append(recent, a)
		}
	}
	g.alerts = recent
	room := len(g.alerts) < MaxAlertsPerDay
	alert := func(t told, text string) string {
		g.told = t
		g.alerts = append(g.alerts, stamp{Mono: mono, Wall: g.latestLocked(s.At, mono)})
		return text
	}
	switch s.State {
	case Disagree:
		g.agreeing = false
		if g.told != toldDisagree && (room || g.told == toldHeld) {
			if g.lost && s.Skew == 0 {
				return alert(toldDisagree, StateLostText)
			}
			return alert(toldDisagree, DisagreeText(s.Skew))
		}
	case Held:
		g.agreeing = false
		if g.told == toldNone && room {
			return alert(toldHeld, HeldText(s.Skew))
		}
	case Agreed, CarrierOnly, NetworkOnly, Unchecked:
		over := s.State == Agreed || s.State == CarrierOnly || g.told == toldHeld
		if g.told == toldNone || !over {
			return ""
		}
		if !g.agreeing {
			g.agreeing, g.agreeAt = true, mono
		}
		if mono-g.agreeAt < AgreeAfter {
			return ""
		}
		// Every alert sent gets its all-clear (security on #68).
		text := AgreeText
		if s.State != Agreed && s.State != CarrierOnly {
			text = HoldEndText
		}
		g.told, g.agreeing = toldNone, false
		if !room {
			text += LastSuffix
		}
		return text
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
//
// Use it only where a later time is the stricter answer (has it expired?).
// A check that something is old enough (a hold period, a soak, a quiet
// window, a wait) uses Earliest instead.
func (g *Guard) Latest(ctx context.Context) (time.Time, Status) {
	now, s := g.refresh(ctx)
	mono := g.cfg.Elapsed()
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.latestLocked(now, mono)
	if !g.verified && g.floor.After(t) {
		t = g.floor // a clock behind keeps nothing alive past the floor (HW-8)
	}
	return t, s
}

// Earliest is the earliest credible time: the earlier of the box clock (the
// held time while held) and the last carrier reading carried forward. A
// caller deciding whether something is old enough uses it, so a clock moved
// forward cannot end a hold, soak or quiet window early (L3 C4 on #68). It
// answers while restricted too; the caller reads the Status.
func (g *Guard) Earliest(ctx context.Context) (time.Time, Status) {
	now, s := g.refresh(ctx)
	mono := g.cfg.Elapsed()
	g.mu.Lock()
	defer g.mu.Unlock()
	if c := g.carrierForwardLocked(mono); !c.IsZero() && c.Before(now) {
		now = c
	}
	if !g.verified && !g.floor.IsZero() && g.floor.Before(now) {
		now = g.floor // a clock ahead ends no wait early (HW-8)
	}
	return now, s
}

func (g *Guard) carrierForwardLocked(mono time.Duration) time.Time {
	if g.carrier.IsZero() {
		return time.Time{}
	}
	return g.carrier.Add(mono - g.carrierMono)
}

func (g *Guard) latestLocked(now time.Time, mono time.Duration) time.Time {
	if c := g.carrierForwardLocked(mono); c.After(now) {
		return c
	}
	return now
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
	// Alerts sent in the last day, counted toward MaxAlertsPerDay, and the
	// boot clock and latest credible time when the file was written, so a
	// later boot trusts the ages measured within this one.
	Alerts    []stamp       `json:"alerts"`
	SavedMono time.Duration `json:"saved_mono"`
	SavedWall time.Time     `json:"saved_wall"`
	// HW-8: the boot that had verified time, the floor, and the hardware
	// clock's offset from UTC (BootEstimate).
	VerifiedBoot string        `json:"verified_boot,omitempty"`
	Floor        time.Time     `json:"floor"`
	Offset       time.Duration `json:"offset"`
	HaveOffset   bool          `json:"have_offset"`
	OffsetHost   string        `json:"offset_host,omitempty"` // HostKey of the PC it was learned on
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
	if err == nil {
		err = json.Unmarshal(b, &v)
	}
	if err != nil {
		// Fail closed: an unreadable record may have held a restriction.
		g.cfg.Logf("clock: state file unreadable, restricting until carrier time agrees: %v", err)
		g.status, g.lost = Status{State: Disagree}, true
		return
	}
	if v.Restricted {
		g.status = Status{State: Disagree, Skew: v.Skew, Since: v.Since}
	}
	g.told = v.Told
	sameBoot := v.Boot != "" && v.Boot == g.cfg.BootID()
	g.floor = v.Floor
	if validOffset(v.Offset) {
		g.offset, g.haveOffset, g.offsetHost = v.Offset, v.HaveOffset, v.OffsetHost
	}
	g.verified = v.VerifiedBoot != "" && v.VerifiedBoot == g.cfg.BootID()
	if v.Anchored && sameBoot {
		g.anchored, g.anchorWall, g.anchorMono = true, v.AnchorWall, v.AnchorMono
	}
	// Alerts from an earlier boot are placed on this boot's clock by their
	// age: the part within that boot comes from its boot clock and is
	// trusted; only the downtime since, which the box clock gives at both
	// ends, is clamped to between zero and this boot's uptime, so no clock
	// setting frees the cap early (L3 F1 on #68). Alerts a day old are
	// pruned before every save, so an in-boot age outside zero to a day
	// means a corrupt file: that alert counts as just sent (security R1).
	mono, wall := g.cfg.Elapsed(), g.cfg.Now()
	down := min(max(wall.Sub(v.SavedWall), 0), mono)
	for _, a := range v.Alerts {
		if !sameBoot {
			age, d := v.SavedMono-a.Mono, down
			if age < 0 || age > alertWindow+time.Minute { // a minute for the save's own delay
				g.cfg.Logf("clock: saved alert age %v implausible, counting it as new", age)
				age, d = 0, 0
			}
			a.Mono = mono - (age + d)
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
		Alerts: g.alerts, SavedMono: g.cfg.Elapsed(),
	}
	v.SavedWall = g.latestLocked(g.cfg.Now(), v.SavedMono)
	v.Floor, v.Offset, v.HaveOffset, v.OffsetHost = g.floor, g.offset, g.haveOffset, g.offsetHost
	if g.verified {
		v.VerifiedBoot = g.cfg.BootID()
	}
	if v.Restricted {
		v.Skew, v.Since = g.status.Skew, g.status.Since
	}
	b, err := json.Marshal(v)
	if err == nil {
		err = durable.WriteFile(g.cfg.StatePath, b, 0o600)
	}
	if err != nil {
		g.cfg.Logf("clock: state not saved: %v", err)
	}
}

// maxOffset is the largest hardware-clock offset from UTC learned: time
// zones span UTC-12 to UTC+14.
const maxOffset = 14 * time.Hour

func validOffset(d time.Duration) bool {
	return d >= -maxOffset && d <= maxOffset && d%(15*time.Minute) == 0
}

// learnOffsetLocked records the hardware clock's offset from verified time
// now, rounded to 15 minutes (time zones are whole quarter hours), if it
// is within ±14 hours (potency C1, security T7).
func (g *Guard) learnOffsetLocked(now time.Time) {
	if g.cfg.RTC == nil || g.cfg.HostID == nil {
		return
	}
	host := HostKey(g.cfg.HostID())
	if host == "" {
		return // the offset belongs to one PC's clock; with no PC named, none
	}
	rtc, err := g.cfg.RTC()
	if err != nil || rtc.IsZero() {
		return
	}
	d := rtc.Sub(now).Round(15 * time.Minute)
	if !validOffset(d) {
		g.cfg.Logf("clock: hardware clock offset %v outside ±14h; not learned", rtc.Sub(now))
		return
	}
	g.offset, g.haveOffset, g.offsetHost = d, true, host
}

// HostKey names the PC an offset was learned on without keeping its
// identifier: a hash of the firmware's system UUID. An absent or
// placeholder UUID names no PC.
func HostKey(id string) string {
	id = strings.ToLower(strings.TrimSpace(id))
	if !validHostID.MatchString(id) || strings.Trim(id, "0-") == "" || strings.Trim(id, "f-") == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("agentos clock host\x00" + id))
	return hex.EncodeToString(sum[:16])
}

var validHostID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (g *Guard) startLocked() time.Time { return g.cfg.Now().Add(-g.cfg.Elapsed()) }

// BootEstimate is the box's best time at boot, before any time service:
// the hardware clock reading rtc less the offset learned at the last
// verified sync, from the guard's state file. ok is false with no offset
// learned or no readable file; then the clock is left as the kernel set it.
// The estimate stays unverified: the guard's floor still bounds it.
func BootEstimate(statePath string, rtc time.Time, hostID string) (time.Time, bool) {
	b, err := os.ReadFile(statePath)
	if err != nil {
		return time.Time{}, false
	}
	var v saved
	if json.Unmarshal(b, &v) != nil || !v.HaveOffset || !validOffset(v.Offset) {
		return time.Time{}, false
	}
	if h := HostKey(hostID); h == "" || h != v.OffsetHost {
		return time.Time{}, false // learned on another PC, or this one unnamed (L3 on #177)
	}
	return rtc.Add(-v.Offset), true
}
