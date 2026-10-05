package owner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The local web UI (CH-7, PLAN P2-2) reaches the channel through these
// methods. Joining the box's Wi-Fi needs the Owner Card's Wi-Fi password, so
// a local sign-in with a code-generator code or grid cell is at least as
// strong as a texted UNLOCK with the challenge: it is also the local unlock
// that O4 asks for, and clears challenge mode and the low-tier lock.

// LocalBound caps local sign-in attempts per fixed 24-hour window (starting
// at its first attempt, not sliding), so the Wi-Fi is never an unmetered
// guessing path, including in challenge mode where wrong codes no longer
// escalate anything.
const LocalBound = 24

// SignInAlertEvery is the least time between two local sign-in texts;
// sign-ins in between are listed in the next one (CH-15).
const SignInAlertEvery = time.Hour

// localAlerts coalesces the owner's texts about local sign-ins. Sign-ins
// not yet texted, and the last such text, are durable (State.LocalSignIns,
// State.LocalAlertAt), so neither a restart nor a failed send loses one.
type localAlerts struct {
	// sending is set while a sign-in text is out, so two callers never
	// send the same sign-ins; evicted counts sign-ins the maxSignIns cap
	// pushed out meanwhile, so the send drops exactly what it listed.
	sending bool
	evicted int
	// wrong lists wrong local codes for the digest; alerted is the
	// bound window whose first wrong code was already texted.
	wrong   []time.Time
	alerted time.Time
}

const maxLocalNotes = 200

// maxSignIns caps the untold sign-ins kept while texts fail; the oldest go
// first, and the text still says how many there were.
const maxSignIns = 64

// signInTextLocked returns the text listing untold sign-ins and how many
// it lists, or "" while the last such text is less than SignInAlertEvery old
// or another is being sent. The caller passes both to sendSignIns.
func (c *Channel) signInTextLocked(now time.Time) (string, int) {
	st := c.codes.st
	if c.local.sending || len(st.LocalSignIns) == 0 ||
		(!st.LocalAlertAt.IsZero() && now.Sub(st.LocalAlertAt) < SignInAlertEvery) {
		return "", 0
	}
	c.local.sending, c.local.evicted = true, 0
	n := len(st.LocalSignIns)
	times := c.clockList(st.LocalSignIns, 8)
	if n > 1 {
		return "Phones signed in on the box's Wi-Fi at " + times + ". Not you? Text STOP.", n
	}
	return "A phone signed in on the box's Wi-Fi at " + times + ". Not you? Text STOP.", n
}

// sendSignIns texts a sign-in alert from signInTextLocked and, only once it
// is sent, drops the n sign-ins it listed, less any the cap pushed out
// meanwhile, so one recorded during the send stays for the next text. A failed send keeps them for the
// next Tick. Called without c.mu.
func (c *Channel) sendSignIns(text string, n int, now time.Time) {
	err := c.alert(text)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.local.sending = false
	if err != nil {
		return
	}
	// If this save fails the sign-ins are texted again: a repeat beats a
	// lost alert.
	_ = c.codes.commit(func(s *State) {
		i := n - c.local.evicted
		if i < 0 {
			i = 0
		}
		s.LocalSignIns = append([]time.Time(nil), s.LocalSignIns[i:]...)
		s.LocalAlertAt = now
	})
}

// wrongLocalLocked records a wrong local code for the digest and returns
// the texts it calls for: one on the first wrong code of a bound window, and
// one when the bound is used up (arbitrator ruling on #32).
func (c *Channel) wrongLocalLocked(now time.Time) []string {
	l := &c.local
	if len(l.wrong) < maxLocalNotes {
		l.wrong = append(l.wrong, now)
	}
	var out []string
	st := c.codes.st
	if !st.LocalStart.Equal(l.alerted) {
		l.alerted = st.LocalStart
		out = append(out, "A wrong code was entered on the box's Wi-Fi at "+c.clock(now)+". Not you? Text STOP. More wrong tries today go in the digest.")
	}
	if st.LocalUsed >= LocalBound {
		out = append(out, fmt.Sprintf("Sign-in on the box's Wi-Fi is paused until %s after %d tries. Not you? Text STOP.",
			c.clock(st.LocalStart.Add(WrongWindow)), LocalBound))
	}
	return out
}

// FlushLocal texts sign-ins held back by SignInAlertEvery once it has
// passed. Tick calls it.
func (c *Channel) FlushLocal() {
	now := c.cfg.Now()
	c.mu.Lock()
	t, n := c.signInTextLocked(now)
	c.mu.Unlock()
	if t != "" {
		c.sendSignIns(t, n, now)
	}
}

func (c *Channel) clock(t time.Time) string { return t.In(c.cfg.Location).Format("15:04") }

// clockList renders times as "09:01, 09:30", at most max of them.
func (c *Channel) clockList(ts []time.Time, max int) string {
	var parts []string
	for i, t := range ts {
		if i == max {
			parts = append(parts, fmt.Sprintf("and %d more", len(ts)-max))
			break
		}
		parts = append(parts, c.clock(t))
	}
	return strings.Join(parts, ", ")
}

// takeLocalNotesLocked returns the digest line for wrong local codes.
func (c *Channel) takeLocalNotesLocked() []string {
	if len(c.local.wrong) == 0 {
		return nil
	}
	s := fmt.Sprintf("%d wrong codes entered on the box's Wi-Fi: %s.", len(c.local.wrong), c.clockList(c.local.wrong, 20))
	c.local.wrong = nil
	return []string{s}
}

// Local sign-in errors.
var (
	ErrWrongCode = errors.New("owner: wrong code")
	ErrTooMany   = errors.New("owner: too many local attempts; try again later")
)

// LocalStatus is what the local status page may show without sign-in.
type LocalStatus struct {
	Stopped       bool
	Unlocked      bool
	UnlockedUntil time.Time
	LowLocked     bool
	Challenged    bool
	// Locks counts session locks; a local device signed in under an
	// earlier count is signed out.
	Locks uint64
}

// LocalStatus reports the channel's state for the local UI.
func (c *Channel) LocalStatus() LocalStatus {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	return LocalStatus{
		Stopped:       c.cfg.Engine.Stopped(),
		Unlocked:      c.codes.unlocked(now),
		UnlockedUntil: c.codes.st.UnlockedUntil,
		LowLocked:     c.codes.st.LowLocked,
		Challenged:    c.codes.st.Challenged,
		Locks:         c.codes.st.Locks,
	}
}

// LocalGridCell returns the grid cell a local sign-in may use instead of a
// code-generator code ("" when the grid is not available).
func (c *Channel) LocalGridCell() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes.gridChallenge()
}

// LocalSignIn checks a code-generator code or the asked grid cell typed on
// the local UI. On success the session is unlocked for UnlockFor, the
// low-tier lock and challenge mode end, and until is returned: the local UI
// remembers the device for the same period (CH-7). A wrong code counts as
// one (CH-18). Sign-ins are always texted to the owner, at most one text
// an hour listing each; wrong codes are texted on the first of a bound
// window and when the bound is used up, and listed in the digest.
func (c *Channel) LocalSignIn(code string) (until time.Time, err error) {
	now := c.cfg.Now()
	c.mu.Lock()
	ok, err := c.takeLocalLocked(now)
	if err != nil || !ok {
		c.mu.Unlock()
		if err == nil {
			err = ErrTooMany
		}
		return time.Time{}, err
	}
	res, locked, err := c.codes.checkStrong(code, now, strongOpts{unlock: c.cfg.UnlockFor, count: true, proof: true})
	var alerts []string
	signIn, signIns := "", 0
	if locked {
		alerts = append(alerts, fmt.Sprintf("%d wrong codes, the last on the box's Wi-Fi. Texted codes are off and the session is locked until you send a code-generator code.", WrongToLock))
	}
	if c.codes.justChallenged {
		c.codes.justChallenged = false
		c.held = nil
		c.alertAt = now
		alerts = append(alerts, fmt.Sprintf("Too many wrong codes, the last on the box's Wi-Fi. Codes by text now need a challenge: reply UNLOCK %s and a code from your code generator within %s.",
			c.codes.currentChallenge(now), dur(ChallengeTTL)))
	}
	switch {
	case err == nil && res == strongOK:
		until = c.codes.st.UnlockedUntil
		c.codes.unlockCh = ""
		// Every local sign-in is told to the owner, since it lifts locks
		// and challenge mode without the owner's phone (L1), coalesced to
		// one text an hour under CH-15 (arbitrator).
		evicted := 0
		if c.codes.commit(func(s *State) {
			s.LocalSignIns = append(s.LocalSignIns, now)
			if k := len(s.LocalSignIns) - maxSignIns; k > 0 {
				s.LocalSignIns = append([]time.Time(nil), s.LocalSignIns[k:]...)
				evicted = k
			}
		}) != nil {
			// Not recorded, so not coalesced either: tell now.
			alerts = append(alerts, "A phone signed in on the box's Wi-Fi at "+c.clock(now)+". Not you? Text STOP.")
		} else {
			c.local.evicted += evicted
		}
		signIn, signIns = c.signInTextLocked(now)
	case err == nil:
		alerts = append(alerts, c.wrongLocalLocked(now)...)
	}
	c.mu.Unlock()
	for _, a := range alerts {
		c.alert(a)
	}
	if signIn != "" {
		c.sendSignIns(signIn, signIns, now)
	}
	switch {
	case err != nil:
		return time.Time{}, err
	case res != strongOK:
		return time.Time{}, ErrWrongCode
	}
	return until, nil
}

// takeLocalLocked spends one local attempt of the fixed 24-hour bound.
func (c *Channel) takeLocalLocked(now time.Time) (bool, error) {
	ok := false
	err := c.codes.commit(func(s *State) {
		if s.LocalStart.IsZero() || !now.Before(s.LocalStart.Add(WrongWindow)) {
			s.LocalStart, s.LocalUsed = now, 0
		}
		if s.LocalUsed < LocalBound {
			s.LocalUsed++
			ok = true
		}
	})
	return ok && err == nil, err
}

// LocalStop is STOP from the local UI. Like STOP by text it needs no code,
// since its worst case is a pause (CH-3).
func (c *Channel) LocalStop(ctx context.Context) error {
	c.mu.Lock()
	c.resume = nil
	c.mu.Unlock()
	_, err := c.cfg.Engine.Stop(ctx)
	if err != nil && !c.cfg.Engine.Stopped() {
		return err
	}
	return nil
}

// LocalResume is RESUME from a signed-in local device (P1-5 carry-forward).
// The caller must have checked the sign-in; it is a stronger proof than the
// texted code CH-11 asks for, so no further code is needed. A texted RESUME
// code issued earlier is voided.
func (c *Channel) LocalResume() (string, error) {
	c.mu.Lock()
	c.resume = nil
	c.mu.Unlock()
	if !c.cfg.Engine.Stopped() {
		return "Not stopped. Nothing to resume.", nil
	}
	if err := c.cfg.Engine.Resume(); err != nil {
		return "", fmt.Errorf("owner: resume failed to record, still stopped: %w", err)
	}
	return "Resumed. Held actions may now run.", nil
}

// alert texts the owner a broker template, if a modem is attached.
func (c *Channel) alert(text string) error {
	if c.cfg.Modem == nil {
		return nil
	}
	return c.cfg.Modem.Send(c.cfg.Owner, text)
}

// TOTP is the code-generator code for seed at t (RFC 6238, SHA-1, 30 s, 6
// digits), for the local UI's enrollment check (§8.1 step 5).
func TOTP(seed []byte, t time.Time) string { return totpAt(seed, t.Unix()) }

// UnlockPeriod is CH-14's N, for the local UI's remembered sign-in.
func (c *Channel) UnlockPeriod() time.Duration { return c.cfg.UnlockFor }
