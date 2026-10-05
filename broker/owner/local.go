package owner

import (
	"context"
	"errors"
	"fmt"
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
const LocalBound = 10

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
// one (CH-18). The owner is texted on every attempt, right or wrong, so a
// sign-in by someone else holding the card is never silent.
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
	res, locked, err := c.codes.checkStrong(code, now, strongOpts{unlock: c.cfg.UnlockFor, count: true})
	var alerts []string
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
	at := now.In(c.cfg.Location).Format("15:04")
	switch {
	case err == nil && res == strongOK:
		until = c.codes.st.UnlockedUntil
		c.codes.unlockCh = ""
		// Every local sign-in is told to the owner, since it lifts locks
		// and challenge mode without the owner's phone (L1).
		alerts = append(alerts, "A phone signed in on the box's Wi-Fi at "+at+". Not you? Text STOP.")
	case err == nil && len(alerts) == 0:
		alerts = append(alerts, "A wrong code was entered on the box's Wi-Fi at "+at+". Not you? Text STOP.")
	}
	c.mu.Unlock()
	for _, a := range alerts {
		c.alert(a)
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
func (c *Channel) alert(text string) {
	if c.cfg.Modem != nil {
		_ = c.cfg.Modem.Send(c.cfg.Owner, text)
	}
}

// TOTP is the code-generator code for seed at t (RFC 6238, SHA-1, 30 s, 6
// digits), for the local UI's enrollment check (§8.1 step 5).
func TOTP(seed []byte, t time.Time) string { return totpAt(seed, t.Unix()) }

// UnlockPeriod is CH-14's N, for the local UI's remembered sign-in.
func (c *Channel) UnlockPeriod() time.Duration { return c.cfg.UnlockFor }
