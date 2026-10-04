package owner

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"math/big"
	"time"
)

// Code hygiene limits (CH-18).
const (
	// WrongPerRequest wrong replies void a request or a RESUME code.
	WrongPerRequest = 3
	// WrongToLock wrong codes of any kind since the last code-generator
	// success, within WrongWindow, lock the low tier and the session.
	WrongToLock = 5
	// WrongToThrottle wrong codes within WrongWindow, successes or not,
	// pause code checks by text until the oldest ages out. This bounds
	// guessing of the 6-digit high-tier codes (assumption O4).
	WrongToThrottle = 10
	WrongWindow     = 24 * time.Hour
)

// codes checks approval codes and owns the durable State. It is not safe
// for concurrent use; Channel serializes access.
//
// Every change to State goes through commit: the change is applied to a
// copy, the copy is saved, and only a saved copy becomes current. So a
// failed save never leaves a step, a cell, or an unlock live in memory that
// a restart would forget (CH-18).
type codes struct {
	sec   Secrets
	st    State
	store Store
	rand  io.Reader
	// challenge is the grid cell last asked for; only it is accepted.
	challenge string
}

// commit applies f to a copy of the state, saves it, and keeps it only if
// the save succeeded.
func (c *codes) commit(f func(*State)) error {
	next := copyState(c.st)
	f(&next)
	if err := c.store.Save(next); err != nil {
		return err
	}
	c.st = next
	return nil
}

// strongResult says how a code-generator or grid code was checked.
type strongResult int

const (
	strongWrong strongResult = iota
	strongOK
	strongThrottled
)

// strongOpts says what a successful strong code does besides being spent.
type strongOpts struct {
	// unlock extends the session unlock to now+unlock (0: no change).
	unlock time.Duration
	// count records a failure as a wrong code.
	count bool
}

// throttled reports whether code checks by text are paused, and until
// when.
func (c *codes) throttled(now time.Time) (bool, time.Time) {
	w := recent(c.st.Wrong, now)
	if len(w) < WrongToThrottle {
		return false, time.Time{}
	}
	return true, w[len(w)-WrongToThrottle].Add(WrongWindow)
}

// matchStrong finds which strong code got is, without changing anything:
// a code-generator step (the current one or the one before, since texts
// arrive late; never at or before the last step accepted) or the
// challenged grid cell. step is 0 for a grid cell.
func (c *codes) matchStrong(got string, now time.Time) (ok bool, step int64, cell string) {
	cur := now.Unix() / totpStep
	if len(c.sec.TOTPSeed) > 0 {
		for _, s := range []int64{cur, cur - 1} {
			if s > c.st.LastStep && eq(got, hotp(c.sec.TOTPSeed, uint64(s))) {
				return true, s, ""
			}
		}
	}
	if c.challenge != "" && !c.gridUsed(c.challenge) && len(c.sec.GridSeed) > 0 &&
		eq(got, GridCell(c.sec.GridSeed, c.challenge)) {
		return true, 0, c.challenge
	}
	return false, 0, ""
}

// checkStrong checks a code-generator code or grid cell. On success the
// code is spent, the low-tier lock lifts, and the session unlock extends if
// o.unlock is set; wrong codes are not forgiven, they age out (CH-18). A
// save failure is a failure. locked reports that this wrong code crossed
// WrongToLock.
func (c *codes) checkStrong(got string, now time.Time, o strongOpts) (res strongResult, locked bool, err error) {
	if t, _ := c.throttled(now); t {
		return strongThrottled, false, nil
	}
	ok, step, cell := c.matchStrong(got, now)
	if !ok {
		if !o.count {
			return strongWrong, false, nil
		}
		locked, err = c.wrong(now)
		return strongWrong, locked, err
	}
	err = c.commit(func(s *State) {
		if cell != "" {
			s.GridUsed = append(s.GridUsed, cell)
		} else {
			s.LastStep = step
		}
		if o.unlock > 0 {
			if t := now.Add(o.unlock); t.After(s.UnlockedUntil) {
				s.UnlockedUntil = t
			}
			s.LowLocked = false
			s.ClearedAt = now
		}
	})
	if err != nil {
		return strongWrong, false, err
	}
	if cell != "" {
		c.challenge = ""
	}
	return strongOK, false, nil
}

// wrong records one wrong code of any kind. locked is true when this one
// crossed WrongToLock: the low tier is off and the session is locked. The
// in-memory state takes the stricter values even if the save fails.
func (c *codes) wrong(now time.Time) (locked bool, err error) {
	err = c.commit(func(s *State) {
		s.Wrong = append(recent(s.Wrong, now), now)
		since := 0
		for _, t := range s.Wrong {
			if t.After(s.ClearedAt) {
				since++
			}
		}
		if since >= WrongToLock && !s.LowLocked {
			s.LowLocked = true
			s.UnlockedUntil = time.Time{}
			locked = true
		}
	})
	if err != nil {
		c.st.Wrong = append(recent(c.st.Wrong, now), now)
		if locked {
			c.st.LowLocked, c.st.UnlockedUntil = true, time.Time{}
		}
	}
	return locked, err
}

// recent keeps the times inside WrongWindow.
func recent(ts []time.Time, now time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if now.Sub(t) < WrongWindow {
			out = append(out, t)
		}
	}
	return out
}

func (c *codes) gridUsed(label string) bool {
	for _, l := range c.st.GridUsed {
		if l == label {
			return true
		}
	}
	return false
}

func (c *codes) unlocked(now time.Time) bool { return now.Before(c.st.UnlockedUntil) }

// lock ends the session unlock (boot on an unknown host, CH-14). Memory is
// locked even if the save fails.
func (c *codes) lock() error {
	err := c.commit(func(s *State) { s.UnlockedUntil = time.Time{} })
	c.st.UnlockedUntil = time.Time{}
	return err
}

// gridChallenge picks an unused cell at random and remembers it. It
// returns "" when the grid is spent.
func (c *codes) gridChallenge() string {
	if len(c.sec.GridSeed) == 0 {
		return ""
	}
	if c.challenge != "" && !c.gridUsed(c.challenge) {
		return c.challenge
	}
	var free []string
	for _, l := range GridLabels() {
		if !c.gridUsed(l) {
			free = append(free, l)
		}
	}
	if len(free) == 0 {
		c.challenge = ""
		return ""
	}
	c.challenge = free[randInt(c.rand, len(free))]
	return c.challenge
}

// textedCode is a fresh low-tier code: 6 random digits (CH-18).
func (c *codes) textedCode() string {
	n := randInt(c.rand, 1_000_000)
	b := []byte("000000")
	for i := 5; i >= 0; i-- {
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b)
}

func randInt(r io.Reader, n int) int {
	v, err := rand.Int(r, big.NewInt(int64(n)))
	if err != nil {
		panic("owner: no system randomness: " + err.Error())
	}
	return int(v.Int64())
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
