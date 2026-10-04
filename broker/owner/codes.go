package owner

import (
	"crypto/subtle"
	"io"
	"math/big"
	"time"

	"crypto/rand"
)

// Code hygiene limits (CH-18).
const (
	// WrongPerRequest wrong replies void a request or a RESUME code.
	WrongPerRequest = 3
	// WrongToLock wrong codes of any kind within WrongWindow lock the low
	// tier and the session.
	WrongToLock = 5
	// WrongToThrottle wrong codes within WrongWindow stop code checks by
	// text until the oldest ages out, which bounds guessing of the
	// 6-digit high-tier codes (assumption O4).
	WrongToThrottle = 10
	WrongWindow     = 24 * time.Hour
)

// codes checks approval codes and keeps their hygiene state. It is not
// safe for concurrent use; Channel serializes access.
type codes struct {
	sec   Secrets
	st    State
	store Store
	rand  io.Reader
	// challenge is the grid cell last asked for; only it is accepted.
	challenge string
}

// strongResult says how a code-generator or grid code was checked.
type strongResult int

const (
	strongWrong strongResult = iota
	strongOK
	strongThrottled
)

// throttled reports whether code checks by text are paused.
func (c *codes) throttled(now time.Time) bool {
	c.prune(now)
	return len(c.st.Wrong) >= WrongToThrottle
}

// checkStrong accepts a code-generator code (current step or one either
// side, never a step at or before the last one accepted) or the value of
// the grid cell last challenged. Success unlocks the session until
// now+unlock and lifts a low-tier lock (CH-14, CH-18). Failure counts as a
// wrong code when count is set.
func (c *codes) checkStrong(code string, now time.Time, unlock time.Duration, count bool) (strongResult, bool, error) {
	if c.throttled(now) {
		return strongThrottled, false, nil
	}
	ok := false
	step := now.Unix() / totpStep
	for _, s := range []int64{step - 1, step, step + 1} {
		if s > c.st.LastStep && len(c.sec.TOTPSeed) > 0 && eq(code, hotp(c.sec.TOTPSeed, uint64(s))) {
			c.st.LastStep = s
			ok = true
			break
		}
	}
	if !ok && c.challenge != "" && !c.gridUsed(c.challenge) && len(c.sec.GridSeed) > 0 && eq(code, GridCell(c.sec.GridSeed, c.challenge)) {
		c.st.GridUsed = append(c.st.GridUsed, c.challenge)
		c.challenge = ""
		ok = true
	}
	if !ok {
		if !count {
			return strongWrong, false, nil
		}
		locked, err := c.wrong(now)
		return strongWrong, locked, err
	}
	if t := now.Add(unlock); t.After(c.st.UnlockedUntil) {
		c.st.UnlockedUntil = t
	}
	c.st.LowLocked = false
	c.st.Wrong = nil
	return strongOK, false, c.store.Save(c.st)
}

// wrong records one wrong code of any kind. locked is true when this one
// crossed WrongToLock: the low tier is now off and the session is locked.
func (c *codes) wrong(now time.Time) (locked bool, err error) {
	c.prune(now)
	c.st.Wrong = append(c.st.Wrong, now)
	if len(c.st.Wrong) >= WrongToLock && !c.st.LowLocked {
		c.st.LowLocked = true
		c.st.UnlockedUntil = time.Time{}
		locked = true
	}
	return locked, c.store.Save(c.st)
}

func (c *codes) prune(now time.Time) {
	keep := c.st.Wrong[:0]
	for _, t := range c.st.Wrong {
		if now.Sub(t) < WrongWindow {
			keep = append(keep, t)
		}
	}
	c.st.Wrong = keep
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

// lock ends the session unlock (boot on an unknown host, CH-14).
func (c *codes) lock() error {
	c.st.UnlockedUntil = time.Time{}
	return c.store.Save(c.st)
}

// gridChallenge picks an unused cell at random and remembers it. It
// returns "" when the grid is spent.
func (c *codes) gridChallenge() string {
	if len(c.sec.GridSeed) == 0 {
		return ""
	}
	if c.challenge != "" {
		return c.challenge
	}
	var free []string
	for _, l := range GridLabels() {
		if !c.gridUsed(l) {
			free = append(free, l)
		}
	}
	if len(free) == 0 {
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
