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
	// WrongToChallenge wrong codes since the last code-generator unlock,
	// within WrongWindow, switch the channel to challenge mode: a code is
	// checked only inside "UNLOCK <challenge> <code>" (or RESUME), with
	// the challenge texted to the owner's number (O4, arbitrator ruling).
	WrongToChallenge = 10
	WrongWindow      = 24 * time.Hour
	// ChallengeBound caps counted challenge attempts per fixed 24-hour
	// window. The window starts at its first attempt and does not slide.
	ChallengeBound = 48
	// ChallengeTTL replaces an unused challenge.
	ChallengeTTL = 30 * time.Minute
	// BadTokensToRotate wrong challenges replace the live one, so guessing
	// the token is not free.
	BadTokensToRotate = 3
)

// codes checks approval codes and owns the durable State. It is not safe
// for concurrent use; Channel serializes access.
//
// Every change to State goes through commit: the change is applied to a
// copy, the copy is saved, and only a saved copy becomes current. So a
// failed save never leaves a step, a cell, or an unlock live in memory that
// a restart would forget (CH-18).
type codes struct {
	sec Secrets
	// verify, when set, checks code-generator codes where the seed is
	// held; sec.TOTPSeed is then not used.
	verify Verifier
	st     State
	store  Store
	rand   io.Reader
	// challenge is the grid cell last asked for; only it is accepted.
	challenge string
	// unlockCh is the current challenge-mode token and its expiry. It is
	// a texted value, so it is never persisted; after a restart the owner
	// asks for a new one.
	unlockCh        string
	unlockChExpires time.Time
	badTokens       int
	// justChallenged is set when a wrong code switched on challenge mode;
	// the channel reads and clears it to tell the owner.
	justChallenged bool
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
)

// strongOpts says what a successful strong code does besides being spent.
type strongOpts struct {
	// unlock extends the session unlock to now+unlock (0: no change).
	unlock time.Duration
	// count records a failure as a wrong code.
	count bool
}

// matchStrong finds which strong code got is: the challenged grid cell, or
// a code-generator step (the current one or the one before, since texts
// arrive late; never at or before the last step accepted). step is 0 for a
// grid cell. Nothing here changes, except that a Verifier spends a step
// that matches. err means the Verifier could not check.
func (c *codes) matchStrong(got string, now time.Time) (ok bool, step int64, cell string, err error) {
	if c.challenge != "" && !c.gridUsed(c.challenge) && len(c.sec.GridSeed) > 0 &&
		eq(got, GridCell(c.sec.GridSeed, c.challenge)) {
		return true, 0, c.challenge, nil
	}
	if c.verify != nil {
		step, ok, err := c.verify.VerifyTOTP(got, c.st.LastStep)
		if err != nil || !ok || step <= c.st.LastStep {
			return false, 0, "", err
		}
		return true, step, "", nil
	}
	cur := now.Unix() / totpStep
	if len(c.sec.TOTPSeed) > 0 {
		for _, s := range []int64{cur, cur - 1} {
			if s > c.st.LastStep && eq(got, hotp(c.sec.TOTPSeed, uint64(s))) {
				return true, s, "", nil
			}
		}
	}
	return false, 0, "", nil
}

// checkStrong checks a code-generator code or grid cell. On success the
// code is spent, the low-tier lock lifts, and the session unlock extends if
// o.unlock is set; wrong codes are not forgiven, they age out (CH-18). A
// save failure is a failure, and so is a Verifier that could not check;
// neither is counted. locked reports that this wrong code crossed
// WrongToLock.
func (c *codes) checkStrong(got string, now time.Time, o strongOpts) (res strongResult, locked bool, err error) {
	ok, step, cell, err := c.matchStrong(got, now)
	if err != nil {
		return strongWrong, false, err
	}
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
			s.Challenged = false
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
		if since >= WrongToChallenge && !s.Challenged {
			s.Challenged = true
			c.justChallenged = true
		}
	})
	if err != nil {
		c.st.Wrong = append(recent(c.st.Wrong, now), now)
		if locked {
			c.st.LowLocked, c.st.UnlockedUntil = true, time.Time{}
		}
		if c.justChallenged {
			c.st.Challenged = true
		}
	}
	return locked, err
}

// currentChallenge returns the live challenge-mode token, making a new one
// when there is none or it is older than ChallengeTTL.
func (c *codes) currentChallenge(now time.Time) string {
	if c.unlockCh == "" || !now.Before(c.unlockChExpires) {
		c.newChallenge(now)
	}
	return c.unlockCh
}

// newChallenge replaces the token: 4 characters, letters (no I or O) and
// digits 2-9, about 20 bits, single use.
func (c *codes) newChallenge(now time.Time) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 4)
	for i := range b {
		b[i] = alphabet[randInt(c.rand, len(alphabet))]
	}
	c.unlockCh, c.unlockChExpires, c.badTokens = string(b), now.Add(ChallengeTTL), 0
}

// badToken records a message that named a wrong challenge, and replaces
// the live one after BadTokensToRotate of them.
func (c *codes) badToken(now time.Time) {
	c.badTokens++
	if c.badTokens >= BadTokensToRotate {
		c.newChallenge(now)
	}
}

// challengeOK reports whether got is the live token, without spending it.
func (c *codes) challengeOK(got string, now time.Time) bool {
	return c.unlockCh != "" && now.Before(c.unlockChExpires) && eq(got, c.unlockCh)
}

// takeAttempt spends the live token and one attempt of the fixed 24-hour
// bound. It reports false when the bound is used up; the token is spent
// either way, so each challenge allows one attempt.
func (c *codes) takeAttempt(now time.Time) (bool, error) {
	c.unlockCh = ""
	ok := false
	err := c.commit(func(s *State) {
		if s.BoundStart.IsZero() || !now.Before(s.BoundStart.Add(WrongWindow)) {
			s.BoundStart, s.BoundUsed = now, 0
		}
		if s.BoundUsed < ChallengeBound {
			s.BoundUsed++
			ok = true
		}
	})
	return ok && err == nil, err
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
