package owner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
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
	// evictedAns is evicted for page answers (State.LocalAnswers).
	evictedAns int
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
func (c *Channel) signInTextLocked(now time.Time) (string, int, int) {
	st := c.codes.st
	if c.local.sending || len(st.LocalSignIns)+len(st.LocalAnswers) == 0 ||
		(!st.LocalAlertAt.IsZero() && now.Sub(st.LocalAlertAt) < SignInAlertEvery) {
		return "", 0, 0
	}
	c.local.sending, c.local.evicted, c.local.evictedAns = true, 0, 0
	n, m := len(st.LocalSignIns), len(st.LocalAnswers)
	var parts []string
	switch {
	case n > 1:
		parts = append(parts, "Phones signed in on my Wi-Fi at "+c.clockList(st.LocalSignIns, 8)+".")
	case n == 1:
		parts = append(parts, "A phone signed in on my Wi-Fi at "+c.clockList(st.LocalSignIns, 8)+".")
	}
	switch {
	case m == 1 && n == 0:
		a := st.LocalAnswers[0]
		parts = append(parts, a.Text+" on my Wi-Fi page at "+c.clock(a.At)+".")
	case m > 0:
		var as []string
		for i, a := range st.LocalAnswers {
			if i == 8 {
				as = append(as, fmt.Sprintf("and %d more", m-8))
				break
			}
			as = append(as, a.Text+" at "+c.clock(a.At))
		}
		parts = append(parts, "On my Wi-Fi page: "+strings.Join(as, ", ")+".")
	}
	return strings.Join(parts, " ") + " Not you? Text STOP.", n, m
}

// sendSignIns texts a sign-in alert from signInTextLocked and, only once it
// is sent, drops the n sign-ins it listed, less any the cap pushed out
// meanwhile, so one recorded during the send stays for the next text. A failed send keeps them for the
// next Tick. Called without c.mu.
func (c *Channel) sendSignIns(text string, n, m int, now time.Time) {
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
		j := max(m-c.local.evictedAns, 0)
		s.LocalAnswers = append([]LocalNote(nil), s.LocalAnswers[j:]...)
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
	t, n, m := c.signInTextLocked(now)
	c.mu.Unlock()
	if t != "" {
		c.sendSignIns(t, n, m, now)
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
	// ErrTextedCode: the page was given the request's texted code. The
	// channel does not count it (L3 S-a on #165); the page counts it for
	// the phone (Security F1 on #171).
	ErrTextedCode = errors.New("That's the code I texted. Here, use a code from your code generator.")
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
	// A refused unlock proof is not a wrong code: it is refused when the
	// vault process has no proof to match (a late redirect, no Verifier),
	// and the vault process counts a wrong one itself (#65 L3 follow-up 1);
	// nor is the owner, who just unlocked, texted about it (#75 L3).
	proof := strings.HasPrefix(code, UnlockProofPrefix)
	res, locked, err := c.codes.checkStrong(code, now, strongOpts{unlock: c.cfg.UnlockFor, count: !proof, proof: true})
	alerts := c.lockAlertsLocked(locked, now)
	signIn, signIns, answers := "", 0, 0
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
			alerts = append(alerts, "A phone signed in on my Wi-Fi at "+c.clock(now)+". Not you? Text STOP.")
		} else {
			c.local.evicted += evicted
		}
		signIn, signIns, answers = c.signInTextLocked(now)
	case err == nil && !proof:
		alerts = append(alerts, c.wrongLocalLocked(now)...)
	}
	c.mu.Unlock()
	for _, a := range alerts {
		c.alert(a)
	}
	if signIn != "" {
		c.sendSignIns(signIn, signIns, answers, now)
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

// lockAlertsLocked returns the texts for a wrong code on the box's Wi-Fi
// that locked the session or switched on challenge mode.
func (c *Channel) lockAlertsLocked(locked bool, now time.Time) []string {
	var alerts []string
	if locked {
		alerts = append(alerts, fmt.Sprintf("%d wrong codes, the last on the box's Wi-Fi. Texted codes are off and the session is locked until you send a code-generator code.", WrongToLock))
	}
	if c.codes.justChallenged {
		c.codes.justChallenged = false
		c.floods.challenge++ // for the digest, as floodLocked counts it (L3 N2 on #165)
		c.held = nil
		c.alertAt = now
		alerts = append(alerts, fmt.Sprintf("Too many wrong codes, the last on the box's Wi-Fi. Codes by text now need a challenge: reply UNLOCK %s and a code from your code generator within %s.",
			c.codes.currentChallenge(now), dur(ChallengeTTL)))
	}
	return alerts
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
	// c.mu spans the resume and the fresh windows, so no release slips
	// between them (L3 on #76), as on the text path.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resume = nil
	if !c.cfg.Engine.Stopped() {
		return "Not stopped. Nothing to resume.", nil
	}
	if err := c.cfg.Engine.Resume(); err != nil {
		return "", fmt.Errorf("owner: resume failed to record, still stopped: %w", err)
	}
	return "Resumed. Stopped actions may now run." + c.rewindowLocked(c.cfg.Now()), nil
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

// LocalAnswer errors: the request is not open, or not as the page showed
// it.
var (
	ErrNoRequest = errors.New("owner: no such open request")
	ErrChanged   = errors.New("owner: the request is not as shown")
)

// LocalNote is a page answer not yet texted to the owner.
type LocalNote struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"` // "Approved K7"
}

// LocalRequest is an open approval request as the local page shows it
// (P2-2a): every field in full, recipients included.
type LocalRequest struct {
	ID      string
	Tier    Tier
	Expires time.Time
	// By is Expires as the owner's texts show it ("14:05").
	By string
	// Local: asked on the page only; it cannot be approved by text.
	Local bool
	Items []Item
	Done  []bool // items already settled
	// Sum digests everything the page shows: each item, which are
	// settled, and the expiry. LocalAnswer takes it back and refuses a
	// request that no longer matches (Security D1).
	Sum string
}

// LocalRequests lists the open requests, oldest first.
func (c *Channel) LocalRequests() []LocalRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	rs := make([]*request, 0, len(c.open))
	for _, r := range c.open {
		rs = append(rs, r)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].n < rs[j].n })
	out := make([]LocalRequest, len(rs))
	for i, r := range rs {
		out[i] = LocalRequest{ID: r.id, Tier: r.tier, Expires: r.expires, By: c.clock(r.expires), Local: r.local,
			Items: append([]Item(nil), r.items...), Done: append([]bool(nil), r.done...), Sum: requestSum(r)}
	}
	return out
}

func requestSum(r *request) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%d|%t", r.id, r.expires.UnixNano(), r.local)
	for i, it := range r.items {
		fmt.Fprintf(h, "|%s|%t", ItemSum(it), r.done[i])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LocalWaiting is STATUS's line for requests only the Wi-Fi page can
// approve (UX A4), or "".
func (c *Channel) LocalWaiting() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.open {
		if r.local {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf("%d waiting for you on my Wi-Fi page.", n)
}

// LocalAnswer approves or denies all open items of a request from the
// local page (P2-2a). sum is the LocalRequest.Sum the page showed: any
// change since refuses with ErrChanged. Approving takes a code-generator
// code (or the asked grid cell) every time, even on a signed-in phone,
// through the same checks as a texted YES, so a code is spent across texts
// and the page alike, and counts against LocalBound; denying needs no
// code. Each answer is texted to the owner, coalesced with local sign-ins
// (UX A6), so a phone left signed in cannot act unseen. On a wrong code the
// reply (tries left, or void) comes back with ErrWrongCode.
func (c *Channel) LocalAnswer(id, sum string, approve bool, code string) (string, error) {
	if approve && code == "" {
		return "", ErrWrongCode
	}
	now := c.cfg.Now()
	c.mu.Lock()
	decided := c.expireLocked(now)
	r := c.open[id]
	if r == nil || requestSum(r) != sum {
		c.mu.Unlock()
		c.decide(decided)
		if r == nil {
			return "", ErrNoRequest
		}
		return "", ErrChanged
	}
	if approve {
		ok, err := c.takeLocalLocked(now)
		if err != nil || !ok {
			c.mu.Unlock()
			c.decide(decided)
			if err == nil {
				err = ErrTooMany
			}
			return "", err
		}
	}
	if approve && !r.local && r.code != "" && eq(code, r.code) {
		// The page takes a code-generator code; the texted one is refused
		// here, not counted as wrong, since a phone offers it from the
		// text (L3 S-a on #165). It still spends a saved try of the day's
		// bound first, like any code, so the hint is no oracle once the
		// bound is spent or while the state cannot be saved (L3 on #171).
		// A page-only request's code is never texted.
		c.mu.Unlock()
		c.decide(decided)
		return "", ErrTextedCode
	}
	rp := reply{word: "NO", id: id}
	if approve {
		rp.word, rp.code = "YES", code
	}
	n := len(decided)
	wasLocked := c.codes.st.LowLocked
	out, _, wrong := c.answerLocked(rp, now, &decided, true)
	msg := strings.Join(out, " ")
	var alerts []string
	var err error
	note := ""
	switch {
	case wrong:
		err = ErrWrongCode
		// A lock or challenge mode this code set off is told like one from
		// a sign-in (L3 S2 on #165).
		alerts = append(c.wrongLocalLocked(now), c.lockAlertsLocked(!wasLocked && c.codes.st.LowLocked, now)...)
		until := c.clock(c.codes.st.LocalStart.Add(WrongWindow))
		switch left := LocalBound - c.codes.st.LocalUsed; {
		case left <= 0:
			msg += " Approving here is paused until " + until + "." // Security R3 on #165
		case left <= 2:
			// Say so before approving here pauses (UX on #165).
			msg += fmt.Sprintf(" %d more %s on my Wi-Fi today, then approving here pauses until %s.",
				left, map[bool]string{true: "try", false: "tries"}[left == 1], until)
		}
		if c.open[id] == nil {
			note = id + " void after wrong codes"
		}
	case len(decided) == n:
		err = errors.New(msg) // nothing settled
	case approve:
		note = "Approved " + id
		// The page's own wording (UX A4); a hold that failed keeps the
		// channel's reply, which says the item did not run (L3 S4).
		ran, some := true, false
		for _, d := range decided[n:] {
			ran = ran && d.Approved
			some = some || d.Approved
		}
		if ran {
			msg = "Approved " + id + ". Your agent can go ahead." + strings.TrimPrefix(msg, "Approved "+id+".")
		} else {
			note += " (it did not run)" // L3 N3 on #165
			if some {
				note = "Approved " + id + " (not all of it ran)" // L3 nit on #171
			}
		}
	default:
		note, msg = "Denied "+id, "Denied "+id+"." // with its ID (UX U-2A-2)
	}
	var text string
	var ns, na int
	if note != "" {
		evicted := 0
		if c.codes.commit(func(s *State) {
			s.LocalAnswers = append(s.LocalAnswers, LocalNote{At: now, Text: note})
			if k := len(s.LocalAnswers) - maxSignIns; k > 0 {
				s.LocalAnswers = append([]LocalNote(nil), s.LocalAnswers[k:]...)
				evicted = k
			}
		}) != nil {
			// Not recorded, so not coalesced either: tell now.
			alerts = append(alerts, note+" on my Wi-Fi page at "+c.clock(now)+". Not you? Text STOP.")
		} else {
			c.local.evictedAns += evicted
		}
		text, ns, na = c.signInTextLocked(now)
	}
	c.mu.Unlock()
	c.decide(decided)
	for _, a := range alerts {
		_ = c.alert(a)
	}
	if text != "" {
		c.sendSignIns(text, ns, na, now)
	}
	if err != nil {
		return msg, err
	}
	return msg, nil
}
