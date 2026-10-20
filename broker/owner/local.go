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
	// A LocalAlertAt after now (a clock correction) counts as expired, so
	// it cannot hold alerts back until real time catches up (#1442).
	if since := now.Sub(st.LocalAlertAt); c.local.sending || len(st.LocalSignIns)+len(st.LocalAnswers) == 0 ||
		(!st.LocalAlertAt.IsZero() && since >= 0 && since < SignInAlertEvery) {
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

// textAfterReply texts the alerts and the sign-in text after the caller has
// its answer. A send takes up to the modem's 220 s, and the page gives up on
// the call after 10 s, so a send before the reply made the page say nothing
// was decided about a request that was (UX-2wb-1). The note behind the
// sign-in text is saved before this runs, so a send that fails is
// retried by the next Tick; the alerts are best effort: they are lost if the
// send fails or the channel stops first (DrainSends). Batches
// run one after another in call order. Called
// without c.mu.
func (c *Channel) textAfterReply(alerts []string, signIn string, n, m int, now time.Time) {
	if len(alerts) == 0 && signIn == "" {
		return
	}
	if c.inlineSends {
		for _, a := range alerts {
			_ = c.alert(a)
		}
		if signIn != "" {
			c.sendSignIns(signIn, n, m, now)
		}
		return
	}
	done := make(chan struct{})
	c.sendMu.Lock()
	prev := c.sendTail
	c.sendTail = done
	c.sendMu.Unlock()
	c.sends.Add(1)
	go func() {
		defer c.sends.Done()
		defer close(done)
		if prev != nil {
			<-prev
		}
		for _, a := range alerts {
			_ = c.alert(a)
		}
		if signIn != "" {
			c.sendSignIns(signIn, n, m, now)
		}
	}()
}

// SendDrain bounds how long agentosd, on shutdown, waits for texts that
// textAfterReply started (DrainSends); a modem send can take 220 s, so the
// wait is shorter. What is not sent by then is retried after the restart
// only where a note is saved (the sign-in text); alerts are lost, as a
// crash would lose them.
const SendDrain = 30 * time.Second

// DrainSends waits up to d for the texts textAfterReply started, returning
// as soon as none is in flight, so a stop does not drop a sign-in or answer
// alert the modem was about to send. agentosd calls it on shutdown once the
// page socket refuses new calls and those in flight have returned, so no
// new text starts during it, while the owner socket still serves the modem
// bridge's outbox, and before the process exits (O34). live, if set, says
// whether anything is still there to send them (modemlink.Link.Bridged):
// once it says no, at the start or any drainTick after, the drain ends
// rather than wait out d for a bridge that has gone.
func (c *Channel) DrainSends(d time.Duration, live func() bool) {
	done := make(chan struct{})
	go func() { c.sends.Wait(); close(done) }()
	t := time.NewTimer(d)
	defer t.Stop()
	var tick <-chan time.Time
	if live != nil {
		if !live() {
			return
		}
		tk := time.NewTicker(drainTick)
		defer tk.Stop()
		tick = tk.C
	}
	for {
		select {
		case <-done:
			return
		case <-t.C:
			return
		case <-tick:
			if !live() {
				return
			}
		}
	}
}

// drainTick is how often DrainSends asks live.
const drainTick = 50 * time.Millisecond

// WaitSends returns once every text started by textAfterReply has finished.
func (c *Channel) WaitSends() { c.sends.Wait() }

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
		out = append(out, "A wrong code was entered on my Wi-Fi at "+c.clock(now)+". Not you? Text STOP. More wrong tries today go in the digest.")
	}
	if st.LocalUsed >= LocalBound {
		out = append(out, fmt.Sprintf("Sign-in on my Wi-Fi is paused until %s after %d tries. Not you? Text STOP.",
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
	s := fmt.Sprintf("%d wrong codes entered on my Wi-Fi: %s.", len(c.local.wrong), c.clockList(c.local.wrong, 20))
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
	// LocalLeft is how many local tries the day's bound has left. Only a
	// signed-in page may show it (Security D1 on P2-2w).
	LocalLeft int
	// LocalReset is when the spent bound resets, as the owner's texts show
	// times ("14:05"); "" while tries are left.
	LocalReset string
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
		LocalLeft:     c.localLeftLocked(now),
		LocalReset:    c.localResetLocked(now),
	}
}

// localResetLocked is the spent bound's fixed reset time, or "". Tries
// past the bound are refused unchecked and never move it (takeLocalLocked).
func (c *Channel) localResetLocked(now time.Time) string {
	if c.localLeftLocked(now) > 0 {
		return ""
	}
	return c.clock(c.codes.st.LocalStart.Add(WrongWindow))
}

// localLeftLocked is what the local bound has left at now.
func (c *Channel) localLeftLocked(now time.Time) int {
	st := c.codes.st
	if st.LocalStart.IsZero() || !now.Before(st.LocalStart.Add(WrongWindow)) {
		return LocalBound
	}
	return max(LocalBound-st.LocalUsed, 0)
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
//
// locks is the session-lock count (LocalStatus.Locks) the code was accepted
// under, read in the same critical section: the texts go out after it, and
// a lock meanwhile must not be credited to this sign-in (SR3-1). The caller
// binds its session to locks and passes it to LocalResume.
func (c *Channel) LocalSignIn(code string) (until time.Time, locks uint64, err error) {
	now := c.cfg.Now()
	c.mu.Lock()
	ok, err := c.takeLocalLocked(now)
	if err != nil || !ok {
		c.mu.Unlock()
		if err == nil {
			err = ErrTooMany
		}
		return time.Time{}, 0, err
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
		until, locks = c.codes.st.UnlockedUntil, c.codes.st.Locks
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
	c.textAfterReply(alerts, signIn, signIns, answers, now)
	switch {
	case err != nil:
		return time.Time{}, 0, err
	case res != strongOK:
		return time.Time{}, 0, ErrWrongCode
	}
	return until, locks, nil
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
		alerts = append(alerts, fmt.Sprintf("%d wrong codes, the last on my Wi-Fi. Texted codes are off and the session is locked until you send a code-generator code.", WrongToLock))
	}
	if c.codes.justChallenged {
		c.codes.justChallenged = false
		c.floods.challenge++ // for the digest, as floodLocked counts it (L3 N2 on #165)
		c.held = nil
		c.alertAt = now
		alerts = append(alerts, fmt.Sprintf("Too many wrong codes, the last on my Wi-Fi. Codes by text now need a challenge: reply UNLOCK %s and a code from your code generator within %s.",
			c.codes.currentChallenge(now), dur(ChallengeTTL)))
	}
	return alerts
}

// StopGen counts STOPs from every channel. A local RESUME reads it when
// the request arrives and commits only if it has not moved.
func (c *Channel) StopGen() int64 { return c.stops.Load() }

// LocalStop is STOP from the local UI. Like STOP by text it needs no code,
// since its worst case is a pause (CH-3).
func (c *Channel) LocalStop(ctx context.Context) error {
	// Like stopNow it never waits on mu behind a code check (CH-2); the
	// count voids an issued RESUME code, so c.resume needs no clearing.
	// One STOP generation for both channels (CH-2): counted with the
	// stop under stopMu, so a RESUME that began earlier cannot undo it.
	// The texted STOP's own path, so neither reports done on an earlier
	// STOP's record.
	c.stopMu.Lock()
	c.stops.Add(1)
	_, err := c.ctrl.Stop(ctx)
	c.stopMu.Unlock()
	return err
}

// ErrLocked: the session was locked since the sign-in a local op rests on.
var ErrLocked = errors.New("owner: session locked since sign-in")

// LocalResume is RESUME from a signed-in local device (P1-5 carry-forward).
// The caller must have checked the sign-in; it is a stronger proof than the
// texted code CH-11 asks for, so no further code is needed. locks is the
// count that sign-in returned: any session lock since refuses with
// ErrLocked, checked where the resume commits (SR3-1). A texted RESUME
// code issued earlier is voided. gen is StopGen as read when the request
// arrived: a STOP since, by any channel, wins (CH-2).
func (c *Channel) LocalResume(locks uint64, gen int64) (string, error) {
	// c.mu spans the resume and the fresh windows, so no release slips
	// between them (L3 on #76), as on the text path.
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.codes.st.Locks != locks {
		return "", ErrLocked
	}
	c.resume = nil
	if !c.cfg.Engine.Stopped() {
		return "Not stopped. Nothing to resume.", nil
	}
	switch err := c.resumeUnlessStopped(gen); {
	case err == errStoppedMeanwhile:
		return stoppedMeanwhile, nil
	case err != nil:
		return "", fmt.Errorf("owner: resume failed to record, still stopped: %w", err)
	}
	return "Resumed. Stopped actions may now run." + c.rewindowLocked(c.cfg.Now()), nil
}

// alert texts the owner a broker template, if a modem is attached. It is
// a security text, never held (CH-15).
func (c *Channel) alert(text string) error {
	if c.cfg.Modem == nil {
		return nil
	}
	// A broker template, so not through Disclose (CH-19).
	return c.postTemplate(ClassSecurity, text)
}

// TOTP is the code-generator code for seed at t (RFC 6238, SHA-1, 30 s, 6
// digits), for the local UI's enrollment check (§8.1 step 5).
func TOTP(seed []byte, t time.Time) string { return totpAt(seed, t.Unix()) }

// UnlockPeriod is CH-14's N, for the local UI's remembered sign-in.
func (c *Channel) UnlockPeriod() time.Duration { return c.cfg.UnlockFor }

// LocalStatusLines is STATUS's text with every note, the page-only
// requests' line first, for a signed-in local page (Potency R3). The
// texted STATUS leaves out notes that do not fit one reply and counts them.
func (c *Channel) LocalStatusLines() string { return c.ctrl.Status() }

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
		// With its ID (UX U-2A-2), and any failed withdrawal kept.
		note, msg = "Denied "+id, "Denied "+id+"."+strings.TrimPrefix(msg, "Denied "+id+".")
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
	c.textAfterReply(alerts, text, ns, na, now)
	if err != nil {
		return msg, err
	}
	return msg, nil
}
