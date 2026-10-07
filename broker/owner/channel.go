// Package owner is the owner channel (SPEC §6.1, PLAN P1-5): the box's own
// number as the conversational address, CH-3's command tiers, two-tier
// approval codes (CH-4, CH-10), batch replies (CH-13), inline session
// unlock (CH-14), code hygiene (CH-18), disclosure filtering (CH-19), and
// queued context-scoped auto-replies with their commitment filter (ADP-11).
//
// Channel sits in front of control.Handler. It owns every word that carries
// or checks a code (RESUME, YES, NO, UNDO, MORE, RUN, and session unlock)
// and passes STOP, STATUS, HELP and task chat to the control handler, which
// asks Channel (as its control.Auth) whether the session is unlocked.
// Nothing here reaches a model, a guest, or the network (ARC-2); the agent
// is reached only through control.Handler's Agent.
package owner

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/journal"
	"github.com/ghbmrk/agentos/broker/modem"
)

// Defaults (CH-10, CH-14, CH-15, REV-3).
const (
	DefaultUnlockFor  = 7 * 24 * time.Hour
	DefaultCodeTTL    = 15 * time.Minute
	DefaultUndoWindow = 10 * time.Minute
	// DefaultReplyLimit caps, per hour, the replies to messages that prove
	// only the owner's number (CH-15): unlock prompts, wrong-code and
	// usage replies, HELP, RESUME code texts. STOP replies, replies that
	// confirm an accepted code, and replies inside an unlocked session are
	// not counted.
	DefaultReplyLimit = 6
	// resumeTextsPerHour caps RESUME code texts (as the skeleton did, B3).
	resumeTextsPerHour = 3
)

// Config configures a Channel.
type Config struct {
	// Owner is the owner's number. Texts from any other number are
	// ignored: never control words, chat, or approvals (CH-3, ADP-12).
	Owner string
	// Modem is the box's SIM. Outbound requests and alerts go through it;
	// Handle works without one.
	Modem  modem.Modem
	Engine control.Engine
	// Agent receives task chat; nil when no agent is running.
	Agent    control.Agent
	Machines func() string
	// Notes are STATUS's exception lines (control.Handler.Notes).
	Notes   []func() string
	Secrets Secrets
	// Verifier, when set, checks code-generator codes in place of
	// Secrets.TOTPSeed, which is then ignored (egress K7).
	Verifier Verifier
	Store    Store
	Limits   Limits
	// Commitments is the owner's phrase list for ADP-11.
	Commitments Commitments
	// UnlockFor is CH-14's N (default 7 days).
	UnlockFor time.Duration
	// CodeTTL bounds texted codes and held messages (default 15 min).
	CodeTTL time.Duration
	// UndoWindow delays queued auto-replies (default 10 min).
	UndoWindow time.Duration
	// ReplyLimit is DefaultReplyLimit when zero.
	ReplyLimit int
	// Location renders times in texts; nil means time.Local.
	Location *time.Location
	Now      func() time.Time
	Rand     io.Reader
	// Decide receives every decision on a requested item, after the
	// channel's lock is released. A decision for an item the caller has
	// already settled (possible after a restart) should be ignored.
	Decide func(Decision)
	// Narrow pauses or revokes a grant or pre-allowance ("PAUSE" or
	// "REVOKE", and its ID) and returns the reply. Like STOP it needs only
	// the owner's number (ADP-9). It runs outside the channel's lock. Nil
	// answers that there are no grants.
	Narrow func(word, id string) string
	// Reissue, if set, takes over the items of requests a restart found
	// open and not expired (Boot), to ask them again with new codes. Boot
	// calls it once, with nil when there are none, after the restart text.
	// Nil: they are cancelled.
	Reissue func([]Carried)
	// Settings answers a whole message that is a box setting (the loop
	// scheduler's Text), before it would go to the agent; HelpExtra is
	// appended to HELP (control.Handler). Nil: no settings.
	Settings  func(ctx context.Context, msg string, unlocked bool) (reply string, ok bool)
	HelpExtra string
	// Narrows reports a setting whose worst case is a pause (LOOPS OFF,
	// a lower budget). In a locked session it runs at once, like a pause
	// word (CH-11), rather than being held for the unlock. It must not
	// call back into the channel.
	Narrows func(msg string) bool
	// Answer takes an owner reply to an agent's question (question.Book
	// .Answer) in an unlocked session, with any code stripped, before it
	// would reach the agent (control.Handler.Answer, W9). Nil: none.
	Answer func(ctx context.Context, msg string) (reply string, ok bool)
}

// Carried is an item of a request open at the last shutdown, handed to
// Config.Reissue. Its old code is dead; Request is the old request's ID.
type Carried struct {
	Ref     string
	Request string
	Asked   time.Time
	Expires time.Time
	Sum     string
}

// Decision is the outcome for one requested item.
type Decision struct {
	Request  string
	Item     int // 1-based
	Ref      string
	Approved bool
	// Why: "owner", "expired", "void" (wrong codes), "not chosen" (left
	// out of a partial YES), "restart" (dropped by a reboot), or "undo"
	// (an auto-reply or held effect the owner cancelled).
	Why string
	// Hold, on an approval, is the UNDO ID the effect is held under until
	// Until (REV-3, CH-16): the caller keeps it from running until
	// DueAutoReplies releases it, and a later decision on Hold (Why "undo"
	// or "restart") cancels it.
	Hold  string
	Until time.Time
	// Page: approved on the box's Wi-Fi page with a fresh strong code,
	// and Sum is ItemSum of the item as the page showed it, so a change
	// that needs the page's confirmation is confirmed by this same
	// answer (Security Q1 and P1 on P2-2a part 2).
	Page bool
	Sum  string
}

// Channel is the owner channel. It implements control.Auth.
type Channel struct {
	cfg  Config
	ctrl *control.Handler

	mu       sync.Mutex
	codes    codes
	open     map[string]*request
	reqN     uint64 // requests opened, for their order
	queued   map[string]*Queued
	released map[string]time.Time // queued IDs released, for UNDO's reply
	lateUndo map[string]bool      // released IDs the owner texted UNDO for
	resume   *resumeCode
	// lineFailed is when the box's line last failed to send (unix nanos
	// of cfg.Now), so a queued reply's silence is not read as the
	// owner's over a line that was down (security B1(a) on PW3).
	lineFailed  atomic.Int64
	resumeTexts []time.Time
	held        *heldMsg
	limited     []time.Time
	active      time.Time // last owner message the control handler ran
	alertAt     time.Time
	// floodAlertAt is the last flood alert; floods counts the events for
	// the digest by kind.
	floodAlertAt time.Time
	floods       floodCounts
	// stops counts STOPs; a RESUME code issued before the latest STOP is
	// void (taken on the fast path, outside mu).
	stops atomic.Int64
	// stopMu orders a fast-path STOP against a RESUME: stopNow holds it
	// across counting and applying the STOP, and resumeUnlessStopped
	// across its re-check and Resume, so a STOP that arrives while a
	// RESUME code is being checked is never lifted by it (CH-2).
	stopMu sync.Mutex
	// challengeTexts are the challenge texts sent in the last hour.
	challengeTexts []time.Time
	dropped        int
	expired        []Decision
	expiredMore    int
	boot           *bootReport
	// local coalesces texts about local UI sign-ins (local.go).
	local localAlerts
}

var _ control.Auth = (*Channel)(nil)

type resumeCode struct {
	code    string // "" when the low tier is locked: a strong code is needed
	stops   int64  // Channel.stops when issued
	expires time.Time
	wrong   int
}

// heldMsg is the one message held while the session is locked (CH-14).
// ready is set when a code-only unlock arrived: the message then runs only
// on RUN, because the code proves the unlock, not who wrote the held text.
type heldMsg struct {
	text    string
	expires time.Time
	ready   bool
}

// New returns a Channel, loading its durable state.
func New(cfg Config) (*Channel, error) {
	if cfg.Owner == "" || cfg.Engine == nil || cfg.Store == nil {
		return nil, errors.New("owner: owner number, engine and store are required")
	}
	if cfg.UnlockFor == 0 {
		cfg.UnlockFor = DefaultUnlockFor
	}
	if cfg.CodeTTL == 0 {
		cfg.CodeTTL = DefaultCodeTTL
	}
	if cfg.UndoWindow == 0 {
		cfg.UndoWindow = DefaultUndoWindow
	}
	if cfg.ReplyLimit == 0 {
		cfg.ReplyLimit = DefaultReplyLimit
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	st, err := cfg.Store.Load()
	if err != nil {
		return nil, err
	}
	c := &Channel{
		cfg:    cfg,
		codes:  codes{sec: cfg.Secrets, verify: cfg.Verifier, st: st, store: cfg.Store, rand: cfg.Rand},
		open:   map[string]*request{},
		queued: map[string]*Queued{}, released: map[string]time.Time{}, lateUndo: map[string]bool{},
		boot: &bootReport{pending: st.Pending, queued: st.Queued},
	}
	if cfg.Modem != nil {
		c.cfg.Modem = watchedLine{Modem: cfg.Modem, c: c}
	}
	c.ctrl = &control.Handler{Engine: cfg.Engine, Auth: c, Agent: cfg.Agent, Machines: cfg.Machines, Notes: append(cfg.Notes[:len(cfg.Notes):len(cfg.Notes)], c.LocalWaiting), Now: cfg.Now,
		Settings: cfg.Settings, HelpExtra: cfg.HelpExtra, Answer: cfg.Answer}
	return c, nil
}

// ApprovalsOpen reports whether an approval request is open, so an
// untagged reply is never taken as a question's answer while the owner
// may mean the request (question Config.ApprovalsOpen, W9).
func (c *Channel) ApprovalsOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open) > 0
}

// IsOwner implements control.Auth (CH-3).
func (c *Channel) IsOwner(from string) bool { return from == c.cfg.Owner }

// SessionUnlocked implements control.Auth (CH-3, CH-14).
func (c *Channel) SessionUnlocked(now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes.unlocked(now)
}

// RequireUnlock ends the session unlock, as after a boot on an unknown host
// (CH-14).
func (c *Channel) RequireUnlock() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.held = nil
	return c.codes.lock()
}

// route is what routeLocked decided for one message.
type route struct {
	replies  []string
	delegate string // text for the control handler
	run      bool   // delegate goes to the control handler
	narrow   *reply // PAUSE or REVOKE, run outside the lock
	// limited: the replies count against ReplyLimit (CH-15).
	limited bool
	// alerts have their own limit (one per AlertEvery) and are not counted
	// against ReplyLimit.
	alerts []string
	at     time.Time
}

// Handle processes one text from number from and returns the texts to send
// back to it.
func (c *Channel) Handle(ctx context.Context, from, text string) []string {
	if out, ok := c.stopNow(ctx, from, text); ok {
		return out
	}
	rt, ok := c.route(from, text)
	if !ok {
		return nil
	}
	return c.finish(ctx, from, rt)
}

// stopNow applies STOP from the owner at once, without mu, so it never
// waits behind a code check in progress or queued (CH-2). A RESUME code
// issued before it is void (stops).
func (c *Channel) stopNow(ctx context.Context, from, text string) ([]string, bool) {
	if !c.IsOwner(from) || control.Parse(text).Word != control.WordStop {
		return nil, false
	}
	c.stopMu.Lock()
	c.stops.Add(1)
	replies := c.ctrl.Handle(ctx, from, text)
	c.stopMu.Unlock()
	var out []string
	for _, r := range replies {
		if r != "" {
			out = append(out, control.Fit(r))
		}
	}
	return out, true
}

// errStoppedMeanwhile reports a RESUME overtaken by a STOP sent while its
// code was being checked.
var errStoppedMeanwhile = errors.New("stopped while the code was checked")

// resumeUnlessStopped lifts STOP only if no STOP arrived since stops was
// gen, checked and applied under stopMu.
func (c *Channel) resumeUnlessStopped(gen int64) error {
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	if c.stops.Load() != gen {
		return errStoppedMeanwhile
	}
	return c.cfg.Engine.Resume()
}

const stoppedMeanwhile = "A STOP arrived while the code was checked, so nothing resumed. Still stopped."

// route makes every decision the channel itself owns, in arrival order.
func (c *Channel) route(from, text string) (route, bool) {
	if !c.IsOwner(from) {
		return route{}, false
	}
	now := c.cfg.Now()
	c.mu.Lock()
	decided := c.expireLocked(now)
	rt := c.routeLocked(text, now, &decided)
	flood := c.floodLocked(now)
	if c.codes.justChallenged {
		c.codes.justChallenged = false
		c.held = nil
		c.alertAt = now
		rt.alerts = append(rt.alerts, fmt.Sprintf("Too many wrong codes. Codes by text now need a challenge: reply UNLOCK %s and a code from your code generator within %s.",
			c.codes.currentChallenge(now), dur(ChallengeTTL))+flood)
	} else if flood != "" {
		rt.alerts = append(rt.alerts, strings.TrimSpace(flood))
	}
	c.mu.Unlock()
	c.decide(decided)
	rt.at = now
	return rt, true
}

// finish runs the control handler if the route calls for it, then fits and
// rate-limits the replies.
func (c *Channel) finish(ctx context.Context, from string, rt route) []string {
	replies := rt.replies
	if rt.run {
		c.mu.Lock()
		c.active = rt.at
		c.mu.Unlock()
		replies = append(replies, c.ctrl.Handle(ctx, from, rt.delegate)...)
	}
	if rt.narrow != nil {
		if c.cfg.Narrow == nil {
			replies = append(replies, "There are no grants to "+strings.ToLower(rt.narrow.word)+".")
		} else {
			replies = append(replies, c.cfg.Narrow(rt.narrow.word, rt.narrow.id))
		}
	}
	var out []string
	for _, r := range replies {
		if r != "" {
			out = append(out, control.Fit(r))
		}
	}
	if rt.limited {
		out = c.limit(out, rt.at)
	}
	for _, a := range rt.alerts {
		out = append(out, control.Fit(a))
	}
	return out
}

// limit drops replies beyond ReplyLimit in the last hour (CH-15).
func (c *Channel) limit(out []string, now time.Time) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := c.limited[:0]
	for _, t := range c.limited {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	c.limited = keep
	var sent []string
	for _, r := range out {
		if len(c.limited) >= c.cfg.ReplyLimit {
			break
		}
		c.limited = append(c.limited, now)
		sent = append(sent, r)
	}
	return sent
}

// routeLocked answers the channel's own words and decides what reaches the
// control handler.
func (c *Channel) routeLocked(text string, now time.Time, decided *[]Decision) route {
	if c.codes.st.Challenged {
		if rt, ok := c.challengeLocked(text, now); ok {
			return rt
		}
	}
	unlocked := c.codes.unlocked(now)
	if r, ok := parseReply(text); ok {
		switch r.word {
		case "RESUME":
			out, accepted := c.resumeLocked(r, now)
			return route{replies: out, limited: !accepted}
		case "UNDO":
			return route{replies: []string{c.undoLocked(r.id, now, decided)}, limited: !unlocked}
		case "PAUSE", "REVOKE":
			return route{narrow: &r, limited: !unlocked}
		case "MORE":
			return route{replies: []string{c.moreLocked(r.id)}, limited: !unlocked}
		case "UNLOCK":
			return route{replies: []string{"Codes are not locked. To unlock a session, send a code from your code generator."}, limited: !unlocked}
		case "RUN":
			if h := c.held; h != nil && h.ready && unlocked {
				c.held = nil
				return route{delegate: h.text, run: true}
			}
			return route{replies: []string{"Nothing is held."}, limited: !unlocked}
		default: // YES, NO
			if len(c.open) > 0 || r.id != "" {
				out, accepted, wrong := c.answerLocked(r, now, decided, false)
				return route{replies: out, limited: !accepted && (wrong || !unlocked)}
			}
			if r.word == "YES" && r.code == "" && len(r.items) == 0 {
				break // a bare "yes" with nothing open is chat
			}
			return route{replies: []string{"No open requests."}, limited: !unlocked}
		}
	}
	switch control.Parse(text).Word {
	case control.WordStop:
		c.resume = nil // a code issued before STOP must not lift it
		return route{delegate: text, run: true}
	case control.WordHelp, control.WordYes, control.WordNo, control.WordUndo,
		control.WordMore, control.WordResume, control.WordUnclear:
		return route{delegate: text, run: true, limited: !unlocked}
	}
	if !unlocked && c.cfg.Narrows != nil && c.cfg.Narrows(text) {
		return route{delegate: text, run: true, limited: true}
	}
	rest, code := splitCode(text)
	if unlocked {
		return c.unlockedChatLocked(text, rest, code, now)
	}
	return c.lockedLocked(rest, code, now)
}

// splitCode finds a code that is the whole message or a separate trailing
// token of exactly 6 digits (CH-14). rest is the message without it.
func splitCode(text string) (rest, code string) {
	if f := fields(text); len(f) == 1 && isCode(f[0]) {
		return "", f[0]
	}
	if r, c, ok := trailingCode(text); ok && r != "" {
		return r, c
	}
	return text, ""
}

// unlockedChatLocked passes chat on. A code in it is checked silently: it
// is not counted when wrong and never extends the unlock, so a spoofer gets
// nothing from guessing, but a matching code is spent and stripped before
// the agent sees it (O5).
func (c *Channel) unlockedChatLocked(text, rest, code string, now time.Time) route {
	if code != "" {
		res, _, err := c.codes.checkStrong(code, now, strongOpts{silent: true})
		if err == nil && res == strongOK {
			if rest == "" {
				return route{replies: []string{"You are already unlocked until " + c.untilText() + "."}}
			}
			return route{delegate: rest, run: true}
		}
		// Otherwise the chat passes on as sent. If the vault's bound on
		// silent checks is full, that includes the code (route raises
		// the flood alert); counted codes still work.
	}
	return route{delegate: text, run: true}
}

// lockedLocked handles STATUS and chat while the session is locked: a code
// unlocks; a message is held, one at a time (CH-3, CH-14).
func (c *Channel) lockedLocked(rest, code string, now time.Time) route {
	if code == "" {
		if c.held != nil {
			c.held = nil
			return route{replies: []string{"Locked. A message was already waiting, so both were dropped. " +
				"Send your message with a code from your code generator at the end."}, limited: true}
		}
		c.held = &heldMsg{text: rest, expires: now.Add(c.cfg.CodeTTL)}
		return route{replies: []string{fmt.Sprintf("Locked. Your message is held for %s. %s",
			dur(c.cfg.CodeTTL), c.unlockPrompt())}, limited: true}
	}
	res, locked, err := c.codes.checkStrong(code, now, strongOpts{unlock: c.cfg.UnlockFor, count: true})
	switch {
	case err != nil:
		return route{replies: []string{c.codeErr(err)}, limited: true}
	case res == strongWrong:
		dropped := ""
		if c.held != nil || rest != "" {
			dropped = "Your message was dropped. "
		}
		c.held = nil
		return route{replies: []string{"Wrong code. " + dropped + c.unlockPrompt() + lockNote(locked)}, limited: true}
	}
	msg := "Unlocked until " + c.untilText() + "."
	if rest != "" {
		// The code came with this message, so this message is the
		// owner's: it runs. Anything held earlier is dropped.
		c.held = nil
		return route{replies: []string{msg}, delegate: rest, run: true}
	}
	if h := c.held; h != nil && now.Before(h.expires) {
		h.ready = true
		h.expires = now.Add(c.cfg.CodeTTL)
		return route{replies: []string{fmt.Sprintf("%s Held: \"%s\". Reply RUN to send it.", msg, field(h.text, 40))}}
	}
	c.held = nil
	return route{replies: []string{msg}}
}

// AlertEvery is the least time between two challenge-mode alerts by text;
// the rest go to the digest (O4).
const AlertEvery = time.Hour

// challengeLocked handles challenge mode (O4, arbitrator ruling). A code
// counts only in "UNLOCK <token> <code>" or "RESUME <token> <code>", with
// the token texted to the owner's number: single use, replaced after each
// attempt or ChallengeTTL, and attempts are capped at ChallengeBound per
// fixed 24-hour window. Any other message carrying a code is dropped
// silently: not counted, nothing consumed, no reply (an alert at most once
// per AlertEvery, and a digest count). ok is false for messages without a
// code, which route as usual.
func (c *Channel) challengeLocked(text string, now time.Time) (route, bool) {
	r, isReply := parseReply(text)
	if isReply && (r.word == "UNLOCK" || r.word == "RESUME") {
		if r.word == "RESUME" && !c.cfg.Engine.Stopped() {
			return route{replies: []string{"Not stopped. Nothing to resume."}, limited: true}, true
		}
		if r.token == "" && r.code == "" {
			return c.challengeText(now, fmt.Sprintf("Codes are locked after too many wrong ones. Reply %s %s and a code from your code generator within %s.",
				r.word, c.codes.currentChallenge(now), dur(ChallengeTTL))), true
		}
		if r.token == "" || !c.codes.challengeOK(r.token, now) {
			if r.token != "" {
				c.codes.badToken(now)
			}
			return c.dropLocked(now), true
		}
		token, expires := c.codes.unlockCh, c.codes.unlockChExpires
		gen := c.stops.Load()
		ok, err := c.codes.takeAttempt(now)
		switch {
		case err != nil:
			return route{replies: []string{stateErr}, limited: true}, true
		case !ok:
			return c.dropLocked(now), true
		}
		res, _, err := c.codes.checkStrong(r.code, now, strongOpts{unlock: c.cfg.UnlockFor})
		if err != nil {
			var ve *VerifyError
			if errors.As(err, &ve) {
				// The vault never checked it: keep the token and the
				// attempt. A failed refund leaves the attempt spent.
				c.codes.refundAttempt(token, expires)
			}
			return route{replies: []string{c.codeErr(err)}, limited: true}, true
		}
		if res != strongOK {
			return c.challengeText(now, fmt.Sprintf("Wrong code. New challenge: reply %s %s and a code from your code generator.",
				r.word, c.codes.currentChallenge(now))), true
		}
		c.held = nil
		msg := "Unlocked until " + c.untilText() + ". Codes work normally again."
		if r.word == "RESUME" {
			c.resume = nil
			switch err := c.resumeUnlessStopped(gen); {
			case err == errStoppedMeanwhile:
				return route{replies: []string{msg + " " + stoppedMeanwhile}}, true
			case err != nil:
				return route{replies: []string{msg + " RESUME failed to record. Still stopped."}}, true
			}
			msg += " Resumed." + c.rewindowLocked(now)
		}
		return route{replies: []string{msg}}, true
	}
	if isReply && r.code != "" {
		return c.dropLocked(now), true
	}
	if _, code := splitCode(text); code != "" {
		return c.dropLocked(now), true
	}
	return route{}, false
}

// challengeTextsPerHour is the challenge texts' own limit, apart from
// ReplyLimit, so a spoofer's bare UNLOCK texts cannot use up the shared
// budget and leave the owner without a challenge after a typo.
const challengeTextsPerHour = 4

func (c *Channel) challengeText(now time.Time, text string) route {
	c.challengeTexts = since(c.challengeTexts, now.Add(-time.Hour))
	if len(c.challengeTexts) >= challengeTextsPerHour {
		return route{}
	}
	c.challengeTexts = append(c.challengeTexts, now)
	return route{replies: []string{text}}
}

// dropLocked ignores a code-bearing message in challenge mode.
func (c *Channel) dropLocked(now time.Time) route {
	c.dropped++
	if !c.alertAt.IsZero() && now.Sub(c.alertAt) < AlertEvery {
		return route{}
	}
	c.alertAt = now
	return route{alerts: []string{"Codes without the current challenge are being ignored. Reply UNLOCK for a one-time challenge."}}
}

// FloodAlertEvery is the least time between two flood alerts by text; every
// flood event also goes in the digest (arbitrator, P2-4c).
const FloodAlertEvery = 24 * time.Hour

// floodCounts are the flood events since the last digest.
type floodCounts struct{ silent, counted, challenge int }

// floodLocked records what the last code check showed: the vault's bound
// on silent checks full, its bound on counted checks full, or challenge
// mode switched on. Each is a sign someone may be texting as the owner. It
// returns the flood alert, with a leading space, at most once per
// FloodAlertEvery, and "" otherwise.
func (c *Channel) floodLocked(now time.Time) string {
	k := &c.codes
	if !k.pausedSilent && !k.pausedCounted && !k.justChallenged {
		return ""
	}
	if k.pausedSilent {
		c.floods.silent++
	}
	if k.pausedCounted {
		c.floods.counted++
	}
	if k.justChallenged {
		c.floods.challenge++
	}
	silent, until := k.pausedSilent, k.pausedUntil
	k.pausedSilent, k.pausedCounted = false, false
	if !c.floodAlertAt.IsZero() && now.Sub(c.floodAlertAt) < FloodAlertEvery {
		return ""
	}
	c.floodAlertAt = now
	msg := " Many wrong codes have come from your number. If they were not yours, someone may be texting as you: reply STOP."
	if silent {
		msg += " Codes in chat pass on unchecked until " + until.In(c.cfg.Location).Format("15:04") + "."
	}
	return msg
}

// TakeDigestNotes returns and clears owner-channel lines for the next
// digest (O4).
func (c *Channel) TakeDigestNotes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	if c.dropped > 0 {
		out = append(out, fmt.Sprintf("%d code messages without the current challenge were ignored.", c.dropped))
		c.dropped = 0
	}
	if f := c.floods; f != (floodCounts{}) {
		var parts []string
		if f.silent > 0 {
			parts = append(parts, fmt.Sprintf("%d texts with a code passed on unchecked", f.silent))
		}
		if f.counted > 0 {
			parts = append(parts, fmt.Sprintf("%d codes refused at the vault's limit", f.counted))
		}
		if f.challenge > 0 {
			parts = append(parts, fmt.Sprintf("challenge mode switched on %d times", f.challenge))
		}
		out = append(out, "Possible code flood: "+strings.Join(parts, ", ")+".")
		c.floods = floodCounts{}
	}
	return append(out, c.takeLocalNotesLocked()...)
}

const stateErr = "Could not save the code check, so it did not count. Try again."

// codeErr is the reply when a code could not be checked or saved. Each
// vault-process failure gets its own fixed wording, since retrying helps
// only in some of them (CH-18).
func (c *Channel) codeErr(err error) string {
	var ve *VerifyError
	if !errors.As(err, &ve) {
		return stateErr
	}
	switch ve.Kind {
	case VaultLocked:
		return "The vault is locked, so the code could not be checked and did not count. Unlock the vault first."
	case VerifyPaused:
		return "Too many wrong codes reached the vault. Code checks are paused until " +
			ve.Until.In(c.cfg.Location).Format("15:04") + ". This code did not count."
	case VerifyLost:
		return "The vault did not answer in time and may have used that code. It did not count. Try again with the next code."
	}
	return "The vault is not answering, so the code was not checked and did not count. Try again shortly."
}

func (c *Channel) untilText() string {
	return c.codes.st.UnlockedUntil.In(c.cfg.Location).Format("Jan 2 15:04")
}

// unlockPrompt asks for a high-tier code; a texted code never unlocks a
// session (CH-14, CH-19).
func (c *Channel) unlockPrompt() string {
	if c.codes.st.Challenged {
		return "Codes are locked after too many wrong ones; reply UNLOCK for a one-time challenge."
	}
	return "Send a code from your code generator" + c.gridOr() + "."
}

func (c *Channel) gridOr() string {
	if cell := c.codes.gridChallenge(); cell != "" {
		return ", or grid cell " + cell
	}
	return ""
}

// lockNote tells the owner that wrong codes locked the low tier (CH-18).
func lockNote(locked bool) string {
	if !locked {
		return ""
	}
	return fmt.Sprintf(" %d wrong codes: texted codes are off and the session is locked until you send a code-generator code.", WrongToLock)
}

// resumeLocked lifts STOP with a low-tier texted code (CH-11), or a
// code-generator code while the low tier is locked (CH-18). accepted is
// true when a code was accepted.
func (c *Channel) resumeLocked(r reply, now time.Time) (out []string, accepted bool) {
	if !c.cfg.Engine.Stopped() {
		c.resume = nil
		return []string{"Not stopped. Nothing to resume."}, false
	}
	if r.code == "" {
		if p := c.resume; p == nil || !now.Before(p.expires) || p.stops != c.stops.Load() {
			c.resume = &resumeCode{expires: now.Add(c.cfg.CodeTTL), stops: c.stops.Load()}
			if !c.codes.st.LowLocked {
				c.resume.code = c.codes.textedCode()
			}
		}
		c.resumeTexts = since(c.resumeTexts, now.Add(-time.Hour))
		if len(c.resumeTexts) >= resumeTextsPerHour {
			return nil, false
		}
		c.resumeTexts = append(c.resumeTexts, now)
		if c.resume.code == "" {
			return []string{"To restart all actions, reply RESUME and a code from your code generator" + c.gridOr() + "."}, false
		}
		return []string{fmt.Sprintf("To restart all actions, reply RESUME %s within %s.", c.resume.code, dur(c.resume.expires.Sub(now)))}, false
	}
	p := c.resume
	if p == nil || !now.Before(p.expires) || p.stops != c.stops.Load() {
		c.resume = nil
		return []string{"No valid code. Reply RESUME for a new one."}, false
	}
	ok, locked, msg := c.checkLocked(p.code, r.code, now)
	if msg != "" {
		return []string{msg}, false
	}
	if !ok {
		p.wrong++
		if p.wrong >= WrongPerRequest {
			c.resume = nil
			return []string{"Wrong code 3 times; it is void. Reply RESUME for a new one." + lockNote(locked)}, false
		}
		return []string{"Wrong code. Reply RESUME <code>." + lockNote(locked)}, false
	}
	c.resume = nil
	switch err := c.resumeUnlessStopped(p.stops); {
	case err == errStoppedMeanwhile:
		return []string{stoppedMeanwhile}, true
	case err != nil:
		return []string{"RESUME failed to record. Still stopped."}, true
	}
	n := 0
	for _, s := range c.cfg.Engine.List() {
		if s.State == journal.Authorized || s.State == journal.NotApplied {
			n++
		}
	}
	text := "Resumed."
	switch {
	case n == 1:
		text = "Resumed. 1 stopped action may now run."
	case n > 1:
		text = fmt.Sprintf("Resumed. %d stopped actions may now run.", n)
	}
	return []string{text + c.rewindowLocked(now)}, true
}

// checkLocked checks a reply code against a texted code, or against the
// code generator and grid when texted is "" or the low tier is locked. A
// strong code also extends the session unlock. msg is set when no check
// could run.
func (c *Channel) checkLocked(texted, got string, now time.Time) (ok, locked bool, msg string) {
	if texted == "" || c.codes.st.LowLocked {
		res, locked, err := c.codes.checkStrong(got, now, strongOpts{unlock: c.cfg.UnlockFor, count: true})
		switch {
		case err != nil:
			return false, false, c.codeErr(err)
		}
		return res == strongOK, locked, ""
	}
	if eq(got, texted) {
		return true, false, ""
	}
	locked, err := c.codes.wrong(now)
	if err != nil {
		return false, locked, stateErr
	}
	return false, locked, ""
}

func since(ts []time.Time, cut time.Time) []time.Time {
	var out []time.Time
	for _, t := range ts {
		if t.After(cut) {
			out = append(out, t)
		}
	}
	return out
}

// Active reports whether the owner sent a message the control handler
// ran (task chat, STATUS) within the last d: the owner is at their phone,
// so an approval request need not wait for its batch (CH-15).
func (c *Channel) Active(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.active.IsZero() && c.cfg.Now().Sub(c.active) < d
}

// LastActive is when the owner last sent a message the control handler
// ran (task chat, STATUS, a setting); zero if never. The sleeper reads it
// for the agent's idle time (PE7).
func (c *Channel) LastActive() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active
}

// UndoOpen reports a queued auto-reply or an approved effect held for its
// undo window (or kept past it by STOP): the sleeper does not stop the
// agent then (PE7 condition 2).
func (c *Channel) UndoOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.queued) > 0
}

// AgentPrefix starts every text Notify sends, so agent-written text can
// never pass for one of the broker's own templates (an approval request,
// a code prompt).
const AgentPrefix = "Agent: "

// Notify texts the owner content that did not come from the broker's own
// templates, such as an agent's answer, behind AgentPrefix. Secret-shaped
// content becomes a pointer to the local UI (CH-19).
func (c *Channel) Notify(text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	if text = Disclose(text); text != Hidden {
		text = AgentPrefix + text
	}
	return c.cfg.Modem.Send(c.cfg.Owner, control.Fit(text))
}

// Inform texts the owner one of the broker's own fixed-wording notices
// (a grant added, an action waiting on the local page). Callers never
// pass agent text: that goes through Notify. Secret-shaped content still
// becomes a pointer (CH-19).
func (c *Channel) Inform(text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	return c.cfg.Modem.Send(c.cfg.Owner, control.Fit(Disclose(text)))
}

// InformContext is Inform with a cancellable transport wait. It accepts only
// broker-owned fixed wording, applies the same disclosure and size filters,
// and refuses a modem without context support rather than invoking Send.
// It does not provide complete multi-line digest delivery: Fit may truncate.
func (c *Channel) InformContext(ctx context.Context, text string) error {
	if ctx == nil {
		return ErrContextSendRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	sender, ok := c.cfg.Modem.(ContextSender)
	if !ok {
		return ErrContextSendUnsupported
	}
	return sender.SendContext(ctx, c.cfg.Owner, control.Fit(Disclose(text)))
}

// Run serves the modem until ctx is done. It first reports what a restart
// dropped (Boot). STOP is applied as soon as it is read, ahead of anything
// queued (stopNow). The channel's other decisions run in arrival order on
// one worker, which may wait on a code check; the control handler's part
// (task chat waits on the agent for up to control.DeliverTimeout) runs on
// its own goroutine, so a slow agent never delays a STOP behind it (CH-2,
// B11).
func (c *Channel) Run(ctx context.Context) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	c.Boot()
	var wg sync.WaitGroup
	defer wg.Wait()
	send := func(to string, rs []string) {
		for _, r := range rs {
			if c.cfg.Modem.Send(to, r) != nil {
				return
			}
		}
	}
	work := make(chan modem.SMS, 256)
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				c.Tick()
			case m := <-work:
				rt, ok := c.route(m.From, m.Text)
				if !ok {
					continue
				}
				if !rt.run {
					send(m.From, c.finish(ctx, m.From, rt))
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					send(m.From, c.finish(ctx, m.From, rt))
				}()
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m := <-c.cfg.Modem.Inbox():
			if m.Alphanumeric {
				continue // a sender ID, not a number: never the owner
			}
			if out, ok := c.stopNow(ctx, m.From, m.Text); ok {
				send(m.From, out)
				continue
			}
			select {
			case work <- m:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
