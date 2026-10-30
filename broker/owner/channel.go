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
	"unicode"

	"github.com/ghbmrk/agentos/broker/boxname"
	"github.com/ghbmrk/agentos/broker/control"
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
	// Retry lists the effects the digest named as unclear and not retried
	// (OP-2), as items to ask about when the owner texts RETRY. Each
	// item's Ref comes back in Decide; the caller retries only an
	// approved one. An error is a part of the box whose waiting effects
	// could not be read; the items are the rest, and RETRY says so
	// rather than "Nothing to retry." (KRN-7). Nil: nothing to retry.
	Retry func() ([]Item, error)
	// OwnerName is the owner's own name, "" when unknown; the box's name
	// may not be it (CH-21).
	OwnerName string
	// AfterFunc runs f once d has passed on the clock Now reads, and
	// returns what stops it; the acknowledgement (OWN-4) waits on it. Nil
	// is time.AfterFunc.
	AfterFunc func(d time.Duration, f func()) (stop func() bool)
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
	// Allowed, on an approval of an item with an Act, says the checker
	// holds an allowed approval for it (a low-tier texted YES or a grid
	// cell, AllowActs) rather than a code-generator code's: it serves an
	// irreversible act but no secret one (ADP-9).
	Allowed bool
}

// Channel is the owner channel. It implements control.Auth.
type Channel struct {
	cfg  Config
	ctrl *control.Handler

	mu          holdMutex
	sends       sync.WaitGroup // texts started after a local reply (textAfterReply)
	inlineSends bool           // tests: textAfterReply sends before returning
	sendTail    chan struct{}  // closed when the latest textAfterReply batch finishes; keeps batches in order
	sendMu      sync.Mutex     // guards sendTail
	codes       codes
	open        map[string]*request
	reqN        uint64 // requests opened, for their order
	retireErr   error  // a retirement not yet saved (retireLocked)
	queued      map[string]*Queued
	released    map[string]time.Time // queued IDs released, for UNDO's reply
	lateUndo    map[string]bool      // released IDs the owner texted UNDO for
	// undo takes an UNDO whose ID the channel does not hold (SetUndo).
	undo atomic.Pointer[UndoHook]
	// current confirms a held text's subjects at send (SetCurrent).
	current atomic.Pointer[CurrentHook]
	// keeper keeps withheld text for the owner page (SetKeeper, keep.go).
	keeper atomic.Pointer[Keeper]
	resume *resumeCode
	// lineFailed is when the box's line last failed to send (unix nanos
	// of cfg.Now), so a queued reply's silence is not read as the
	// owner's over a line that was down (security B1(a) on PW3).
	lineFailed  atomic.Int64
	resumeTexts []time.Time
	held        *heldMsg
	recent      recentWindow // texts to the owner a reaction may mark (CH-11)
	// sinceOwner are the agent texts checkAgent let through since the
	// owner's last message, oldest first, at most maxSinceOwner: the
	// CH-19 and CH-21 checks run on each new one joined to them (CH-12).
	// agentMu guards it, so a text is checked and added in one step.
	agentMu    sync.Mutex
	sinceOwner []string
	// reactMu orders a reaction event's delivery against ForgetRecent: an
	// event is checked and delivered under its read lock, and a deletion
	// clears the window under its write lock (CAP-3). It is taken before mu.
	reactMu sync.RWMutex
	rename  *renameReq // a NAME waiting for its code (name.go)
	limited []time.Time
	active  time.Time // last owner message the control handler ran
	// chat is when owner task chat last reached the agent, which only an
	// unlocked session does; control words, settings and answers never
	// set it (security B1 on #2372).
	chat    time.Time
	alertAt time.Time
	// ackStop stops the acknowledgement due for task chat, nil when none
	// is (OWN-4); ackGen tells a timer that fired late from the one now
	// due. ackSend orders an acknowledgement against Converse's replies;
	// it is taken before mu.
	// replies counts replies sent, so a delivery arms nothing when one
	// went out meanwhile; ackStops is the STOP count when it was armed.
	ackStop  func() bool
	ackGen   uint64
	ackSend  sync.Mutex
	replies  uint64
	ackStops int64
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
	// pmu orders the pacer's non-urgent Post and Release (pacer.go), so
	// held texts leave the hold once and in order. It is taken before mu.
	pmu sync.Mutex
	// checkedIn and countedIn are the holds of mu in which the hour's
	// allowance was last checked and a text last counted, so a test can
	// pin a paced check and its count to one hold (#1638).
	checkedIn, countedIn uint64
	// spent are the counts Spend made for approval request texts not yet
	// sent, oldest first; sendRequest sends on one instead of counting
	// again, and Refund takes back one no request used (#1685).
	spent []time.Time
}

// holdMutex is a sync.Mutex that numbers its holds.
type holdMutex struct {
	sync.Mutex
	holds uint64
}

func (m *holdMutex) Lock() { m.Mutex.Lock(); m.holds++ }

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
	react   string // a held reaction's event, delivered in place of text (CH-11)
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
	checkPacing(&st)
	if cfg.AfterFunc == nil {
		cfg.AfterFunc = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	c := &Channel{
		cfg:    cfg,
		codes:  codes{sec: cfg.Secrets, verify: cfg.Verifier, st: st, store: cfg.Store, rand: cfg.Rand},
		open:   map[string]*request{},
		queued: map[string]*Queued{}, released: map[string]time.Time{}, lateUndo: map[string]bool{},
		boot: &bootReport{pending: st.Pending, queued: st.Queued},
	}
	c.recent.forgotAt = st.ForgotAt
	c.recent.restore(st.Guarded, cfg.Now())
	if cfg.Modem != nil {
		c.cfg.Modem = watchedLine{Modem: cfg.Modem, c: c}
	}
	var agent control.Agent
	if cfg.Agent != nil {
		agent = chatAgent{Agent: cfg.Agent, c: c}
	}
	// The page-only requests' line is STATUS's first note, so the texted
	// reply, which leaves out notes that do not fit, always keeps it.
	c.ctrl = &control.Handler{Engine: cfg.Engine, Auth: c, Agent: agent, Machines: cfg.Machines, Notes: append([]func() string{c.LocalWaiting}, cfg.Notes...), Now: cfg.Now,
		Settings: c.settings, HelpExtra: strings.TrimSpace(cfg.HelpExtra + " " + pacingHelp), Answer: cfg.Answer}
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
	react    string // a reaction event for the agent (CH-11)
	reactGen uint64 // recent.gen() when react was worded (CAP-3)
	narrow   *reply // PAUSE or REVOKE, run outside the lock
	retry    bool   // RETRY: ask about the digest's unclear effects, outside the lock
	undo     string // an UNDO ID the channel does not hold, for the hook
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
	if c.IsOwner(from) {
		c.ownerSpoke()
	}
	if out, ok := c.stopNow(ctx, from, text); ok {
		c.recordReplies(from, out)
		return out
	}
	rt, ok := c.route(from, text)
	if !ok {
		return nil
	}
	out := c.finish(ctx, from, rt)
	c.recordReplies(from, out)
	return out
}

// stopNow applies STOP from the owner at once, without mu, so it never
// waits behind a code check in progress or queued (CH-2). A RESUME code
// issued before it is void (stops). A STOP sent with codes in any form
// (stopForm) is STOP too: no code is checked, counted or passed on, since
// STOP needs none and a wrong one must not keep it from stopping (#2459,
// #2475). The handler gets bare STOP, never the text.
func (c *Channel) stopNow(ctx context.Context, from, text string) ([]string, bool) {
	if !c.IsOwner(from) || !stopForm(text) {
		return nil, false
	}
	if _, ok := parseReaction(text); ok {
		return nil, false // a reaction is never a control word (CH-11)
	}
	c.stopMu.Lock()
	c.stops.Add(1)
	replies := c.ctrl.Handle(ctx, from, string(control.WordStop))
	c.stopMu.Unlock()
	var out []string
	for _, r := range replies {
		if r != "" {
			out = append(out, control.Fit(r))
		}
	}
	return out, true
}

// stopForm reports whether text is STOP alone or with only codes
// (SEC-stop-forms, #2475). Word boundaries come first: every rune but a
// letter, a digit, a combining mark or a format character separates
// words, before folding, so a symbol that folds to letters ("£" to GBP)
// stays a separator as it was for control.Parse. Each word is then
// folded (fold, the package's NFKC stand-in) and upper-cased. Text is a
// STOP form when one word is STOP and every word is STOP, code-like (a
// digit run of any length or a grid cell label), or STOP glued to
// code-like parts ("STOP123456", "123456STOP"). So "STOP,123456",
// "123456 STOP", "STOP 1234567", "STOP c c2", "STOP H3" and full-width
// forms all stop. Any other word keeps CH-11's rule that a control word
// counts only as the whole message, so "stop the newsletter" is chat.
func stopForm(text string) bool {
	stop := false
	for _, w := range stopWords(text) {
		switch {
		case stopCode(w):
		case gluedStop(w):
			stop = true
		default:
			return false
		}
	}
	return stop
}

// stopWords splits text into folded, upper-cased words, deciding word
// boundaries before folding (stopForm).
func stopWords(text string) []string {
	raw := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Cf, r) {
			return r
		}
		return ' '
	}, text)
	var out []string
	for _, w := range strings.Fields(raw) {
		out = append(out, fields(fold(w))...)
	}
	return out
}

// gluedStop reports whether w is STOP with nothing or a code-like part
// on each side of it.
func gluedStop(w string) bool {
	i := strings.Index(w, string(control.WordStop))
	if i < 0 {
		return false
	}
	pre, post := w[:i], w[i+len(control.WordStop):]
	return (pre == "" || stopCode(pre)) && (post == "" || stopCode(post))
}

// stopCode reports whether w is a digit run or a grid cell label.
func stopCode(w string) bool { return allDigits(w) || gridLabel(w) }

// gridLabel reports whether w (upper-cased) is a cell label of the grid,
// "A1" to "J10" (GridLabels).
func gridLabel(w string) bool {
	for _, l := range GridLabels() {
		if w == l {
			return true
		}
	}
	return false
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
	if rt.react != "" {
		replies = append(replies, c.deliverReaction(ctx, from, rt)...)
	}
	if rt.undo != "" {
		replies = append(replies, c.undoElsewhere(ctx, rt.undo))
	}
	if rt.narrow != nil {
		if c.cfg.Narrow == nil {
			replies = append(replies, "There are no grants to "+strings.ToLower(rt.narrow.word)+".")
		} else {
			replies = append(replies, c.cfg.Narrow(rt.narrow.word, rt.narrow.id))
		}
	}
	if rt.retry {
		replies = append(replies, c.askRetry())
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
	// A reaction is read first: never a control word, a code, RUN or an
	// approval, whatever it quotes (CH-11).
	if rx, ok := c.readReaction(text); ok {
		return c.reactionLocked(text, rx, now, c.codes.unlocked(now))
	}
	if c.codes.st.Challenged {
		if rt, ok := c.challengeLocked(text, now); ok {
			return rt
		}
	}
	unlocked := c.codes.unlocked(now)
	if n, ok := parseName(text); ok {
		return c.nameLocked(text, n, now, unlocked)
	}
	if r, ok := parseReply(text); ok {
		switch r.word {
		case "RESUME":
			out, accepted := c.resumeLocked(r, now)
			return route{replies: out, limited: !accepted}
		case "UNDO":
			out, held := c.undoLocked(r.id, now, decided)
			if !held {
				return route{undo: r.id, limited: !unlocked}
			}
			return route{replies: []string{out}, limited: !unlocked}
		case "PAUSE", "REVOKE":
			return route{narrow: &r, limited: !unlocked}
		case "MORE":
			return route{replies: []string{c.moreLocked(r.id)}, limited: !unlocked}
		case "UNLOCK":
			return route{replies: []string{"Codes are not locked. To unlock a session, send a code from your code generator."}, limited: !unlocked}
		case "RETRY":
			return route{retry: true, limited: !unlocked}
		case "RUN":
			if h := c.held; h != nil && h.ready && unlocked {
				c.held = nil
				if h.react != "" {
					return route{react: h.react, reactGen: c.recent.gen()}
				}
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
		if n, ok := parseName(h.text); ok && h.react == "" && n.name != "" && n.code == "" {
			// A held NAME is not run by RUN: the unlock code proves
			// the owner, not who wrote it, so it gets the texted
			// confirmation instead. Its name passed the check when held.
			c.held = nil
			name, _ := boxname.Check(n.name, c.cfg.OwnerName)
			return route{replies: []string{msg + " " + c.askRenameLocked(name, now)}, limited: true}
		}
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
	if n, ok := parseName(text); ok && n.code != "" {
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

// allowErr: the checker did not record the approval, so nothing ran.
const allowErr = "The box could not record this approval, so nothing was approved and the code did not count. Try again."

// allowUnknownErr: the checker may have recorded the approval and could
// not withdraw it, so the act may still run; the reply says so (SW-5).
// A reply to a request adds how to withdraw it: NO revokes its acts.
const allowUnknownErr = "The box could not confirm or withdraw this approval, so the action may still run. The code did not count."

// secretActErr: an allowed approval never serves an act that releases a
// secret, so a grid cell or texted code cannot approve it (CH-4, CH-10).
const secretActErr = "This approval releases a secret, so only a code from your code generator approves it. That code did not count."

// codeErr is the reply when a code could not be checked or saved. Each
// vault-process failure gets its own fixed wording, since retrying helps
// only in some of them (CH-18).
func (c *Channel) codeErr(err error) string {
	if errors.Is(err, errAllowUnknown) {
		return allowUnknownErr
	}
	if errors.Is(err, errAllow) {
		return allowErr
	}
	if errors.Is(err, errSecretAct) {
		return secretActErr
	}
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
	ok, _, locked, msg := c.checkLocked(p.code, r.code, now, nil)
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
		if s.Phase == control.Held {
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
// strong code also extends the session unlock and approves acts (Item.Act)
// at the checker: a code-generator code through the Verifier, a grid cell
// or a texted code as allowed approvals (AllowActs), and allowed reports
// those. msg is set when no check could run or the checker did not record
// an allow; the reply then approved nothing and counted as no try.
func (c *Channel) checkLocked(texted, got string, now time.Time, acts []CheckerAct) (ok, allowed, locked bool, msg string) {
	if texted == "" || c.codes.st.LowLocked {
		res, locked, err := c.codes.checkStrong(got, now, strongOpts{unlock: c.cfg.UnlockFor, count: true, acts: acts})
		switch {
		case err != nil:
			return false, false, false, c.codeErr(err)
		}
		return res == strongOK || res == strongAllowed, res == strongAllowed, locked, ""
	}
	if eq(got, texted) {
		if len(acts) == 0 {
			return true, false, false, ""
		}
		if secretAct(acts) {
			return false, false, false, secretActErr
		}
		if err := c.codes.allowThen(acts, nil); err != nil {
			return false, false, false, c.codeErr(err)
		}
		return true, true, false, ""
	}
	locked, err := c.codes.wrong(now)
	if err != nil {
		return false, false, locked, stateErr
	}
	return false, false, locked, ""
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

// Chatting reports whether owner task chat reached the agent within the
// last d: the owner is talking with the agent, so its questions are
// conversation (CH-15, #2363). Unlike Active, a control word, a setting
// or a question's answer does not count, since none reaches the agent
// and each needs only the owner's number, which can be spoofed.
func (c *Channel) Chatting(d time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.chat.IsZero() && c.cfg.Now().Sub(c.chat) < d
}

// chatAgent records when the control handler delivers owner task chat
// to the agent, which it does only in an unlocked session, and arms the
// acknowledgement from when the message reached the box (OWN-4): a
// sleeping agent's inbox takes it too, so the wait covers a wake. A
// reaction event (eventDelivery) arms none, nor does a delivery the agent
// replied to before it returned.
type chatAgent struct {
	control.Agent
	c *Channel
}

func (a chatAgent) Deliver(ctx context.Context, text string, public bool) error {
	at := a.c.cfg.Now()
	a.c.mu.Lock()
	replies := a.c.replies
	a.c.mu.Unlock()
	err := a.Agent.Deliver(ctx, text, public)
	if err == nil {
		a.c.mu.Lock()
		a.c.chat = a.c.cfg.Now()
		if ctx.Value(eventDelivery{}) == nil && a.c.replies == replies {
			a.c.armAckLocked(at)
		}
		a.c.mu.Unlock()
	}
	return err
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

// Notify texts the owner content that did not come from the broker's own
// templates, such as an agent's answer, with no label (CH-21): the CH-21
// check (AgentVoice), not a marker, keeps it from passing for one of the
// broker's own templates (an approval request, a code prompt).
// Secret-shaped content becomes a pointer to the local UI (CH-19).
// It is paced as ClassAgent (CH-15).
func (c *Channel) Notify(text string) error {
	return c.NotifyAs(ClassAgent, text)
}

// Inform texts the owner one of the broker's own fixed-wording notices
// (a grant added, an action waiting on the local page). Callers never
// pass agent text: that goes through Notify. Secret-shaped content still
// becomes a pointer (CH-19). It is paced as ClassUpdate (CH-15).
func (c *Channel) Inform(text string) error {
	return c.Post(ClassUpdate, text)
}

// Run serves the modem until ctx is done. It first reports what a restart
// dropped (Boot). STOP is applied as soon as it is read, ahead of anything
// queued (stopNow). The channel's other decisions run in arrival order on
// one worker, which may wait on a code check; the control handler's part
// (task chat waits on the agent for up to control.DeliverTimeout) runs on
// its own goroutine, as does a reaction event, so a slow agent never delays
// a STOP or the next text behind it (CH-2, B11, CH-11).
func (c *Channel) Run(ctx context.Context) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	c.Boot()
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		c.mu.Lock()
		c.stopAckLocked() // no acknowledgement outlives the channel
		c.mu.Unlock()
	}()
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
				if !rt.run && rt.react == "" {
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

// askRetry asks about the unclear effects Config.Retry lists (OP-2): one
// request per effect, never one YES for all, each at the tier its own
// verified facts give, and on the local page when its recipients cannot
// be texted. It returns the reply, "" once every request is on its way.
// A reply ends with one step that works, never two (CH-12).
func (c *Channel) askRetry() string {
	var items []Item
	var unread error
	if c.cfg.Retry != nil {
		items, unread = c.cfg.Retry()
	}
	if unread == nil && len(items) == 0 {
		return "Nothing to retry."
	}
	var short string
	if len(items) > 0 {
		short = c.askRetryItems(items)
	}
	switch {
	case unread != nil && short != "":
		return short + " " + retryUnread
	case unread != nil:
		return retryUnread
	case short != "":
		return short + " Text RETRY again later for the rest."
	}
	return ""
}

// retryUnread is RETRY's line while part of the box cannot say what is
// waiting: it may hold effects to retry, so "Nothing to retry." would be
// untrue (KRN-7).
const retryUnread = "Part of me is not answering, so I could not check every action to retry. Text RETRY again later."

// askRetryItems asks about each of items, as askRetry says. It returns
// why some could not be asked, without a step, or "" once all were.
func (c *Channel) askRetryItems(items []Item) string {
	if len(items) > 20 {
		items = items[:20]
	}
	var text, local []Item
	for _, it := range items {
		if SMSApprovable(it) {
			text = append(text, it)
		} else {
			local = append(local, it)
		}
	}
	var errs []error
	if len(text) > 0 {
		_, err := c.RequestEach(text, make([]time.Time, len(text)))
		errs = append(errs, err)
	}
	if len(local) > 0 {
		_, err := c.RequestLocalEach(local, make([]time.Time, len(local)))
		errs = append(errs, err)
	}
	switch err := errors.Join(errs...); {
	case err == nil:
		return ""
	case errors.Is(err, ErrFull):
		return "Too many open requests to ask about every retry now."
	default:
		return "Could not ask about every retry now."
	}
}
