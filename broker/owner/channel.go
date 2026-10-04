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
	"sync"
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
	Secrets  Secrets
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
}

// Decision is the outcome for one requested item.
type Decision struct {
	Request  string
	Item     int // 1-based
	Ref      string
	Approved bool
	// Why: "owner", "expired", "void" (wrong codes), "not chosen" (left
	// out of a partial YES), or "restart" (dropped by a reboot).
	Why string
}

// Channel is the owner channel. It implements control.Auth.
type Channel struct {
	cfg  Config
	ctrl *control.Handler

	mu          sync.Mutex
	codes       codes
	open        map[string]*request
	queued      map[string]*Queued
	resume      *resumeCode
	resumeTexts []time.Time
	held        *heldMsg
	limited     []time.Time
	expired     []Decision
	expiredMore int
	boot        *bootReport
}

var _ control.Auth = (*Channel)(nil)

type resumeCode struct {
	code    string // "" when the low tier is locked: a strong code is needed
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
		codes:  codes{sec: cfg.Secrets, st: st, store: cfg.Store, rand: cfg.Rand},
		open:   map[string]*request{},
		queued: map[string]*Queued{},
		boot:   &bootReport{pending: st.Pending, queued: st.Queued},
	}
	c.ctrl = &control.Handler{Engine: cfg.Engine, Auth: c, Agent: cfg.Agent, Machines: cfg.Machines, Now: cfg.Now}
	return c, nil
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
	// limited: the replies count against ReplyLimit (CH-15).
	limited bool
	at      time.Time
}

// Handle processes one text from number from and returns the texts to send
// back to it.
func (c *Channel) Handle(ctx context.Context, from, text string) []string {
	rt, ok := c.route(from, text)
	if !ok {
		return nil
	}
	return c.finish(ctx, from, rt)
}

// route makes every decision the channel itself owns, in arrival order.
func (c *Channel) route(from, text string) (route, bool) {
	if !c.IsOwner(from) {
		return route{}, false
	}
	now := c.cfg.Now()
	c.mu.Lock()
	decided := c.expireLocked(now)
	rt := c.routeLocked(text, now, &decided)
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
		replies = append(replies, c.ctrl.Handle(ctx, from, rt.delegate)...)
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
	unlocked := c.codes.unlocked(now)
	if r, ok := parseReply(text); ok {
		switch r.word {
		case "RESUME":
			out, accepted := c.resumeLocked(r, now)
			return route{replies: out, limited: !accepted}
		case "UNDO":
			return route{replies: []string{c.undoLocked(r.id, now)}, limited: !unlocked}
		case "MORE":
			return route{replies: []string{c.moreLocked(r.id)}, limited: !unlocked}
		case "RUN":
			if h := c.held; h != nil && h.ready && unlocked {
				c.held = nil
				return route{delegate: h.text, run: true}
			}
			return route{replies: []string{"Nothing is held."}, limited: !unlocked}
		default: // YES, NO
			if len(c.open) > 0 || r.id != "" {
				out, accepted, wrong := c.answerLocked(r, now, decided)
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
		if res, _, err := c.codes.checkStrong(code, now, strongOpts{}); err == nil && res == strongOK {
			if rest == "" {
				return route{replies: []string{"You are already unlocked until " + c.untilText() + "."}}
			}
			return route{delegate: rest, run: true}
		}
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
		return route{replies: []string{stateErr}, limited: true}
	case res == strongThrottled:
		c.held = nil
		return route{replies: []string{c.throttleText(now)}, limited: true}
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

const stateErr = "Could not save the code check, so it did not count. Try again."

func (c *Channel) untilText() string {
	return c.codes.st.UnlockedUntil.In(c.cfg.Location).Format("Jan 2 15:04")
}

// unlockPrompt asks for a high-tier code; a texted code never unlocks a
// session (CH-14, CH-19).
func (c *Channel) unlockPrompt() string {
	return "Send a code from your code generator" + c.gridOr() + "."
}

func (c *Channel) gridOr() string {
	if cell := c.codes.gridChallenge(); cell != "" {
		return ", or grid cell " + cell
	}
	return ""
}

func (c *Channel) throttleText(now time.Time) string {
	_, until := c.codes.throttled(now)
	return "Too many wrong codes. Codes by text are paused until " +
		until.In(c.cfg.Location).Format("Jan 2 15:04") + ". STOP still works."
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
		if p := c.resume; p == nil || !now.Before(p.expires) {
			c.resume = &resumeCode{expires: now.Add(c.cfg.CodeTTL)}
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
	if p == nil || !now.Before(p.expires) {
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
	if err := c.cfg.Engine.Resume(); err != nil {
		return []string{"RESUME failed to record. Still stopped."}, true
	}
	n := 0
	for _, s := range c.cfg.Engine.List() {
		if s.State == journal.Authorized || s.State == journal.NotApplied {
			n++
		}
	}
	return []string{fmt.Sprintf("Resumed. %d held actions may now run.", n)}, true
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
			return false, false, stateErr
		case res == strongThrottled:
			return false, false, c.throttleText(now)
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

// Notify texts the owner content that did not come from the broker's own
// templates, such as an agent's answer. Secret-shaped content becomes a
// pointer to the local UI (CH-19).
func (c *Channel) Notify(text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	return c.cfg.Modem.Send(c.cfg.Owner, control.Fit(Disclose(text)))
}

// Run serves the modem until ctx is done. It first reports what a restart
// dropped (Boot). The channel's own decisions run in arrival order; the
// control handler's part (task chat waits on the agent for up to
// control.DeliverTimeout) runs on its own goroutine, so a slow agent never
// delays a STOP behind it (CH-2, B11).
func (c *Channel) Run(ctx context.Context) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	c.Boot()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	send := func(to string, rs []string) {
		for _, r := range rs {
			if c.cfg.Modem.Send(to, r) != nil {
				return
			}
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			c.Tick()
		case m := <-c.cfg.Modem.Inbox():
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
}
