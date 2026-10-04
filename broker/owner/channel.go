// Package owner is the owner channel (SPEC §6.1, PLAN P1-5): the box's own
// number as the conversational address, CH-3's command tiers, two-tier
// approval codes (CH-4, CH-10), batch replies (CH-13), inline session
// unlock (CH-14), code hygiene (CH-18), disclosure filtering (CH-19), and
// queued context-scoped auto-replies with their commitment filter (ADP-11).
//
// Channel sits in front of control.Handler. It owns every word that carries
// or checks a code (RESUME, YES, NO, UNDO, MORE, and session unlock) and
// passes STOP, STATUS, HELP and task chat to the control handler, which
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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/modem"
)

// Defaults (CH-10, CH-14, REV-3).
const (
	DefaultUnlockFor  = 7 * 24 * time.Hour
	DefaultCodeTTL    = 15 * time.Minute
	DefaultUndoWindow = 10 * time.Minute
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
	// Location renders times in texts; nil means time.Local.
	Location *time.Location
	Now      func() time.Time
	Rand     io.Reader
	// Decide receives every decision on a requested item, after the
	// channel's lock is released.
	Decide func(Decision)
}

// Decision is the outcome for one requested item.
type Decision struct {
	Request  string
	Item     int // 1-based
	Ref      string
	Approved bool
	// Why: "owner", "expired", "void" (wrong codes), or "not chosen"
	// (left out of a partial YES).
	Why string
}

// Channel is the owner channel. It implements control.Auth.
type Channel struct {
	cfg  Config
	ctrl *control.Handler

	mu      sync.Mutex
	codes   codes
	open    map[string]*request
	queued  map[string]*queuedReply
	resume  *resumeCode
	held    *heldMsg
	expired []Decision
}

var _ control.Auth = (*Channel)(nil)

type request struct {
	id      string
	items   []Item
	tier    Tier
	code    string // texted code, low tier only
	expires time.Time
	wrong   int
	done    []bool
}

type resumeCode struct {
	code    string // "" when the low tier is locked: a strong code is needed
	expires time.Time
	wrong   int
}

type heldMsg struct {
	text    string
	expires time.Time
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
		queued: map[string]*queuedReply{},
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
	return c.codes.lock()
}

// Handle processes one text from number from and returns the texts to send
// back to it.
func (c *Channel) Handle(ctx context.Context, from, text string) []string {
	if !c.IsOwner(from) {
		return nil
	}
	now := c.cfg.Now()
	c.mu.Lock()
	decided := c.expireLocked(now)
	replies, delegate, run := c.routeLocked(text, now, &decided)
	c.mu.Unlock()

	c.decide(decided)
	if run {
		replies = append(replies, c.ctrl.Handle(ctx, from, delegate)...)
	}
	for i, r := range replies {
		replies[i] = control.Fit(r)
	}
	return replies
}

// routeLocked answers the channel's own words and decides what reaches the
// control handler. run reports whether delegate goes there.
func (c *Channel) routeLocked(text string, now time.Time, decided *[]Decision) (replies []string, delegate string, run bool) {
	if r, ok := parseReply(text); ok {
		switch r.word {
		case "RESUME":
			return c.resumeLocked(r, now), "", false
		case "UNDO":
			return []string{c.undoLocked(r.id, now)}, "", false
		case "MORE":
			return []string{c.moreLocked(r.id)}, "", false
		default: // YES, NO
			if len(c.open) > 0 || r.id != "" {
				return c.answerLocked(r, now, decided), "", false
			}
			if r.word == "YES" && r.code == "" && len(r.items) == 0 {
				break // a bare "yes" with nothing open is chat
			}
			return []string{"No open requests."}, "", false
		}
	}
	switch control.Parse(text).Word {
	case control.WordStop:
		c.resume = nil // a code issued before STOP must not lift it
		return nil, text, true
	case control.WordHelp, control.WordYes, control.WordNo, control.WordUndo, control.WordMore, control.WordResume:
		return nil, text, true
	}
	// STATUS and task chat need an unlocked session (CH-3). While locked, a
	// code may be the whole message or appended to it (CH-14). While
	// unlocked, numbers are chat and are not checked, so a spoofer inside
	// the unlock window gets no free guesses at extending it.
	if c.codes.unlocked(now) {
		return nil, text, true
	}
	held := text
	code := ""
	if f := fields(text); len(f) == 1 && isCode(f[0]) {
		held, code = "", f[0]
	} else if rest, tc, ok := trailingCode(text); ok && rest != "" {
		held, code = rest, tc
	}
	if held != "" {
		c.held = &heldMsg{text: held, expires: now.Add(c.cfg.CodeTTL)}
	}
	if code == "" {
		return []string{fmt.Sprintf("Locked. Your message is held for %s. %s", dur(c.cfg.CodeTTL), c.unlockPrompt())}, "", false
	}
	res, locked, err := c.codes.checkStrong(code, now, c.cfg.UnlockFor, true)
	switch {
	case err != nil:
		return []string{stateErr}, "", false
	case res == strongOK:
		return c.unlockedLocked(now)
	case res == strongThrottled:
		return []string{c.throttleText()}, "", false
	}
	if held != "" {
		return []string{"Wrong code. Your message is held. " + c.unlockPrompt() + lockNote(locked)}, "", false
	}
	return []string{"Wrong code. " + c.unlockPrompt() + lockNote(locked)}, "", false
}

const stateErr = "Could not save the code check. Nothing changed; try again."

// unlockedLocked confirms an unlock and runs a held message (CH-14).
func (c *Channel) unlockedLocked(now time.Time) ([]string, string, bool) {
	msg := fmt.Sprintf("Unlocked until %s.", c.codes.st.UnlockedUntil.In(c.cfg.Location).Format("Jan 2 15:04"))
	h := c.held
	c.held = nil
	if h != nil && now.Before(h.expires) {
		return []string{msg + " Running your held message."}, h.text, true
	}
	return []string{msg}, "", false
}

// unlockPrompt asks for a high-tier code; a texted code never unlocks a
// session (CH-14, CH-19).
func (c *Channel) unlockPrompt() string {
	if cell := c.codes.gridChallenge(); cell != "" {
		return "Send a code from your code generator, or grid cell " + cell + "."
	}
	return "Send a code from your code generator."
}

func (c *Channel) throttleText() string {
	return "Too many wrong codes today. Codes by text are paused; unlock on the box's Wi-Fi page or try again tomorrow."
}

// lockNote tells the owner that wrong codes locked the low tier (CH-18).
func lockNote(locked bool) string {
	if !locked {
		return ""
	}
	return fmt.Sprintf(" %d wrong codes in 24 h: texted codes are off and the session is locked until you send a code-generator code.", WrongToLock)
}

// resumeLocked lifts STOP with a low-tier texted code (CH-11), or a
// code-generator code while the low tier is locked (CH-18).
func (c *Channel) resumeLocked(r reply, now time.Time) []string {
	if !c.cfg.Engine.Stopped() {
		c.resume = nil
		return []string{"Not stopped. Nothing to resume."}
	}
	if r.code == "" {
		if c.codes.st.LowLocked {
			c.resume = &resumeCode{expires: now.Add(c.cfg.CodeTTL)}
			return []string{"To restart all actions, reply RESUME and a code from your code generator" + c.gridOr() + "."}
		}
		c.resume = &resumeCode{code: c.codes.textedCode(), expires: now.Add(c.cfg.CodeTTL)}
		return []string{fmt.Sprintf("To restart all actions, reply RESUME %s within %s.", c.resume.code, dur(c.cfg.CodeTTL))}
	}
	p := c.resume
	if p == nil || !now.Before(p.expires) {
		c.resume = nil
		return []string{"No valid code. Reply RESUME for a new one."}
	}
	ok, locked, msg := c.checkLocked(p.code, r.code, now)
	if msg != "" {
		return []string{msg}
	}
	if !ok {
		p.wrong++
		if p.wrong >= WrongPerRequest {
			c.resume = nil
			return []string{"Wrong code 3 times; it is void. Reply RESUME for a new one." + lockNote(locked)}
		}
		return []string{"Wrong code. Reply RESUME <code>." + lockNote(locked)}
	}
	c.resume = nil
	if err := c.cfg.Engine.Resume(); err != nil {
		return []string{"RESUME failed to record. Still stopped."}
	}
	return []string{"Resumed. Held actions may now run."}
}

// checkLocked checks a reply code against a texted code, or against the
// code generator and grid when texted is "" or the low tier is locked.
// msg is set when no check could run.
func (c *Channel) checkLocked(texted, got string, now time.Time) (ok, locked bool, msg string) {
	if texted == "" || c.codes.st.LowLocked {
		res, locked, err := c.codes.checkStrong(got, now, c.cfg.UnlockFor, true)
		switch {
		case err != nil:
			return false, false, stateErr
		case res == strongThrottled:
			return false, false, c.throttleText()
		}
		return res == strongOK, locked, ""
	}
	if eq(got, texted) {
		return true, false, ""
	}
	locked, err := c.codes.wrong(now)
	if err != nil {
		return false, false, stateErr
	}
	return false, locked, ""
}

func (c *Channel) gridOr() string {
	if cell := c.codes.gridChallenge(); cell != "" {
		return " or grid cell " + cell
	}
	return ""
}

// Request opens an approval request for items and texts it to the owner.
// ttl bounds how long it stays open (0: CodeTTL); a low-tier request never
// outlives CodeTTL, since its texted code expires then (CH-10).
func (c *Channel) Request(items []Item, ttl time.Duration) (string, error) {
	if len(items) == 0 || len(items) > 20 {
		return "", errors.New("owner: a request has 1 to 20 items")
	}
	if c.cfg.Modem == nil {
		return "", errors.New("owner: no modem")
	}
	now := c.cfg.Now()
	c.mu.Lock()
	tier := Low
	for _, it := range items {
		if Classify(it.Facts, c.cfg.Limits, now) == High {
			tier = High
		}
	}
	if c.codes.st.LowLocked {
		tier = High // texted codes are off (CH-18)
	}
	if ttl <= 0 {
		ttl = c.cfg.CodeTTL
	}
	if tier == Low && ttl > c.cfg.CodeTTL {
		ttl = c.cfg.CodeTTL
	}
	r := &request{id: c.newIDLocked(), items: append([]Item(nil), items...), tier: tier,
		expires: now.Add(ttl), done: make([]bool, len(items))}
	if tier == Low {
		r.code = c.codes.textedCode()
	}
	text := c.renderLocked(r)
	c.open[r.id] = r
	c.mu.Unlock()
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		c.mu.Lock()
		delete(c.open, r.id)
		c.mu.Unlock()
		return "", err
	}
	return r.id, nil
}

// renderLocked is the approval text (CH-12): fixed wording from verified
// fields, the expiry, and the valid replies, in GSM-7 within three
// segments. Items that do not fit are left to MORE.
func (c *Channel) renderLocked(r *request) string {
	exp := r.expires.In(c.cfg.Location).Format("15:04")
	var replies string
	strong := r.tier == High || c.codes.st.LowLocked
	switch {
	case strong && len(r.items) == 1:
		replies = fmt.Sprintf("Reply YES %s and a code from your code generator%s, or NO %s.", r.id, c.gridOr(), r.id)
	case strong:
		replies = fmt.Sprintf("Reply YES %s and a code from your code generator%s (add item numbers to approve some), or NO %s.", r.id, c.gridOr(), r.id)
	case len(r.items) == 1:
		replies = fmt.Sprintf("Reply YES %s %s or NO %s.", r.id, r.code, r.id)
	default:
		replies = fmt.Sprintf("Reply YES %s %s for all, YES %s 1 2 %s for some, or NO %s.", r.id, r.code, r.id, r.code, r.id)
	}
	if len(r.items) == 1 {
		return fmt.Sprintf("%s: %s. Expires %s. %s", r.id, r.items[0].line(), exp, replies)
	}
	for shown := len(r.items); shown >= 0; shown-- {
		var b strings.Builder
		fmt.Fprintf(&b, "%s: %d items.", r.id, len(r.items))
		for i := 0; i < shown; i++ {
			fmt.Fprintf(&b, " %d %s.", i+1, r.items[i].line())
		}
		if shown < len(r.items) {
			fmt.Fprintf(&b, " Items %d-%d: MORE %s.", shown+1, len(r.items), r.id)
		}
		fmt.Fprintf(&b, " Expires %s. %s", exp, replies)
		if fits(b.String()) {
			return b.String()
		}
	}
	return fmt.Sprintf("%s: %d items. MORE %s lists them. Expires %s. %s", r.id, len(r.items), r.id, exp, replies)
}

// moreLocked lists a request's open items (CH-12's MORE).
func (c *Channel) moreLocked(id string) string {
	r := c.open[id]
	if r == nil {
		return fmt.Sprintf("No open request %s.", id)
	}
	var b strings.Builder
	b.WriteString(id + ":")
	for i, it := range r.items {
		if r.done[i] {
			continue
		}
		next := fmt.Sprintf(" %d %s.", i+1, it.line())
		if !fits(b.String() + next + " Rest on the box's Wi-Fi page.") {
			b.WriteString(" Rest on the box's Wi-Fi page.")
			break
		}
		b.WriteString(next)
	}
	return b.String()
}

// answerLocked applies YES or NO to a request (CH-13).
func (c *Channel) answerLocked(rp reply, now time.Time, decided *[]Decision) []string {
	r, msg := c.findLocked(rp)
	if r == nil {
		return []string{msg}
	}
	for _, n := range rp.items {
		if n > len(r.items) || r.done[n-1] {
			return []string{fmt.Sprintf("%s has no open item %d.", r.id, n)}
		}
	}
	chosen := map[int]bool{}
	for _, n := range rp.items {
		chosen[n-1] = true
	}
	all := len(rp.items) == 0
	if rp.word == "NO" {
		c.closeLocked(r, func(i int) (bool, bool) { return all || chosen[i], false }, "owner", decided)
		if all {
			return []string{"Denied " + r.id + "."}
		}
		return []string{fmt.Sprintf("Denied %s item %s.", r.id, list(rp.items))}
	}
	if rp.code == "" {
		return []string{fmt.Sprintf("Include the code: YES %s <code>.", r.id)}
	}
	texted := r.code
	if r.tier == High {
		texted = ""
	}
	ok, locked, msg := c.checkLocked(texted, rp.code, now)
	if msg != "" {
		return []string{msg}
	}
	if !ok {
		r.wrong++
		if r.wrong >= WrongPerRequest {
			c.closeLocked(r, func(int) (bool, bool) { return true, false }, "void", decided)
			return []string{fmt.Sprintf("Wrong code 3 times; %s is void and denied.", r.id) + lockNote(locked)}
		}
		return []string{fmt.Sprintf("Wrong code for %s. %d tries left.", r.id, WrongPerRequest-r.wrong) + lockNote(locked)}
	}
	// A partial YES closes the batch: the listed items are approved and the
	// rest denied, so the single-use code is not left open (assumption O3).
	var denied []int
	for i := range r.items {
		if !r.done[i] && !all && !chosen[i] {
			denied = append(denied, i+1)
		}
	}
	c.closeLocked(r, func(i int) (bool, bool) { return true, all || chosen[i] }, "", decided)
	if all {
		return []string{"Approved " + r.id + "."}
	}
	s := fmt.Sprintf("Approved %s item %s.", r.id, list(rp.items))
	if len(denied) > 0 {
		s += fmt.Sprintf(" Denied %s.", list(denied))
	}
	return []string{s}
}

// findLocked resolves which request a reply answers.
func (c *Channel) findLocked(rp reply) (*request, string) {
	if rp.id != "" {
		if r := c.open[rp.id]; r != nil {
			return r, ""
		}
		return nil, fmt.Sprintf("No open request %s.", rp.id)
	}
	if len(c.open) == 1 {
		for _, r := range c.open {
			return r, ""
		}
	}
	// A texted code names its request (CH-18: bound to one request).
	if rp.code != "" && !c.codes.st.LowLocked {
		for _, r := range c.open {
			if r.tier == Low && eq(rp.code, r.code) {
				return r, ""
			}
		}
	}
	return nil, fmt.Sprintf("%d requests are open. Reply with an ID: %s.", len(c.open), strings.Join(c.openIDsLocked(), ", "))
}

// closeLocked settles items: pick(i) says whether item i is settled now and
// whether it is approved. The request closes when no item is left.
func (c *Channel) closeLocked(r *request, pick func(int) (settle, approve bool), why string, decided *[]Decision) {
	for i, it := range r.items {
		if r.done[i] {
			continue
		}
		settle, approve := pick(i)
		if !settle {
			continue
		}
		w := why
		if w == "" {
			w = "owner"
			if !approve {
				w = "not chosen"
			}
		}
		r.done[i] = true
		*decided = append(*decided, Decision{Request: r.id, Item: i + 1, Ref: it.Ref, Approved: approve, Why: w})
	}
	for _, d := range r.done {
		if !d {
			return
		}
	}
	delete(c.open, r.id)
}

// expireLocked denies requests past their expiry and drops stale held
// messages and RESUME codes. Expired items are kept for the digest (CH-13).
func (c *Channel) expireLocked(now time.Time) []Decision {
	var out []Decision
	for _, id := range c.openIDsLocked() {
		r := c.open[id]
		if now.Before(r.expires) {
			continue
		}
		c.closeLocked(r, func(int) (bool, bool) { return true, false }, "expired", &out)
	}
	c.expired = append(c.expired, out...)
	if c.held != nil && !now.Before(c.held.expires) {
		c.held = nil
	}
	if c.resume != nil && !now.Before(c.resume.expires) {
		c.resume = nil
	}
	return out
}

// Tick expires what is due; Run calls it every minute.
func (c *Channel) Tick() {
	c.mu.Lock()
	d := c.expireLocked(c.cfg.Now())
	c.mu.Unlock()
	c.decide(d)
}

// TakeExpired returns and clears the items that expired unanswered, for the
// next digest (CH-13).
func (c *Channel) TakeExpired() []Decision {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.expired
	c.expired = nil
	return out
}

func (c *Channel) decide(ds []Decision) {
	if c.cfg.Decide == nil {
		return
	}
	for _, d := range ds {
		c.cfg.Decide(d)
	}
}

func (c *Channel) openIDsLocked() []string {
	ids := make([]string, 0, len(c.open))
	for id := range c.open {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// idLetters avoids I and O, which read as 1 and 0.
const idLetters = "ABCDEFGHJKLMNPQRSTUVWXYZ"

// newIDLocked returns an ID unique among open requests and queued replies:
// a letter and a digit, or a letter and two digits when those run out
// (CH-12: at most 3 characters).
func (c *Channel) newIDLocked() string {
	taken := func(id string) bool { return c.open[id] != nil || c.queued[id] != nil }
	for tries := 0; tries < 64; tries++ {
		id := fmt.Sprintf("%c%d", idLetters[randInt(c.cfg.Rand, len(idLetters))], 2+randInt(c.cfg.Rand, 8))
		if !taken(id) {
			return id
		}
	}
	for {
		id := fmt.Sprintf("%c%02d", idLetters[randInt(c.cfg.Rand, len(idLetters))], randInt(c.cfg.Rand, 100))
		if !taken(id) {
			return id
		}
	}
}

func list(ns []int) string {
	s := make([]string, len(ns))
	for i, n := range ns {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
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

// Run serves the modem: each text from the owner is handled and answered.
// It returns when ctx is done.
func (c *Channel) Run(ctx context.Context) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			c.Tick()
		case m := <-c.cfg.Modem.Inbox():
			for _, r := range c.Handle(ctx, m.From, m.Text) {
				if err := c.cfg.Modem.Send(m.From, r); err != nil {
					break
				}
			}
		}
	}
}
