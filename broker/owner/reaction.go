package owner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Reactions (CH-11, D-127). A phone sends a tapback to a box texted by SMS
// as a text such as `Liked “Reply YES R7K 482913 or NO R7K.”`. The channel
// reads it before its own words: a reaction is never a control word, a
// code, RUN or an approval. It reaches the agent as an event the broker
// words (the kind plus the marked text, matched against the recent texts
// to the owner), never as the owner's quote, and only when a task message
// would (CH-3); while the session is locked it is held as one is (CH-14).

// reactionForm matches the reaction texts read today: the iPhone tapbacks and
// their removals, and the emoji form ("Reacted 👍 to"). Qualification
// records the formats the owner's phones send; Loop 2 extends the list
// (LOOP-10).
var reactionForm = regexp.MustCompile(`(?is)^(liked|loved|disliked|laughed at|emphasi[sz]ed|questioned|` +
	`removed a like from|removed a heart from|removed a dislike from|removed a laugh from|` +
	`removed an exclamation from|removed an exclamation mark from|removed an emphasis from|` +
	`removed a question mark from|removed an? [^\p{L}\s]+ from|reacted \S+ to) ` +
	`["“](.+)["”]$`)

// quoteMarks are the quote characters a phone puts round a quote. A quote
// that holds one is not read as a reaction on its form alone: the owner's own
// text that starts like a form and holds a second quote is chat (#2201). It
// is a reaction only when the quote marks a recent box text (readReaction).
const quoteMarks = `"“”`

// reaction is one owner reaction: its kind in lower case, as the agent
// reads it, and the quoted text.
type reaction struct {
	kind   string
	quoted string
	// tell: the owner is told the text was read as a reaction
	// (readAsReaction): an unlisted form, whose lead-in is dropped, or a
	// form read so only because a deletion forgot texts (CAP-3).
	tell bool
}

// readAsReaction tells the owner that a text was read as a reaction, so
// its words never reached the agent (#2277, #2360). It is fixed and
// never echoes the quote, which holds a request or a code (CH-3).
const readAsReaction = "I read that as a reaction to one of my texts, so it did not go to the agent. " +
	"To tell the agent something, send it without quoting that text."

// parseReaction reports whether text, whole, is a reaction form.
func parseReaction(text string) (reaction, bool) {
	rx, ok := parseForm(text)
	if !ok || strings.ContainsAny(rx.quoted, quoteMarks) {
		return reaction{}, false
	}
	return rx, true
}

// parseForm is parseReaction without the check on quote marks in the quote.
func parseForm(text string) (reaction, bool) {
	m := reactionForm.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil || strings.TrimSpace(m[2]) == "" {
		return reaction{}, false
	}
	return reaction{kind: strings.Join(strings.Fields(strings.ToLower(m[1])), " "), quoted: m[2]}, true
}

// unlistedForm matches text outside the fixed list that still has the shape
// of a reaction: a short lead-in of words or emoji, then a quote that runs to
// the end of the text. It is read as a reaction only when the quote marks a
// recent box text that holds a request or a code (#2202).
var unlistedForm = regexp.MustCompile(`(?s)^([\p{L}\p{M}\p{N}\p{P}\p{So}\p{Sk} ]{1,40}?) ["“](.+)["”]$`)

// readReaction is parseReaction, plus two cases that need the recent texts:
// a listed form whose quote holds quote marks, when the quote marks a recent
// box text (a request or a RUN offer quotes its own words), and an unlisted
// form, when the quote marks a text to the owner that is a request or holds
// a box code (CH-3). The agent's own text is never a reason: its digits
// already passed Disclose, so an unlisted form quoting it stays chat and the
// owner's words reach the agent whole (CH-11). The exception is the 24 h
// after a deletion, when the agent may no longer hold the text quoted
// (CAP-3, #2360, CAP3-reaction-recent-forget-O44).
func (c *Channel) readReaction(text string) (reaction, bool) {
	if rx, ok := parseReaction(text); ok {
		return rx, true
	}
	if rx, ok := parseForm(text); ok {
		now := c.cfg.Now()
		if _, found := c.recent.match(rx.quoted, now); found {
			return rx, true
		}
		// After a deletion the quote may mark a forgotten text, which as
		// chat would reach the agent whole: read it as a reaction that
		// matched none until the forgotten texts are past the window
		// (CAP-3, #2360).
		if c.recent.forgotWithin(now) {
			rx.tell = true
			return rx, true
		}
		return reaction{}, false
	}
	m := unlistedForm.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil || len(strings.Fields(m[1])) > 5 {
		return reaction{}, false
	}
	now := c.cfg.Now()
	unlisted := reaction{kind: "reacted to", quoted: m[2], tell: true}
	if t, ok := c.recent.match(m[2], now); ok && t.guarded() {
		return unlisted, true
	}
	// After a deletion an unlisted form quoting an agent text may quote a
	// forgotten reply, which as chat would reach the agent whole: read it
	// as a reaction until the forgotten texts are past the window (CAP-3,
	// #2360). A forgotten text no longer matches, so its event matches none.
	if c.recent.forgotWithin(now) && strings.HasPrefix(normQuote(m[2]), normQuote(AgentPrefix)) {
		return unlisted, true
	}
	return reaction{}, false
}

// ErrAgentReaction refuses agent text that is a reaction form: until
// qualification records how the owner's phone shows one, the agent
// replies in text (CH-11).
var ErrAgentReaction = errors.New("owner: agent reactions are refused; reply in text")

// refuseReaction is ErrAgentReaction if agent text is a reaction form.
func refuseReaction(text string) error {
	if _, ok := parseReaction(text); ok {
		return ErrAgentReaction
	}
	return nil
}

const (
	// recentTexts bounds the window of texts to the owner a reaction is
	// matched against, by count and by age.
	recentTexts  = 20
	recentMaxAge = 24 * time.Hour
	// minQuote is the shortest quote matched as part of a text, so a few
	// characters never name one.
	minQuote = 12
)

// sentText is one recent text to the owner.
type sentText struct {
	text    string
	at      time.Time
	request bool     // an approval request (sendRequest)
	ids     []string // the requests it asks, from the broker's record
	local   bool     // approvable on the local page only
}

// guarded reports whether a reaction to t is never shown to the agent with
// its text: an approval request, or a box text that holds a code (CH-3).
// The agent's own text is never guarded: its digits already passed
// Disclose.
func (t sentText) guarded() bool {
	return t.request || (!strings.HasPrefix(t.text, AgentPrefix) && carriesCode.MatchString(t.text))
}

// recentWindow is the window of texts to the owner.
type recentWindow struct {
	mu    sync.Mutex
	texts []sentText
	// forgets counts the deletions that cleared the window, so a reaction
	// event worded before one is never delivered after it (CAP-3).
	forgets uint64
	// forgotAt is the last deletion's time, kept in State.ForgotAt so a
	// restart does not end the 24 h rule early (forgotWithin).
	forgotAt time.Time
}

// forget drops every recent text that a reaction would show the agent: a
// deletion's reach covers them, since any may quote the deleted record and
// a reaction would quote it back (CAP-3, #2360). Guarded texts stay, so a
// reaction to a live request or code is still read as one and never
// reaches the agent as chat; their events never show their text.
func (r *recentWindow) forget(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept := r.texts[:0:0]
	for _, t := range r.texts {
		if t.guarded() {
			kept = append(kept, t)
		}
	}
	r.texts = kept
	r.forgets++
	r.forgotAt = now
}

// forgotWithin reports whether a deletion forgot texts that would still be
// in the window at now.
func (r *recentWindow) forgotWithin(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return !r.forgotAt.IsZero() && now.Sub(r.forgotAt) <= recentMaxAge
}

// gen is the number of deletions that cleared the window.
func (r *recentWindow) gen() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.forgets
}

func (r *recentWindow) add(t sentText) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, t)
	if n := len(r.texts) - recentTexts; n > 0 {
		r.texts = append(r.texts[:0:0], r.texts[n:]...)
	}
}

// match finds the latest recent text the quote marks: the same text, or,
// for a quote of at least minQuote characters, one that holds it (phones
// cut long quotes, usually with an ellipsis, and some quote a part).
func (r *recentWindow) match(quoted string, now time.Time) (sentText, bool) {
	q := normQuote(quoted)
	if q == "" {
		return sentText{}, false
	}
	short := utf8.RuneCountInString(q) < minQuote
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.texts) - 1; i >= 0; i-- {
		t := r.texts[i]
		if now.Sub(t.at) > recentMaxAge {
			break
		}
		if n := normQuote(t.text); n == q || (!short && strings.Contains(n, q)) {
			return t, true
		}
	}
	return sentText{}, false
}

// normQuote folds quotes and case, collapses whitespace, and drops a
// trailing ellipsis.
func normQuote(s string) string {
	s = strings.NewReplacer("“", `"`, "”", `"`, "‘", "'", "’", "'").Replace(s)
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	for _, e := range []string{"…", "..."} {
		s = strings.TrimSpace(strings.TrimSuffix(s, e))
	}
	return s
}

// carriesCode matches a box text that holds a code or a challenge token: a
// run of digits (texted codes, RESUME codes) or the token after UNLOCK or
// RESUME (4 letters and digits). A reaction event never shows such a text
// to the agent.
var carriesCode = regexp.MustCompile(`[0-9]{4,}|\b(?:UNLOCK|RESUME) [A-HJ-NP-Z2-9]{4}\b`)

// ForgetRecent is a deletion's reach into the owner channel (CAP-3,
// #2360): it drops the recent texts a reaction would show the agent and a
// held reaction's event, and voids any event worded before it that has not
// gone to the agent. An event being delivered when it runs finishes first,
// so none quoting a forgotten text reaches the agent once it returns. The
// deletion's time is saved, so the 24 h rule outlives a restart.
func (c *Channel) ForgetRecent() {
	c.reactMu.Lock()
	defer c.reactMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	c.recent.forget(now)
	// A failed save still holds for this run; only a restart before the
	// next save would lose it.
	_ = c.saveLocked(func(s *State) { s.ForgotAt = now })
	if c.held != nil && c.held.react != "" {
		c.held = nil
	}
}

// deliverReaction gives rt's reaction event to the agent, unless a
// deletion cleared the recent texts after it was worded: its quote may be
// of a forgotten text, so it is dropped (CAP-3, #2360).
func (c *Channel) deliverReaction(ctx context.Context, from string, rt route) []string {
	c.reactMu.RLock()
	defer c.reactMu.RUnlock()
	c.mu.Lock()
	stale := c.recent.gen() != rt.reactGen
	if !stale {
		c.active = rt.at
	}
	c.mu.Unlock()
	if stale {
		return nil
	}
	return c.ctrl.Event(ctx, from, rt.react)
}

// reactionEvent is the broker-worded text the agent gets for rx, and the
// pointer the owner gets when the marked text expects a reply.
func (c *Channel) reactionEvent(rx reaction) (event, pointer string) {
	t, ok := c.recent.match(rx.quoted, c.cfg.Now())
	if !ok {
		return fmt.Sprintf("Owner reaction: %s a text that matched none of the recent texts.", rx.kind), ""
	}
	switch {
	case t.request:
		event = fmt.Sprintf("Owner reaction: %s an approval request (not shown). A reaction does not answer it.", rx.kind)
	case strings.HasPrefix(t.text, AgentPrefix):
		// The agent's own text: no pointer, so the broker never vouches
		// for replies the agent's words name.
		return fmt.Sprintf("Owner reaction: %s your text %q", rx.kind, strings.TrimPrefix(t.text, AgentPrefix)), ""
	case carriesCode.MatchString(t.text):
		event = fmt.Sprintf("Owner reaction: %s a text from the box with a code in it (not shown).", rx.kind)
	default:
		event = fmt.Sprintf("Owner reaction: %s the box's text %q", rx.kind, t.text)
	}
	return event, replyPointer(t)
}

// recordReplies adds the texts Handle returns for the owner to the recent
// texts: the daemon sends them over the owner socket, not this channel's
// line, so watchedLine never sees them.
func (c *Channel) recordReplies(from string, out []string) {
	if from != c.cfg.Owner {
		return
	}
	now := c.cfg.Now()
	for _, t := range out {
		c.recent.add(sentText{text: t, at: now})
	}
}

// replyPointer is one line naming the valid replies to a text that
// expects one (an approval request, a RUN offer, any "Reply …"), sent to
// the owner as conversation. It is for the box's own texts only. A
// request's IDs come from the broker's record, never from the text: a
// request carries agent words (an item's object), which could name
// another request.
func replyPointer(t sentText) string {
	if t.request {
		switch {
		case len(t.ids) == 1 && t.local:
			return fmt.Sprintf("A reaction does not approve anything. Approve or deny %s on my Wi-Fi page, or reply NO %s.", t.ids[0], t.ids[0])
		case len(t.ids) == 1:
			return fmt.Sprintf("A reaction does not approve anything. Reply YES %s with the code that text asks for, or NO %s.", t.ids[0], t.ids[0])
		case len(t.ids) > 1:
			return fmt.Sprintf("A reaction does not approve anything. That text asks %s: reply YES or NO with an ID, as it says.", strings.Join(t.ids, ", "))
		}
		return "A reaction is not a reply. Reply in words, as that text says."
	}
	if strings.Contains(t.text, "Reply RUN") {
		return "A reaction does not send it. Reply RUN to send the held message."
	}
	if strings.Contains(t.text, "Reply ") || strings.Contains(t.text, "reply ") {
		return "A reaction is not a reply. Reply in words, as that text says."
	}
	return ""
}

// reactionLocked routes an owner reaction: held while locked, delivered as
// its event while unlocked (CH-3, CH-14).
func (c *Channel) reactionLocked(text string, rx reaction, now time.Time, unlocked bool) route {
	event, pointer := c.reactionEvent(rx)
	var replies []string
	if rx.tell {
		replies = append(replies, readAsReaction)
	}
	if pointer != "" {
		replies = append(replies, pointer)
	}
	if unlocked {
		return route{replies: replies, react: event, reactGen: c.recent.gen()}
	}
	if c.held != nil {
		c.held = nil
		return route{replies: append([]string{"Locked. A message was already waiting, so both were dropped. " +
			"Send your message with a code from your code generator at the end."}, replies...), limited: true}
	}
	c.held = &heldMsg{text: text, react: event, expires: now.Add(c.cfg.CodeTTL)}
	return route{replies: append([]string{fmt.Sprintf("Locked. Your reaction is held for %s. %s",
		dur(c.cfg.CodeTTL), c.unlockPrompt())}, replies...), limited: true}
}
