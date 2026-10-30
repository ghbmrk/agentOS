package owner

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
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
	lead string // an unlisted form's lead-in, for the STOP hint (#2264)
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

// cutForm is unlistedForm for a quote a phone cut short, which has no
// closing quote (`Pinned “Liked “<request cut>…`). It is tried only after
// unlistedForm and counts only as the quote of a guarded text, as that is.
var cutForm = regexp.MustCompile(`(?s)^([\p{L}\p{M}\p{N}\p{P}\p{So}\p{Sk} ]{1,40}?) ["“](.+)$`)

// shapeForm is the lead-in and quote of text if it has the shape of an
// unlisted form, closed or cut.
func shapeForm(text string) (lead, quote string, ok bool) {
	text = strings.TrimSpace(text)
	for _, re := range []*regexp.Regexp{unlistedForm, cutForm} {
		if m := re.FindStringSubmatch(text); m != nil {
			return m[1], m[2], len(strings.Fields(m[1])) <= 5
		}
	}
	return "", "", false
}

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
		// A form whose quote holds quote marks may be a nest round a
		// guarded text (`Liked “Loved “<request>””`).
		if _, found := c.recent.matchGuarded(rx.quoted, now); found {
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
	lead, quote, ok := shapeForm(text)
	if !ok {
		return reaction{}, false
	}
	now := c.cfg.Now()
	unlisted := reaction{kind: "reacted to", quoted: quote, tell: true, lead: lead}
	if _, ok := c.recent.matchGuarded(quote, now); ok {
		return unlisted, true
	}
	// After a deletion an unlisted form may quote a forgotten reply, which
	// as chat would reach the agent whole: read it as a reaction until the
	// forgotten texts are past the window (CAP-3, #2360), as a listed form
	// is above. Agent text carries no label (CH-21), so the quote cannot
	// tell a forgotten reply from other text; every unlisted form counts.
	// A forgotten text no longer matches, so its event matches none.
	if c.recent.forgotWithin(now) {
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
	// matched against, by count and by age; guarded texts are counted
	// apart (put).
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
	agent   bool     // the agent's words (sendOwner), not the broker's
	ids     []string // the requests it asks, from the broker's record
	local   bool     // approvable on the local page only
	// restored marks a guarded text read back from State.Guarded after a
	// restart: text is then normalized and code-masked (maskCodes), and
	// request says whether it was an approval request.
	restored bool
}

// guarded reports whether a reaction to t is never shown to the agent with
// its text: an approval request, or a box text that holds a code (CH-3).
// The agent's own text is never guarded: its digits already passed
// Disclose.
func (t sentText) guarded() bool {
	return t.restored || t.request || (!t.agent && carriesCode.MatchString(t.text))
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

func (r *recentWindow) add(t sentText) { r.put(t, nil) }

// put adds t and prunes the window. Guarded texts are kept apart from the
// cap on the others, so later box texts never push a live request out
// (#2392): each kind keeps its latest recentTexts within recentMaxAge, and
// a request that open reports still open stays, uncounted, until it ages
// out, so there are at most recentTexts plus MaxOpen guarded texts and
// requests the agent opens never push a box code out. open is called with the
// channel's mu held. Only a guarded text, put with open, prunes guarded
// texts; add (open nil) leaves them to age out, since it cannot tell
// which requests are open.
func (r *recentWindow) put(t sentText, open func(id string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.texts = append(r.texts, t)
	var kept []sentText
	guarded, plain := 0, 0
	for i := len(r.texts) - 1; i >= 0; i-- {
		s := r.texts[i]
		if t.at.Sub(s.at) > recentMaxAge {
			break
		}
		switch {
		case !s.guarded():
			if plain++; plain > recentTexts {
				continue
			}
		case open != nil && slices.ContainsFunc(s.ids, open):
			// An open request is not counted, so requests the agent opens
			// never push a box code out.
		case open == nil || guarded < recentTexts:
			guarded++
		default:
			continue
		}
		kept = append(kept, s)
	}
	slices.Reverse(kept)
	r.texts = kept
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
	forms := maskedForms(q)
	// A short quote that holds a code or ends inside one is a cut of a
	// guarded text when that text holds it: as chat it would carry the
	// code's digits to the agent (#2392). Other short quotes match whole.
	cut := short && slices.ContainsFunc(forms, func(f string) bool { return f != q })
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.texts) - 1; i >= 0; i-- {
		t := r.texts[i]
		if now.Sub(t.at) > recentMaxAge {
			break
		}
		if !t.restored {
			n := normQuote(t.text)
			if n == q || ((!short || cut && t.guarded()) && strings.Contains(n, q)) {
				return t, true
			}
			continue
		}
		for _, mq := range forms {
			if t.text == mq || ((!short || cut) && strings.Contains(t.text, mq)) {
				return t, true
			}
		}
	}
	return sentText{}, false
}

// nestDepth bounds how many forms a quote is peeled through.
const nestDepth = 6

// quoteLayers is the quote and the quotes inside it: while a layer is
// itself a reaction form, its own quote is the next layer. A phone that
// reacts to a reaction sends such a nest (`Pinned “Liked “<text>””`).
func quoteLayers(quoted string) []string {
	layers := []string{quoted}
	for len(layers) < nestDepth {
		inner, ok := peelForm(layers[len(layers)-1])
		if !ok {
			break
		}
		layers = append(layers, inner)
	}
	return layers
}

// peelForm is the quote of text if text is a listed or unlisted form.
func peelForm(text string) (string, bool) {
	if rx, ok := parseForm(text); ok {
		return rx.quoted, true
	}
	_, quote, ok := shapeForm(text)
	return quote, ok
}

// matchGuarded finds a guarded text the quote marks, however it is
// wrapped: the quote is the text, or part of it, or a form around either
// (quoteLayers), or other words around the whole text. Only guarded texts
// count, so a nest around the agent's own text stays chat (CH-11).
func (r *recentWindow) matchGuarded(quoted string, now time.Time) (sentText, bool) {
	for _, l := range quoteLayers(quoted) {
		if t, ok := r.match(l, now); ok && t.guarded() {
			return t, true
		}
		if t, ok := r.within(l, now); ok {
			return t, true
		}
	}
	return sentText{}, false
}

// within finds the latest guarded text, of at least minQuote characters,
// that the quote holds whole.
func (r *recentWindow) within(quoted string, now time.Time) (sentText, bool) {
	q := normQuote(quoted)
	mq := maskCodes(q)
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.texts) - 1; i >= 0; i-- {
		t := r.texts[i]
		if now.Sub(t.at) > recentMaxAge {
			break
		}
		if !t.guarded() {
			continue
		}
		n, hay := normQuote(t.text), q
		if t.restored {
			n, hay = t.text, mq
		}
		if utf8.RuneCountInString(n) >= minQuote && strings.Contains(hay, n) {
			return t, true
		}
	}
	return sentText{}, false
}

// maskCodes replaces every code and challenge token in s with "#", so a
// text can be kept and matched without its code.
// It is blind to case, as s is usually normalized (lowercased) already.
func maskCodes(s string) string { return maskCode.ReplaceAllString(s, "#") }

// maskCode is carriesCode in any case.
var maskCode = regexp.MustCompile(`(?i)` + carriesCode.String())

// cutCodeTail and cutCodeHead match the part of a code a quote ends or
// starts inside: 1 to 3 digits, or part of a challenge token. The part is
// too short for maskCodes.
var (
	cutCodeTail = regexp.MustCompile(`(?i)(?:[0-9]{1,3}|\b(?:unlock|resume)(?: [a-z0-9]{1,3})?)$`)
	cutCodeHead = regexp.MustCompile(`^[0-9]{1,3}`)
)

// maskedForms is the normalized quote q with its codes masked, and, if it
// ends or starts inside a code, with that part masked too: the head alone,
// the tail alone, and both, since a quote may be cut inside a code at one
// end while the other end holds digits that are no code (a time, a
// request's ID). A text kept masked (restore) is matched against these.
func maskedForms(q string) []string {
	m := maskCodes(q)
	head := cutCodeHead.ReplaceAllString(m, "#")
	tail := cutCodeTail.ReplaceAllString(m, "#")
	both := cutCodeHead.ReplaceAllString(tail, "#")
	forms := []string{m}
	for _, f := range []string{head, tail, both} {
		if !slices.Contains(forms, f) {
			forms = append(forms, f)
		}
	}
	return forms
}

// restore puts the saved guarded texts back in the window after a restart,
// the ones still inside its age.
func (r *recentWindow) restore(marks []GuardedMark, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range marks {
		if now.Sub(m.At) <= recentMaxAge {
			r.texts = append(r.texts, sentText{text: m.Text, at: m.At, request: m.Request, restored: true})
		}
	}
}

// remember adds t to the recent texts and, if it is guarded, to the saved
// guard, with its codes masked, so a restart keeps guarding it (CH-3,
// #2381). Nothing is saved that is not already on disk but the words of a
// text the owner's phone holds too.
func (c *Channel) remember(t sentText) {
	if !t.guarded() {
		c.recent.add(t)
		return
	}
	m := GuardedMark{Text: maskCodes(normQuote(t.text)), At: t.at, Request: t.request}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recent.put(t, func(id string) bool { return c.open[id] != nil })
	_ = c.saveLocked(func(s *State) {
		keep := s.Guarded[:0:0]
		for _, g := range s.Guarded {
			if t.at.Sub(g.At) <= recentMaxAge {
				keep = append(keep, g)
			}
		}
		keep = append(keep, m)
		if n := len(keep) - recentTexts; n > 0 {
			keep = append(keep[:0:0], keep[n:]...)
		}
		s.Guarded = keep
	})
}

// normQuote folds quotes and case, collapses whitespace, and drops every
// leading and trailing ellipsis (a phone cuts a quote at either end, and
// a cut of a cut adds another).
func normQuote(s string) string {
	s = strings.NewReplacer("“", `"`, "”", `"`, "‘", "'", "’", "'").Replace(s)
	s = strings.ToLower(strings.Join(strings.Fields(s), " "))
	for prev := ""; s != prev; {
		prev = s
		for _, e := range []string{"…", "..."} {
			s = strings.TrimSpace(strings.TrimSuffix(s, e))
			s = strings.TrimSpace(strings.TrimPrefix(s, e))
		}
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
// deletion's time is saved, so the 24 h rule outlives a restart. It
// returns how many held agent texts it dropped, for the forget reply
// (CAP3-F1): a count, never their text.
func (c *Channel) ForgetRecent() int {
	c.reactMu.Lock()
	defer c.reactMu.Unlock()
	// pmu first, as every pacing path takes it: a release in flight
	// finishes before the hold is cleaned, so none sends after this
	// returns.
	c.pmu.Lock()
	defer c.pmu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	c.recent.forget(now)
	// A failed save still holds for this run; only a restart before the
	// next save would lose it. The held agent texts go in the same save:
	// each may quote a forgotten reply, and a release would send it after
	// the deletion and put it back in the window (#2374). They are not
	// counted in HeldDropped, so no released notice speaks of them; the
	// forget reply counts them instead (CAP3-F1).
	dropped := 0
	_ = c.saveLocked(func(s *State) {
		s.ForgotAt = now
		keep := s.Held[:0:0]
		for _, h := range s.Held {
			if !h.Agent {
				keep = append(keep, h)
			}
		}
		dropped = len(s.Held) - len(keep)
		s.Held = keep
	})
	if c.held != nil && c.held.react != "" {
		c.held = nil
	}
	return dropped
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
	return c.ctrl.Event(context.WithValue(ctx, eventDelivery{}, true), from, rt.react)
}

// eventDelivery marks a delivery as an event, not task chat, so it arms
// no acknowledgement (OWN-4).
type eventDelivery struct{}

// reactionEvent is the broker-worded text the agent gets for rx, and the
// pointer the owner gets when the marked text expects a reply.
func (c *Channel) reactionEvent(rx reaction) (event, pointer string) {
	now := c.cfg.Now()
	t, ok := c.recent.match(rx.quoted, now)
	if !ok {
		t, ok = c.recent.matchGuarded(rx.quoted, now)
	}
	if !ok {
		return fmt.Sprintf("Owner reaction: %s a text that matched none of the recent texts.", rx.kind), ""
	}
	switch {
	case t.request:
		event = fmt.Sprintf("Owner reaction: %s an approval request (not shown). A reaction does not answer it.", rx.kind)
	case t.agent:
		// The agent's own text: no pointer, so the broker never vouches
		// for replies the agent's words name.
		return fmt.Sprintf("Owner reaction: %s your text %q", rx.kind, t.text), ""
	case t.restored || carriesCode.MatchString(t.text):
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
		c.remember(sentText{text: t, at: now})
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
		if hint, ok := c.ctrl.StopHint(rx.lead); ok {
			replies = append(replies, hint)
		}
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
