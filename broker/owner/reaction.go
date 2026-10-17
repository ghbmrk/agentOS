package owner

import (
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
var reactionForm = regexp.MustCompile(`(?is)^(liked|loved|disliked|laughed at|emphasized|questioned|` +
	`removed a like from|removed a heart from|removed a dislike from|removed a laugh from|` +
	`removed an exclamation from|removed a question mark from|reacted \S+ to) ` +
	`["“](.+)["”]$`)

// reaction is one owner reaction: its kind in lower case, as the agent
// reads it, and the quoted text.
type reaction struct {
	kind   string
	quoted string
}

// parseReaction reports whether text, whole, is a reaction form.
func parseReaction(text string) (reaction, bool) {
	m := reactionForm.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil || strings.TrimSpace(m[2]) == "" {
		return reaction{}, false
	}
	kind := strings.Join(strings.Fields(strings.ToLower(m[1])), " ")
	return reaction{kind: kind, quoted: m[2]}, true
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
	request bool // an approval request (SendRequest)
}

// recentWindow is the window of texts to the owner.
type recentWindow struct {
	mu    sync.Mutex
	texts []sentText
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

// manyDigits are runs a reaction event never passes to the agent: codes
// and the like in the box's own texts.
var manyDigits = regexp.MustCompile(`[0-9]{4,}`)

var (
	replyYes = regexp.MustCompile(`Reply YES ([A-Z][0-9A-Z]{0,2})\b`)
	replyQ   = regexp.MustCompile(`Reply (Q[0-9]+) and your answer`)
)

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
		event = fmt.Sprintf("Owner reaction: %s your text %q", rx.kind, strings.TrimPrefix(t.text, AgentPrefix))
	default:
		event = fmt.Sprintf("Owner reaction: %s the box's text %q", rx.kind, manyDigits.ReplaceAllString(t.text, "[digits]"))
	}
	return event, replyPointer(t)
}

// replyPointer is one line naming the valid replies to a text that
// expects one (an approval request, a question, a RUN offer), sent to the
// owner as conversation.
func replyPointer(t sentText) string {
	if m := replyYes.FindStringSubmatch(t.text); m != nil {
		return fmt.Sprintf("A reaction does not approve anything. Reply YES %s with the code that text asks for, or NO %s.", m[1], m[1])
	}
	if strings.Contains(t.text, "Reply RUN") {
		return "A reaction does not send it. Reply RUN to send the held message."
	}
	if m := replyQ.FindStringSubmatch(t.text); m != nil {
		return fmt.Sprintf("A reaction is not an answer. Reply %s and your answer.", m[1])
	}
	if t.request || strings.Contains(t.text, "Reply ") {
		return "A reaction is not a reply. Reply in words, as that text says."
	}
	return ""
}

// reactionLocked routes an owner reaction: held while locked, delivered as
// its event while unlocked (CH-3, CH-14).
func (c *Channel) reactionLocked(text string, rx reaction, now time.Time, unlocked bool) route {
	event, pointer := c.reactionEvent(rx)
	var replies []string
	if pointer != "" {
		replies = append(replies, pointer)
	}
	if unlocked {
		return route{replies: replies, react: event}
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
