package owner

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// AutoReply is a context-scoped reply the agent composed under an ADP-11
// pre-allowance. The broker has already checked the rule's other conditions
// (earned, verified thread starter, recipients read from the source, no
// attachments or money); this package applies the commitment filter and
// the alert with undo.
type AutoReply struct {
	Ref string
	// Recipients are canonical identifiers read from the thread.
	Recipients []string
	Body       string
	// Facts classify the reply if it becomes an approval request. Verb
	// defaults to "send".
	Facts Facts
}

// Queued is a reply waiting out its undo window.
type Queued struct {
	ID     string
	SendAt time.Time
	Reply  AutoReply
}

// QueueResult says what happened to a reply.
type QueueResult struct {
	// Queued is set when the reply waits out the undo window.
	Queued *Queued
	// Request is the approval request ID when the commitment filter
	// matched; Matched names the pattern class.
	Request string
	Matched string
}

// QueueAutoReply applies ADP-11. A reply that matches the commitment
// filter (secret-shaped content, amounts, dates, commitment phrases)
// becomes a normal approval request. Otherwise it is queued for the undo
// window and the owner is texted its first line and UNDO <id> (CH-16). If
// the alert cannot be sent, the reply is dropped.
func (c *Channel) QueueAutoReply(ar AutoReply) (QueueResult, error) {
	if c.cfg.Modem == nil {
		return QueueResult{}, errors.New("owner: no modem")
	}
	if len(ar.Recipients) == 0 || strings.TrimSpace(ar.Body) == "" {
		return QueueResult{}, errors.New("owner: an auto-reply needs recipients and a body")
	}
	to := strings.Join(ar.Recipients, ", ")
	if m := c.cfg.Commitments.Match(ar.Body); m != "" {
		f := ar.Facts
		if f.Verb == "" {
			f.Verb = "send"
		}
		id, err := c.Request([]Item{{Ref: ar.Ref, Object: "reply (" + m + ")", Recipient: to, Facts: f}}, 0)
		return QueueResult{Request: id, Matched: m}, err
	}
	now := c.cfg.Now()
	c.mu.Lock()
	if len(c.open)+len(c.queued) >= MaxOpen {
		c.mu.Unlock()
		return QueueResult{}, ErrFull
	}
	id, err := c.newIDLocked(now)
	if err != nil {
		c.mu.Unlock()
		return QueueResult{}, err
	}
	if err := c.codes.commit(func(s *State) { s.Queued = append(s.Queued, QueuedRef{ID: id, Ref: ar.Ref}) }); err != nil {
		c.mu.Unlock()
		return QueueResult{}, err
	}
	q := &Queued{ID: id, SendAt: now.Add(c.cfg.UndoWindow), Reply: ar}
	c.queued[id] = q
	text := fmt.Sprintf("Auto-reply to %s: \"%s\". Sends %s. Reply UNDO %s to stop it.",
		field(to, 40), field(firstLine(ar.Body), 60), q.SendAt.In(c.cfg.Location).Format("15:04"), id)
	c.mu.Unlock()
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		c.mu.Lock()
		delete(c.queued, id)
		c.retireLocked(id, now)
		c.mu.Unlock()
		return QueueResult{}, err
	}
	out := *q
	return QueueResult{Queued: &out}, nil
}

// DueAutoReplies returns and removes replies whose undo window has passed;
// the caller sends them through the account's adapter. Nothing is released
// while the broker is stopped (ADP-11: STOP applies).
func (c *Channel) DueAutoReplies() []Queued {
	if c.cfg.Engine.Stopped() {
		return nil
	}
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Queued
	for id, q := range c.queued {
		if !now.Before(q.SendAt) {
			out = append(out, *q)
			delete(c.queued, id)
			c.retireLocked(id, now)
		}
	}
	return out
}

// undoLocked cancels a queued reply inside its window (CH-16); the reply's
// item is decided as denied with Why "undo".
func (c *Channel) undoLocked(id string, now time.Time, decided *[]Decision) string {
	q := c.queued[id]
	if q == nil {
		return fmt.Sprintf("Nothing to undo for %s.", id)
	}
	if !now.Before(q.SendAt) {
		return fmt.Sprintf("%s is past its undo window.", id)
	}
	delete(c.queued, id)
	c.retireLocked(id, now)
	*decided = append(*decided, Decision{Request: id, Item: 1, Ref: q.Reply.Ref, Why: "undo"})
	return fmt.Sprintf("Cancelled %s. The reply was not sent.", id)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
