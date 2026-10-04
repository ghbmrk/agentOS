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
	// Facts classify the reply if it becomes an approval request.
	Facts Facts
}

// Queued is a reply waiting out its undo window.
type Queued struct {
	ID     string
	SendAt time.Time
	Reply  AutoReply
}

type queuedReply struct {
	Queued
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
// filter (amounts, dates, commitment phrases, or secret-shaped content)
// becomes a normal approval request. Otherwise it is queued for the undo
// window and the owner is texted its first line and UNDO <id> (CH-16).
func (c *Channel) QueueAutoReply(ar AutoReply) (QueueResult, error) {
	if c.cfg.Modem == nil {
		return QueueResult{}, errors.New("owner: no modem")
	}
	if len(ar.Recipients) == 0 || strings.TrimSpace(ar.Body) == "" {
		return QueueResult{}, errors.New("owner: an auto-reply needs recipients and a body")
	}
	to := strings.Join(ar.Recipients, ", ")
	if m := c.cfg.Commitments.Match(ar.Body); m != "" {
		id, err := c.Request([]Item{{
			Ref: ar.Ref, Verb: "send", Object: "reply (" + m + ")", Recipient: to, Facts: ar.Facts,
		}}, 0)
		return QueueResult{Request: id, Matched: m}, err
	}
	now := c.cfg.Now()
	c.mu.Lock()
	q := &queuedReply{Queued{ID: c.newIDLocked(), SendAt: now.Add(c.cfg.UndoWindow), Reply: ar}}
	c.queued[q.ID] = q
	text := fmt.Sprintf("Auto-reply to %s: \"%s\". Sends %s. Reply UNDO %s to stop it.",
		field(to, 40), field(firstLine(ar.Body), 60), q.SendAt.In(c.cfg.Location).Format("15:04"), q.ID)
	c.mu.Unlock()
	if err := c.cfg.Modem.Send(c.cfg.Owner, text); err != nil {
		// No alert, no send: ADP-11 allows a reply only with its alert.
		c.mu.Lock()
		delete(c.queued, q.ID)
		c.mu.Unlock()
		return QueueResult{}, err
	}
	out := q.Queued
	return QueueResult{Queued: &out}, nil
}

// DueAutoReplies returns and removes replies whose undo window has passed;
// the caller sends them through the account's adapter.
func (c *Channel) DueAutoReplies() []Queued {
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Queued
	for id, q := range c.queued {
		if !now.Before(q.SendAt) {
			out = append(out, q.Queued)
			delete(c.queued, id)
		}
	}
	return out
}

// undoLocked cancels a queued reply inside its window (CH-16).
func (c *Channel) undoLocked(id string, now time.Time) string {
	q := c.queued[id]
	if q == nil {
		return fmt.Sprintf("Nothing to undo for %s.", id)
	}
	if !now.Before(q.SendAt) {
		return fmt.Sprintf("%s is past its undo window.", id)
	}
	delete(c.queued, id)
	return fmt.Sprintf("Cancelled %s. The reply was not sent.", id)
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
