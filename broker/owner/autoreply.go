package owner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
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

// Queued is a reply, or an approved effect (Held), waiting out its undo
// window. A held effect's Reply carries only its Ref.
type Queued struct {
	ID     string
	SendAt time.Time
	Reply  AutoReply
	Held   bool
	// Late is set at release on a reply (not a held effect) released more
	// than LateRelease after its window, or whose window saw the box's
	// line fail to send: its silence is not the owner's (security B1(a)
	// on PW3), so it is never read as an implicit acceptance.
	Late bool
	// Alerted is when the owner was texted the reply's alert; zero for a
	// held effect, or before the alert went out.
	Alerted time.Time
}

// LateRelease is how long after its window a queued reply may be released
// and still count as on time: the daemon releases every minute.
const LateRelease = 2 * time.Minute

// watchedLine records when the box's line fails to send.
type watchedLine struct {
	modem.Modem
	c *Channel
}

func (w watchedLine) Send(to, text string) error {
	err := w.Modem.Send(to, text)
	if err != nil {
		w.c.lineFailed.Store(w.c.cfg.Now().UnixNano())
	}
	return err
}

// ContextSender can cancel a local send wait. Cancellation does not establish
// remote non-delivery; callers must inspect the transport's evidence.
type ContextSender interface {
	SendContext(context.Context, string, string) error
}

var ErrContextSendUnsupported = errors.New("owner: modem does not support context send")
var ErrContextSendRequired = errors.New("owner: send context is required")

func (w watchedLine) SendContext(ctx context.Context, to, text string) error {
	sender, ok := w.Modem.(ContextSender)
	if !ok {
		return ErrContextSendUnsupported
	}
	err := sender.SendContext(ctx, to, text)
	// A nested watched modem may expose ContextSender but refuse before any
	// transport call. Only that exact sentinel is non-attempt evidence:
	// joined/wrapped errors may still include an actual line failure.
	if err != nil && err != ErrContextSendUnsupported {
		w.c.lineFailed.Store(w.c.cfg.Now().UnixNano())
	}
	return err
}

// LineDown says err is the owner's line being down (modem.ErrDown): the
// text did not go, and asking again later may reach the owner.
func LineDown(err error) bool { return errors.Is(err, modem.ErrDown) }

// RequestSender is a modem that tells an approval request apart from the
// channel's other texts: the modem bridge's link, whose recovery text
// counts the requests that did not go (UX on #170).
type RequestSender interface {
	SendRequest(to, text string) error
}

func (w watchedLine) SendRequest(to, text string) error {
	rs, ok := w.Modem.(RequestSender)
	if !ok {
		return w.Send(to, text)
	}
	err := rs.SendRequest(to, text)
	if err != nil {
		w.c.lineFailed.Store(w.c.cfg.Now().UnixNano())
	}
	return err
}

// sendRequest texts the owner an approval request.
func (c *Channel) sendRequest(text string) error {
	if rs, ok := c.cfg.Modem.(RequestSender); ok {
		return rs.SendRequest(c.cfg.Owner, text)
	}
	return c.cfg.Modem.Send(c.cfg.Owner, text)
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
	c.mu.Lock()
	q.Alerted = now
	out := *q
	c.mu.Unlock()
	return QueueResult{Queued: &out}, nil
}

// DueAutoReplies returns and removes replies and held effects whose undo
// window has passed; the caller runs them through the account's adapter. Nothing is released
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
			if !q.Held {
				failed := time.Unix(0, c.lineFailed.Load())
				q.Late = now.Sub(q.SendAt) > LateRelease || q.Alerted.IsZero() || !failed.Before(q.Alerted)
			}
			out = append(out, *q)
			delete(c.queued, id)
			c.retireLocked(id, now)
			c.released[id] = now
		}
	}
	for id, t := range c.released {
		if now.Sub(t) >= RetireFor {
			delete(c.released, id)
			delete(c.lateUndo, id)
		}
	}
	return out
}

// UndoneAfterRelease reports whether the owner texted UNDO for id after
// it was released: too late to stop it, but not silence the owner chose,
// so the gate reports no implicit acceptance for it (L3 MUST-4 on #109).
func (c *Channel) UndoneAfterRelease(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lateUndo[id]
}

// ResumeWindow is the fresh undo window RESUME gives each held effect or
// queued reply that STOP kept past, or close to, its release (UX-76-1).
const ResumeWindow = 2 * time.Minute

// undoLocked cancels a queued reply or held effect that has not been
// released (CH-16), whatever the clock: one that STOP kept past its window
// has still not run (UX-76-1). Its item is decided as denied with Why
// "undo"; a held effect's decision names its Hold.
func (c *Channel) undoLocked(id string, now time.Time, decided *[]Decision) string {
	q := c.queued[id]
	if q == nil {
		if _, ok := c.released[id]; ok {
			c.lateUndo[id] = true
			return fmt.Sprintf("%s is past its undo window; it was released.", id)
		}
		return fmt.Sprintf("Nothing to undo for %s.", id)
	}
	delete(c.queued, id)
	c.retireLocked(id, now)
	d := Decision{Request: id, Item: 1, Ref: q.Reply.Ref, Why: "undo"}
	if q.Held {
		d.Hold = id
	}
	*decided = append(*decided, d)
	if q.Held {
		return fmt.Sprintf("Cancelled %s. It did not run.", id)
	}
	return fmt.Sprintf("Cancelled %s. The reply was not sent.", id)
}

// rewindowLocked gives every queued reply and held effect due within
// ResumeWindow a fresh ResumeWindow, after a RESUME, and returns the
// sentence naming them (UX-76-1), or "" for none.
func (c *Channel) rewindowLocked(now time.Time) string {
	at := now.Add(ResumeWindow)
	var ids []string
	for id, q := range c.queued {
		if q.SendAt.Before(at) {
			q.SendAt = at
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	switch len(ids) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf(" %s runs at %s unless you reply UNDO %s.", ids[0], c.clock(at), ids[0])
	}
	s := fmt.Sprintf(" %s run at %s unless you reply UNDO and an ID.", strings.Join(ids, ", "), c.clock(at))
	if !fits("Resumed. 999 stopped actions may now run." + s) {
		s = fmt.Sprintf(" %d queued items run at %s unless you reply UNDO and an ID.", len(ids), c.clock(at))
	}
	return s
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
