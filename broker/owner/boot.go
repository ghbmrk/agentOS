package owner

import (
	"fmt"
	"strings"
)

// bootReport is what the previous run left open: requests and queued
// auto-replies, by reference. A restart loses their codes and bodies by
// design (codes are never persisted), so they are closed and reported.
type bootReport struct {
	pending []PendingRef
	queued  []QueuedRef
}

// Boot reports what a restart dropped (OP-4, CH-13): each item of a
// request open at shutdown, and each auto-reply still queued, is decided
// as denied with Why "restart" and listed for the digest, and the owner is texted which requests were
// cancelled and which auto-replies were not sent. Run calls it; it does
// nothing the second time.
func (c *Channel) Boot() {
	now := c.cfg.Now()
	c.mu.Lock()
	b := c.boot
	c.boot = nil
	if b == nil || (len(b.pending) == 0 && len(b.queued) == 0) {
		c.mu.Unlock()
		return
	}
	var decided []Decision
	var reqs, replies []string
	for _, p := range b.pending {
		reqs = append(reqs, p.ID)
		for i, ref := range p.Refs {
			decided = append(decided, Decision{Request: p.ID, Item: i + 1, Ref: ref, Why: "restart"})
		}
	}
	for _, q := range b.queued {
		replies = append(replies, q.ID)
		decided = append(decided, Decision{Request: q.ID, Item: 1, Ref: q.Ref, Why: "restart"})
	}
	c.addExpiredLocked(decided)
	for _, id := range append(append([]string(nil), reqs...), replies...) {
		c.retireLocked(id, now)
	}
	text := "Box restarted."
	if len(reqs) > 0 {
		text += " Cancelled requests: " + strings.Join(reqs, ", ") + "."
	}
	if len(replies) > 0 {
		text += " Auto-replies not sent: " + strings.Join(replies, ", ") + "."
	}
	text += " Ask your agent again if still needed."
	if !fits(text) {
		text = fmt.Sprintf("Box restarted. %d requests cancelled and %d auto-replies not sent. Ask your agent again if still needed.",
			len(reqs), len(replies))
	}
	c.mu.Unlock()
	c.decide(decided)
	if c.cfg.Modem != nil {
		_ = c.cfg.Modem.Send(c.cfg.Owner, text)
	}
}
