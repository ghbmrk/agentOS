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

// Boot reports what a restart dropped (OP-4, CH-13). Every old code dies:
// each request open at shutdown is retired. With Config.Reissue set, the
// items of a request not yet expired are handed to it to be re-sent with
// new codes, and those that expired meanwhile are decided as denied with
// Why "expired". Without it, or for a request recorded without its expiry,
// they are decided as denied with Why "restart". Each auto-reply still
// queued is decided as denied with Why "restart". The decided items are
// listed for the digest, and the owner is texted what was re-sent,
// cancelled, expired, and not sent. Run calls it; it does nothing the
// second time.
func (c *Channel) Boot() {
	now := c.cfg.Now()
	c.mu.Lock()
	b := c.boot
	c.boot = nil
	if b == nil || (len(b.pending) == 0 && len(b.queued) == 0) {
		c.mu.Unlock()
		if b != nil && c.cfg.Reissue != nil {
			c.cfg.Reissue(nil)
		}
		return
	}
	var decided []Decision
	var carried []Carried
	var resent, reqs, expired, replies []string
	for _, p := range b.pending {
		keep := c.cfg.Reissue != nil && !p.Expires.IsZero() && len(p.Sums) == len(p.Refs)
		switch {
		case keep && now.Before(p.Expires):
			resent = append(resent, p.ID)
			for i, ref := range p.Refs {
				carried = append(carried, Carried{Ref: ref, Request: p.ID, Asked: p.Asked, Expires: p.Expires, Sum: p.Sums[i]})
			}
		case keep:
			expired = append(expired, p.ID)
			for i, ref := range p.Refs {
				decided = append(decided, Decision{Request: p.ID, Item: i + 1, Ref: ref, Why: "expired"})
			}
		default:
			reqs = append(reqs, p.ID)
			for i, ref := range p.Refs {
				decided = append(decided, Decision{Request: p.ID, Item: i + 1, Ref: ref, Why: "restart"})
			}
		}
	}
	for _, q := range b.queued {
		replies = append(replies, q.ID)
		decided = append(decided, Decision{Request: q.ID, Item: 1, Ref: q.Ref, Why: "restart"})
	}
	c.addExpiredLocked(decided)
	for _, p := range b.pending {
		c.retireLocked(p.ID, now)
	}
	for _, id := range replies {
		c.retireLocked(id, now)
	}
	text := "Box restarted."
	if len(resent) > 0 {
		text += " Old codes no longer work. " + strings.Join(resent, ", ") + " will be re-sent with new codes unless the details changed."
	}
	if len(reqs) > 0 {
		text += " Cancelled requests: " + strings.Join(reqs, ", ") + "."
	}
	if len(expired) > 0 {
		text += " Expired: " + strings.Join(expired, ", ") + "."
	}
	if len(replies) > 0 {
		text += " Auto-replies not sent: " + strings.Join(replies, ", ") + "."
	}
	if len(reqs)+len(expired)+len(replies) > 0 {
		text += " Ask your agent again if still needed."
	}
	if !fits(text) {
		text = fmt.Sprintf("Box restarted. %d requests re-sent with new codes, %d cancelled, %d expired, and %d auto-replies not sent.",
			len(resent), len(reqs), len(expired), len(replies))
	}
	c.mu.Unlock()
	if c.cfg.Modem != nil {
		_ = c.cfg.Modem.Send(c.cfg.Owner, text)
	}
	c.decide(decided)
	if c.cfg.Reissue != nil {
		c.cfg.Reissue(carried)
	}
}
