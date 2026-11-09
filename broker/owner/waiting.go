package owner

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/ghbmrk/agentos/broker/modem"
)

// Sessions open on the page (CH-14, D-311). No text, call or code by text
// opens a session: the owner page does, at P3 (LocalSignIn). Every task
// message or reaction that arrives while the session is locked waits here,
// unauthenticated and in arrival order, and never reaches a guest or a
// model (D-080). The hold is bounded by size (HoldSegments, D-087): a
// message that would pass the bound is dropped, never an earlier one, so a
// spoofer cannot displace what the owner sent first. Each message is
// discarded UnlockFor after it arrives. The page shows each in full, and
// the owner's tap runs the ones it marks and discards the rest
// (LocalRunHeld), so the owner runs only text they have read.

// DefaultHoldSegments is CH-14's default bound on held text, in SMS
// segments (D-087).
const DefaultHoldSegments = 9

// WaitingMsg is one owner message held for the page.
type WaitingMsg struct {
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
	Text string    `json:"text"`
	// React marks a held reaction, set by the hold itself (reactionLocked)
	// so a forget drops exactly what was held as one (CAP-3).
	React bool `json:"react,omitempty"`
}

// waitingReply is the one reply a locked period gets (CH-14).
const waitingReply = "Locked. I kept your message for my Wi-Fi page: sign in there at home to read it and send it."

// segs is text's length in SMS segments, at least one.
func segs(text string) int {
	n, _ := modem.Segments(text)
	return max(n, 1)
}

// waitLocked keeps text for the page and returns the locked reply, which
// goes once per locked period (CH-14). A message that would pass the size
// bound, or that cannot be saved, is dropped and counted.
func (c *Channel) waitLocked(text string, react bool, now time.Time) route {
	st := c.codes.st
	used := 0
	for _, m := range st.Waiting {
		used += segs(m.Text)
	}
	tell := !st.WaitingTold
	if used+segs(text) > c.cfg.HoldSegments {
		_ = c.codes.commit(func(s *State) { s.WaitingDropped++; s.WaitingTold = true })
		if !tell {
			return route{limited: true}
		}
		return route{replies: []string{"Locked. The messages kept for my Wi-Fi page fill it, so this one was dropped. Sign in there at home to read the rest."}, limited: true}
	}
	err := c.codes.commit(func(s *State) {
		s.WaitingSeq++
		s.Waiting = append(slices.Clone(s.Waiting), WaitingMsg{ID: strconv.FormatUint(s.WaitingSeq, 10), At: now, Text: text, React: react})
		s.WaitingTold = true
	})
	if err != nil {
		return route{replies: []string{"Locked. I could not keep your message. Send it again after you sign in on my Wi-Fi page at home."}, limited: true}
	}
	if !tell {
		return route{limited: true}
	}
	return route{replies: []string{waitingReply}, limited: true}
}

// expireWaitingLocked discards held messages UnlockFor after each arrived,
// counting them for STATUS and the page.
func (c *Channel) expireWaitingLocked(now time.Time) {
	n := 0
	for _, m := range c.codes.st.Waiting {
		if !now.Before(m.At.Add(c.cfg.UnlockFor)) {
			n++
		}
	}
	if n == 0 {
		return
	}
	_ = c.codes.commit(func(s *State) {
		keep := s.Waiting[:0:0]
		for _, m := range s.Waiting {
			if now.Before(m.At.Add(c.cfg.UnlockFor)) {
				keep = append(keep, m)
			}
		}
		s.WaitingExpired += len(s.Waiting) - len(keep)
		s.Waiting = keep
	})
}

// LocalHeld lists the messages held for the page, in arrival order and in
// full, with the counts of those dropped at the bound and those expired
// since the owner last ran or discarded them.
func (c *Channel) LocalHeld() (msgs []WaitingMsg, dropped, expired int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireWaitingLocked(c.cfg.Now())
	st := c.codes.st
	return slices.Clone(st.Waiting), st.WaitingDropped, st.WaitingExpired
}

// heldNote is STATUS's line for held messages, "" when there are none.
func (c *Channel) heldNote() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireWaitingLocked(c.cfg.Now())
	st := c.codes.st
	var out string
	switch n := len(st.Waiting); {
	case n == 1:
		out = "1 message waits for you on my Wi-Fi page."
	case n > 1:
		out = fmt.Sprintf("%d messages wait for you on my Wi-Fi page.", n)
	}
	if st.WaitingDropped > 0 {
		out += fmt.Sprintf(" %d dropped: the hold was full.", st.WaitingDropped)
	}
	if st.WaitingExpired > 0 {
		out += fmt.Sprintf(" %d expired unread.", st.WaitingExpired)
	}
	if len(out) > 0 && out[0] == ' ' {
		out = out[1:]
	}
	return out
}

// ErrHeldChanged refuses a run whose shown list names a message no longer
// held, or marks one it did not show.
var ErrHeldChanged = errors.New("owner: the held messages changed")

// LocalRunHeld is the owner's tap on the page (CH-14): of the held messages
// the page showed (shown), it runs those in run, in arrival order, and
// discards the rest of shown. A message that arrived after the page was
// drawn stays held. It needs an open session, which only the page opens,
// so the run is the owner's at P3; each message then routes as if it had
// arrived in that session. The replies go to the owner's number. It
// returns how many ran.
func (c *Channel) LocalRunHeld(shown, run []string) (int, error) {
	now := c.cfg.Now()
	c.mu.Lock()
	if !c.codes.unlocked(now) {
		c.mu.Unlock()
		return 0, ErrLocked
	}
	c.expireWaitingLocked(now)
	held := map[string]bool{}
	for _, m := range c.codes.st.Waiting {
		held[m.ID] = true
	}
	show := map[string]bool{}
	for _, id := range shown {
		if !held[id] {
			c.mu.Unlock()
			return 0, ErrHeldChanged
		}
		show[id] = true
	}
	marked := map[string]bool{}
	for _, id := range run {
		if !show[id] {
			c.mu.Unlock()
			return 0, ErrHeldChanged
		}
		marked[id] = true
	}
	var texts []string
	err := c.codes.commit(func(s *State) {
		texts = texts[:0]
		keep := s.Waiting[:0:0]
		for _, m := range s.Waiting {
			switch {
			case marked[m.ID]:
				texts = append(texts, m.Text)
			case !show[m.ID]:
				keep = append(keep, m)
			}
		}
		s.Waiting = keep
		s.WaitingDropped, s.WaitingExpired = 0, 0
	})
	c.mu.Unlock()
	if err != nil {
		return 0, err
	}
	c.runHeld(texts)
	return len(texts), nil
}

// runHeld routes each text in order as the owner's, in the session the
// page opened, and texts the replies to the owner. It runs behind the
// sends textAfterReply starts (DrainSends bounds it on shutdown).
func (c *Channel) runHeld(texts []string) {
	if len(texts) == 0 {
		return
	}
	do := func() {
		for _, t := range texts {
			rt, ok := c.route(c.cfg.Owner, t)
			if !ok {
				continue
			}
			out := c.finish(context.Background(), c.cfg.Owner, rt)
			c.recordReplies(c.cfg.Owner, out)
			if c.cfg.Modem == nil {
				continue
			}
			for _, r := range out {
				if c.cfg.Modem.Send(c.cfg.Owner, r) != nil {
					break
				}
			}
		}
	}
	if c.inlineSends {
		do()
		return
	}
	done := make(chan struct{})
	c.sendMu.Lock()
	prev := c.sendTail
	c.sendTail = done
	c.sendMu.Unlock()
	c.sends.Add(1)
	go func() {
		defer c.sends.Done()
		defer close(done)
		if prev != nil {
			<-prev
		}
		do()
	}()
}
