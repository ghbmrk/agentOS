package owner

import (
	"log"
	"time"
)

// Converse texts the owner the agent's reply to a message the owner sent:
// conversation, not a push (CH-15). It goes at once, in quiet hours too
// and with the hour's texts spent, and does not count toward the hour,
// as the channel's own replies to the owner's texts do not. Like Notify,
// secret-shaped content is kept and becomes a pointer to the local UI
// (CH-19, keep.go) and the rest goes with no label (CH-21). Callers pass a reply bound to one
// owner message (guest POST /owner/reply), so the owner's own texts
// bound how many go, or an agent question while the owner's task chat
// is open, which the question book bounds itself (#2363); other agent
// text the owner did not ask for goes through Notify.
//
// A reply that goes out stops the acknowledgement due for the owner's
// task chat (OWN-4); one that fails to send does not.
func (c *Channel) Converse(text string) error {
	if c.cfg.Modem == nil {
		return ErrNoModem
	}
	text, err := c.checkAgent(text)
	if err != nil {
		return err
	}
	c.ackSend.Lock()
	defer c.ackSend.Unlock()
	if err := c.sendOwner(agentText(text)); err != nil {
		return err
	}
	c.mu.Lock()
	c.replies++
	c.stopAckLocked()
	c.mu.Unlock()
	return nil
}

// AckText is the acknowledgement (OWN-4): the broker's own fixed words,
// with nothing of the agent's.
const AckText = "On it."

// armAckLocked notes owner task chat that reached the agent at at. If no
// acknowledgement is due, one falls due the owner's ACK seconds after at;
// one already due covers this message too, so the owner gets at most one
// for the messages of one wait (OWN-4). c.mu is held.
func (c *Channel) armAckLocked(at time.Time) {
	if c.cfg.Modem == nil || c.ackStop != nil && c.ackStops == c.stops.Load() {
		return
	}
	c.stopAckLocked() // one voided by a STOP since
	c.ackGen++
	gen := c.ackGen
	c.ackStops = c.stops.Load()
	c.ackStop = c.cfg.AfterFunc(c.codes.st.Pacing.ackAfter()-c.cfg.Now().Sub(at), func() { c.ack(gen) })
}

// stopAckLocked stops the acknowledgement due, if any. c.mu is held.
func (c *Channel) stopAckLocked() {
	if c.ackStop != nil {
		c.ackStop()
		c.ackStop = nil
	}
	c.ackGen++
}

// ack sends the acknowledgement armed as gen unless a reply went out, a
// STOP came ("On it." never follows "Stopped."), or a later one replaced
// it. It is conversation (CH-15): it goes at once, in
// quiet hours too, uncounted, with no agent prefix. ackSend orders it
// against Converse, so it never follows the reply that stopped it.
func (c *Channel) ack(gen uint64) {
	c.ackSend.Lock()
	defer c.ackSend.Unlock()
	c.mu.Lock()
	if gen != c.ackGen || c.ackStop == nil || c.stops.Load() != c.ackStops {
		c.mu.Unlock()
		return // replaced, replied to, or voided by a STOP since
	}
	c.ackStop = nil
	m := c.cfg.Modem
	c.mu.Unlock()
	if m == nil {
		return
	}
	if err := m.Send(c.cfg.Owner, AckText); err != nil {
		log.Printf("owner channel: acknowledgement not sent: %v", err)
	}
}

// ChatOpen reports whether a task chat is open: owner task chat reached
// the agent within the owner's CHAT window (CH-15), so the agent's
// questions are conversation. It is Chatting with the owner's setting.
func (c *Channel) ChatOpen() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.chat.IsZero() && c.cfg.Now().Sub(c.chat) < c.codes.st.Pacing.chatWindow()
}

// ChatWindow is how long a task chat stays open after the owner's last
// message reached the agent (CH-15).
func (c *Channel) ChatWindow() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.codes.st.Pacing.chatWindow()
}
