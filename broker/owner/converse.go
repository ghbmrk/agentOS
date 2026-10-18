package owner

// Converse texts the owner the agent's reply to a message the owner sent:
// conversation, not a push (CH-15). It goes at once, in quiet hours too
// and with the hour's texts spent, and does not count toward the hour,
// as the channel's own replies to the owner's texts do not. Like Notify,
// secret-shaped content becomes a pointer to the local UI (CH-19) and
// the rest goes behind AgentPrefix. Callers pass a reply bound to one
// owner message (guest POST /owner/reply), so the owner's own texts
// bound how many go, or an agent question while the owner's task chat
// is open, which the question book bounds itself (#2363); other agent
// text the owner did not ask for goes through Notify.
func (c *Channel) Converse(text string) error {
	if c.cfg.Modem == nil {
		return ErrNoModem
	}
	text, err := checkAgent(text)
	if err != nil {
		return err
	}
	return c.cfg.Modem.Send(c.cfg.Owner, agentText(text))
}
