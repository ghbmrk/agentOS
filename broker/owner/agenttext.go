package owner

// RefuseAgentText is the check Converse, Notify and NotifyNow run on
// agent text before it reaches the owner: ErrAgentReaction if text is a
// reaction form (CH-11). The guest plane runs it on a reply before
// storing it, so the guest hears the refusal (#2196).
func RefuseAgentText(text string) error { return refuseReaction(text) }
