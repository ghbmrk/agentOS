package owner

import "github.com/ghbmrk/agentos/broker/boxname"

// withholdAgent returns the CH-21 replacement text when agent text asks for
// a code or imitates the owner-channel reply grammar; otherwise "".
// Wire into Channel.Notify with the 3-line patch in
// /workspace/agentOS-drafts/ch-21/channel-withhold.patch (REQ: CH-21).
func withholdAgent(text string) string {
	if boxname.AskForCode(text) || boxname.ReplyGrammar(text) {
		return boxname.Withheld
	}
	return ""
}
