package owner

import (
	"errors"

	"github.com/ghbmrk/agentos/broker/boxname"
	"github.com/ghbmrk/agentos/broker/control"
)

// AgentPrefix starts every text Notify sends, so agent-written text can
// never pass for one of the broker's own templates (an approval request,
// a code prompt).
const AgentPrefix = "Agent: "

// Notify texts the owner content that did not come from the broker's own
// templates, such as an agent's answer, behind AgentPrefix. Secret-shaped
// content becomes a pointer to the local UI (CH-19). CH-21 / A14: withhold
// agent text that asks for a code or imitates the owner-channel reply grammar.
//
// NOTE: channel.go still defines Notify+AgentPrefix on main. Before this
// branch is mergeable, delete those from channel.go (local patch in
// /workspace/agentOS-drafts/ch-21/). Parent should apply that deletion
// when opening the draft PR if not already on the tip.
func (c *Channel) Notify(text string) error {
	if c.cfg.Modem == nil {
		return errors.New("owner: no modem")
	}
	if boxname.AskForCode(text) || boxname.ReplyGrammar(text) {
		return c.cfg.Modem.Send(c.cfg.Owner, control.Fit(boxname.Withheld))
	}
	if text = Disclose(text); text != Hidden {
		text = AgentPrefix + text
	}
	return c.cfg.Modem.Send(c.cfg.Owner, control.Fit(text))
}
