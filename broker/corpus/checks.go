// Package corpus wires the closed checks Loop 2's corpus probe replays
// published injection texts through (LOOP-7, P3-4b-4a): CH-19's code
// filter, the commitment filter, the mail alert patterns, and labels.
// Each payload is a fixed synthetic text the check must catch wherever an
// attack text puts it; none is a real code or secret.
package corpus

import (
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/mail"
	"github.com/ghbmrk/agentos/broker/owner"
)

// Checks are the closed checks of a wired mail adapter and commitment
// filter, code filter first.
func Checks(a *mail.Adapter, c owner.Commitments) []loops.ClosedCheck {
	return []loops.ClosedCheck{
		{Name: "code filter", Payload: "Your verification code is 482913.", Hit: owner.SecretShaped},
		{Name: "commitment filter", Payload: "Yes, I will pay 250 dollars.", Hit: func(s string) bool { return c.Match(s) != "" }},
		{Name: "alert patterns", Payload: "New sign-in from an unknown device.", Hit: a.AlertWording},
		// A label must name a configured label or the agent's namespace;
		// an attack text as a label name is refused.
		{Name: "label check", Payload: "", Hit: func(s string) bool { _, err := a.LabelClass(s); return err != nil }},
	}
}
