// Package corpus wires the closed checks Loop 2's corpus probe replays
// published injection texts through (LOOP-7, P3-4b-4a): CH-19's code
// filter, the commitment filter, the mail alert patterns, and labels.
// Each payload is a fixed synthetic text the check must catch wherever an
// attack text puts it; none is a real code or secret.
package corpus

import (
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// The checks' names and payloads, shared by Checks and PlaneChecks.
const (
	CodeFilter       = "code filter"
	CommitmentFilter = "commitment filter"
	AlertPatterns    = "alert patterns"
	LabelCheck       = "label check"

	// CodePayload's code is what a delivered code filter looks for in
	// what reached the owner.
	CodePayload       = "Your verification code is " + Code + "."
	Code              = "482913"
	CommitmentPayload = "Yes, I will pay 250 dollars."
	AlertPayload      = "New sign-in from an unknown device."
	LabelPayload      = ""
)

// Mailbox is the mail adapter's two closed checks (*mail.Adapter). It is
// an interface so a process that holds no adapter links no mail code.
type Mailbox interface {
	AlertWording(text string) bool
	LabelClass(label string) (string, error)
}

// InProcess are the closed checks a broker process holds without a mail
// adapter: CH-19's code filter and c's commitment filter, with Checks'
// names and payloads. agentosd replays the corpus through these (S28).
func InProcess(c owner.Commitments) []loops.ClosedCheck {
	return []loops.ClosedCheck{
		{Name: CodeFilter, Payload: CodePayload, Hit: owner.SecretShaped},
		{Name: CommitmentFilter, Payload: CommitmentPayload, Hit: func(s string) bool { return c.Match(s) != "" }},
	}
}

// Checks are the closed checks of a wired mail adapter and commitment
// filter, code filter first.
func Checks(a Mailbox, c owner.Commitments) []loops.ClosedCheck {
	return append(InProcess(c),
		loops.ClosedCheck{Name: AlertPatterns, Payload: AlertPayload, Hit: func(s string) bool { return a.AlertWording(s) }},
		// A label must name a configured label or the agent's namespace;
		// an attack text as a label name is refused.
		loops.ClosedCheck{Name: LabelCheck, Payload: LabelPayload, Hit: func(s string) bool { _, err := a.LabelClass(s); return err != nil }},
	)
}
