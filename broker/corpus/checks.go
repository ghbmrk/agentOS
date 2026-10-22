// Package corpus wires the closed checks Loop 2's corpus probe replays
// published injection texts through (LOOP-7, HLD-5, P3-4b-4a): CH-19's
// code filter, the commitment filter, the mail alert patterns, and labels.
// Each payload is a fixed synthetic text the check must catch wherever an
// attack text puts it; none is a real code or secret.
package corpus

import (
	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/owner"
)

// The checks' names and payloads, shared by InProcess and PlaneChecks.
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

// InProcess are the closed checks a broker process holds itself: CH-19's
// code filter and c's commitment filter. The alert patterns and the label
// check sit in the mail clerk's process (VRB-2) and are reached only
// through a guest (PlaneChecks).
func InProcess(c owner.Commitments) []loops.ClosedCheck {
	return []loops.ClosedCheck{
		{Name: CodeFilter, Payload: CodePayload, Hit: owner.SecretShaped},
		{Name: CommitmentFilter, Payload: CommitmentPayload, Hit: func(s string) bool { return c.Match(s) != "" }},
	}
}
