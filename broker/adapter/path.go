// Package adapter is the §11 path for agent-drafted adapters (ADP-6, ADP-8).
// The mismatch check itself lives in verb (ADP-8); this package records
// what a proposal must carry before the change pipeline may adopt it.
package adapter

import (
	"fmt"
	"strings"

	"github.com/ghbmrk/agentos/broker/verb"
)

// Proposal is one adapter candidate before §11 adoption (ADP-6).
type Proposal struct {
	// Name is the adapter's declared tool name.
	Name string
	// PrivateDerived is true when the draft came from the owner's
	// interactions (OSS-3); false means it must come from the clean room.
	PrivateDerived bool
	// CleanRoom is true when OSS-2 re-created it for publication.
	CleanRoom bool
	// Ops maps each declared operation to a closed-list verb (ADP-2).
	Ops map[string]string
	// NewGrants lists grant specs the owner must approve (ADP-2).
	NewGrants []string
	// Unmapped lists operations with no verb yet; the owner chooses.
	Unmapped []string
}

// Refusal is why a proposal may not enter the change pipeline.
type Refusal struct {
	Reason string
}

func (r Refusal) Error() string { return "adapter: " + r.Reason }

// Check reports whether p may be proposed through §11 (ADP-6).
// It does not run the demo; the caller passes Ops after the exercise.
func Check(p Proposal) error {
	if strings.TrimSpace(p.Name) == "" {
		return Refusal{Reason: "name required"}
	}
	if !p.PrivateDerived && !p.CleanRoom {
		return Refusal{Reason: "must be private-derived or clean-room (OSS-3)"}
	}
	if p.PrivateDerived && p.CleanRoom {
		return Refusal{Reason: "private-derived adapters are not published"}
	}
	if len(p.Ops) == 0 && len(p.Unmapped) == 0 {
		return Refusal{Reason: "no operations declared"}
	}
	for op, v := range p.Ops {
		if !verb.Valid(v) {
			return Refusal{Reason: fmt.Sprintf("operation %q maps to unknown verb %q", op, v)}
		}
	}
	// New grants or unmapped ops must be listed so the owner is asked (ADP-2).
	if len(p.Unmapped) > 0 && len(p.NewGrants) == 0 {
		// Unmapped ops themselves are the ask; OK.
	}
	return nil
}
