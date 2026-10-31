package main

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/clerk/handoff"
	"github.com/ghbmrk/agentos/broker/localapi"
)

// The page's made-card lengths are the hand-off's (MIG-4-recovery-r4d): the
// kernel's card passes through agentosd whole, so a drift would leave the
// page refusing every card.
func TestMadeCardLengthsMatchTheHandoff(t *testing.T) {
	if localapi.RecoveryCardKeyLen != handoff.CardKeyLen || localapi.RecoveryCardLen != handoff.MadeCardLen {
		t.Fatalf("localapi %d/%d, handoff %d/%d", localapi.RecoveryCardKeyLen, localapi.RecoveryCardLen, handoff.CardKeyLen, handoff.MadeCardLen)
	}
}
