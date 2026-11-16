package localapi

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-14

// The page's run lists carry the largest hold the owner can set, so a
// full hold above 64 messages is never refused as stale (#5187).
func TestMaxInboxCoversTheLargestHold(t *testing.T) {
	if MaxInbox < owner.MaxHoldSegments {
		t.Fatalf("MaxInbox %d below owner.MaxHoldSegments %d", MaxInbox, owner.MaxHoldSegments)
	}
	if owner.MaxHoldSegments <= 64 {
		t.Fatalf("owner.MaxHoldSegments %d: no settable hold above 64", owner.MaxHoldSegments)
	}
}
