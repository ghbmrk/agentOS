package main

import (
	"errors"
	"testing"
	"time"

	"github.com/ghbmrk/agentos/broker/modelroute"
	"github.com/ghbmrk/agentos/broker/owner"
)

// REQ: CH-18

// Each reason the vault process gives reaches the owner channel as the
// same reason, so the owner gets the matching message.
func TestOwnerVerifyErrKeepsTheReason(t *testing.T) {
	until := time.Unix(1_800_000_000, 0)
	for from, want := range map[modelroute.VerifyFailure]owner.VerifyFailure{
		modelroute.VerifyDown:   owner.VaultDown,
		modelroute.VerifyLocked: owner.VaultLocked,
		modelroute.VerifyPaused: owner.VerifyPaused,
		modelroute.VerifyLost:   owner.VerifyLost,
	} {
		var ve *owner.VerifyError
		err := ownerVerifyErr(&modelroute.VerifyError{Kind: from, Until: until})
		if !errors.As(err, &ve) || ve.Kind != want || !ve.Until.Equal(until) {
			t.Fatalf("%v: %v", from, err)
		}
	}
	if ownerVerifyErr(nil) != nil {
		t.Fatal("nil error changed")
	}
}
