package tr3_test

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/loops"
	"github.com/ghbmrk/agentos/broker/update"
)

// REQ: UPD-7, CAP-2
//
// Tests-only markers for soft gaps already met. Does not claim HW-* or OSS-12.
//
// UPD-7: soak plus attestations replaces a central staged rollout — Loop 3
// already reads the owner's soak from settings (maintain.TestOwnerSoakIsRead)
// and check/attest paths refuse unattested security fixes.
// CAP-2: public machines may use uncredentialed/provider-side reach that
// private ones may not (egress.TestServerToolsFollowTheDataLabel).

func TestTR3SoftGapsAlreadyMet(t *testing.T) {
	if loops.ChannelStable != update.ChannelStable {
		t.Fatal("stable channel renamed; UPD-7 soak wiring needs a look")
	}
	if update.ChannelFast == "" || update.ChannelStable == "" {
		t.Fatal("update channels missing")
	}
}
