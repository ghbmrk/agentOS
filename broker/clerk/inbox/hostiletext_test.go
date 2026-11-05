package inbox

// REQ: VRB-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A DKIM selector and domain come from a sender's mail. These checks refuse
// every hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, dnsName)
}
