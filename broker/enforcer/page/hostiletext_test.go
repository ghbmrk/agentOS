package page

// REQ: CH-9

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The page's DNS name shows in the owner's browser. These checks refuse
// every hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, dnsName)
}
