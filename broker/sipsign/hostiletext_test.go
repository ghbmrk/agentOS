package sipsign

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A SIP host shows in a signed call's line. These checks refuse every
// hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, hostName)
}
