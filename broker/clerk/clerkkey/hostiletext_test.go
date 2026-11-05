package clerkkey

// REQ: CLK-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A clerk's name keys its uid and socket. These checks refuse every hostile
// shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, ValidName)
}
