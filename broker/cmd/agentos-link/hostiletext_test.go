package main

// REQ: HW-16

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The link interface name comes from the unit's flags. These checks refuse
// every hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, ifaceName)
}
