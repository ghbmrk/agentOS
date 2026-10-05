package control

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/loops"
)

// REQ: CH-11, CH-12
//
// HELP stays one text of at most three segments once the loops' line is
// added (UX-49-1).
func TestHelpWithLoopsFitsThreeSegments(t *testing.T) {
	if n := len(helpText + " " + loops.HelpLine); n > 459 {
		t.Fatalf("HELP with the loops line is %d characters, over 3 GSM-7 segments (459)", n)
	}
}
