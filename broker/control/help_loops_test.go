package control_test

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/control"
	"github.com/ghbmrk/agentos/broker/loops"
)

// REQ: CH-11, CH-12
//
// HELP stays one text of at most three segments once the loops' line is
// added (UX-49-1). An external test: loops reaches control through change
// and owner.
func TestHelpWithLoopsFitsThreeSegments(t *testing.T) {
	if n := len(control.HelpTextForTest + " " + loops.HelpLine); n > 459 {
		t.Fatalf("HELP with the loops line is %d characters, over 3 GSM-7 segments (459)", n)
	}
}
