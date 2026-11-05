package vision

// REQ: DEV-8

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// An enrolled ID and a model name show to the owner. These checks refuse
// every hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, validName)
	hostiletext.Run(t, ValidModelName)
}
