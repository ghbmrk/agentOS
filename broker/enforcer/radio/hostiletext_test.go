package radio

// REQ: NET-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A radio name goes on the air and to the owner. These checks refuse every
// hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, name)
}
