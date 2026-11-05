package proc

// REQ: STO-1

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A store name names a directory under root. These checks refuse every
// hostile shape today; the corpus keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, ValidStoreName)
}
