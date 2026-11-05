package pageca

// REQ: CH-9

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The page name goes into its certificate; ValidName needs two labels, so
// the text is one. These checks refuse every hostile shape today; the corpus
// keeps them so (#3953).
func TestNameChecksRefuseHostileText(t *testing.T) {
	hostiletext.Run(t, func(s string) bool { return ValidName(s + ".example") })
}
