package follow

// REQ: CH-10

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The owner's name for a source reaches the owner in broker-voiced texts, so
// it refuses the hostile-text corpus (#3901).
func TestNameCheckRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, NameOK)
}
