package wire

// REQ: NET-2, NET-4

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/internal/hostiletext"
)

// A name the channel carries refuses the hostile-text corpus as
// broker/enforcer/policy's tokens do (#3901), so the channel and the policy
// never disagree on a device's name.
func TestNameCheckRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, Name)
}
