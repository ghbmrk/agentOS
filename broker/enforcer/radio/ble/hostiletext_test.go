package ble

// REQ: NET-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The stack's device and characteristic names refuse the hostile-text
// corpus, as the channel's (enforcer/wire) do, so a name the host would
// refuse never names a device in the stack's configuration.
func TestNameCheckRefusesHostileText(t *testing.T) {
	hostiletext.Run(t, name)
}
