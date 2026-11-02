package channel

// REQ: NET-2

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// NET-2 Safety devices (#3872): the channel carries a garage door's close
// only to a door the signed policy records with obstruction reversal and a
// pre-close warning. The policy refuses to load any other naming; Allowed
// checks it again, so a device that reached the channel by another path
// still gets no close. Revert mutant: Allowed back on policy.Nameable
// carries the close to the door with no safeguard.
func TestCloseNeedsSafeguards(t *testing.T) {
	rev, warn := policy.SafeguardObstructionReversal, policy.SafeguardPreCloseWarning
	for _, c := range []struct {
		g    []string
		want bool
	}{
		{[]string{rev, warn}, true},
		{[]string{rev}, false},
		{[]string{warn}, false},
		{nil, false},
	} {
		dev := policy.Device{ID: "garage", Network: policy.NetDevices, Class: policy.ClassGarageDoor, Secure: SecureClose, Safeguards: c.g}
		if got := Allowed(dev, wire.VerbClose); got != c.want {
			t.Errorf("close to a door with %v: %v, want %v", c.g, got, c.want)
		}
		for _, v := range []wire.Verb{wire.VerbOn, wire.VerbOff, wire.VerbLock, wire.VerbShut} {
			if Allowed(dev, v) {
				t.Errorf("%v to a door with %v carried", v, c.g)
			}
		}
	}
}
