package ipform

// REQ: KRN-12, DEV-2

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// Forms finds the target in every corpus form that carries it, zoned or
// not, and in no near miss (#4910, #4037). Catches a form Forms drops, or a
// near miss it misreads as carrying an address.
func TestFormsRunsTheAddressCorpus(t *testing.T) {
	for _, s := range []string{"169.254.169.254", "192.168.77.200", "10.0.0.1", "100.64.0.1"} {
		target := netip.MustParseAddr(s)
		hostiletext.RunAddrs(t, target, func(text string) bool {
			return slices.Contains(Forms(netip.MustParseAddr(text)), target)
		})
	}
}
