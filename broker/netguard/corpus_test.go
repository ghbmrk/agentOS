package netguard

// REQ: KRN-12, DEV-2

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// Check refuses as a decoy each corpus form that carries a decoy address,
// zoned or not, and no near miss (#4910, #4037). The decoy is given in
// plain form, as Config.Decoy says. Catches a connect-time check that
// misses an embedded decoy, or reads one into an address that holds none.
func TestCheckRunsTheAddressCorpus(t *testing.T) {
	for _, s := range []string{"169.254.169.254", "192.168.77.200", "10.0.0.1"} {
		target := netip.MustParseAddr(s)
		p := New(Config{
			Decoy: func(a netip.Addr) bool { return a == target },
			Connect: func(context.Context, string, string) (net.Conn, error) {
				return nil, errors.New("no connect in this test")
			},
		})
		hostiletext.RunAddrs(t, target, func(text string) bool {
			var de *DeniedError
			err := p.Check(context.Background(), netip.MustParseAddr(text), 443, "tcp")
			return errors.As(err, &de) && de.Reason == ReasonDecoy
		})
	}
}
