package plan

// REQ: CLK-7

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// A declared refresh header's value refuses the header-value corpus (#4910,
// #5089): no line break, control character, DEL, non-ASCII byte or padding
// reaches a refresh as a header the clerk sets itself.
func TestRefreshHeaderValuesRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaderValues(t, headerValue)
}
