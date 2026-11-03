package call_test

import (
	"github.com/ghbmrk/agentos/broker/call"
	"github.com/ghbmrk/agentos/broker/modem/at"
)

// The modem's call is the line, unchanged.
var _ call.Incoming = (*at.Call)(nil)
