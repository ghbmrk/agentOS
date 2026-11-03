package model

// REQ: CLK-3

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The key's header is a name keyHeaders holds exactly: the header corpus's
// credential, request-reshaping, hop-by-hop and broken names, in any case,
// are refused (#4910, #2623), and so is a widened list. Catches a key sent in a header a remote logs
// or a proxy acts on.
func TestKeyHeadersRefuseTheCorpus(t *testing.T) {
	hostiletext.RunHeaders(t, func(h string) bool {
		d := Shipped[0]
		d.Header = h
		return d.validate() == nil
	}, hostiletext.Exactly(t, keyHeaders, "Authorization", "X-Api-Key")...)
}
