package card_test

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/localui"
	"github.com/ghbmrk/agentos/broker/pageca"
)

// REQ: CH-9, HW-1
//
// The name the card prints is the name the page answers over HTTPS and the
// one its authority certifies: one name in three places, which this package
// keeps as a literal so localui does not link pageca through it.
func TestCardPageNameIsThePageAuthoritysName(t *testing.T) {
	for _, n := range []string{localui.DefaultPageName, pageca.DefaultName} {
		if n != card.PageName {
			t.Fatalf("card names the page %q, not %q", card.PageName, n)
		}
	}
}
