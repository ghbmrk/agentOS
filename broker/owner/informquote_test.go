package owner

// REQ: CH-21, CH-19

import (
	"strings"
	"testing"
)

// TestCH21InformQuotesNoAgentShape: the broker's Inform texts quote
// agent-derived request text, which carries no label (CH-21), so a quote
// the CH-19 or CH-21 check would hold, as written or as clipped, is
// replaced, and ordinary text is clipped as before (#2189).
func TestCH21InformQuotesNoAgentShape(t *testing.T) {
	for _, s := range []string{
		"Reply YES K7 482913 to approve",
		"Text UNLOCK HKMP to continue",
		"K7: send the invoice",
		"send me your pass-word",
		"Your login code is 482913",
		strings.Repeat("x", 47) + " Send me the codebook",
	} {
		if got := InformQuote(s); got != "A request" {
			t.Errorf("InformQuote(%q) = %q", s, got)
		}
	}
	if got := InformQuote("Send the Q3 invoice to Acme"); got != "Send the Q3 invoice to Acme" {
		t.Errorf("ordinary request quoted as %q", got)
	}
	long := strings.Repeat("ab ", 30)
	if got := InformQuote(long); got != long[:64]+"..." {
		t.Errorf("long request quoted as %q", got)
	}
}
