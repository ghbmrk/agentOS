package localsrv

// REQ: LOG-4, CH-7

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/hostiletext"
)

// The name the owner types to forget reaches the kernel's look-up: the
// hostile-text corpus (#3901) is refused before it does.
func TestEraseNameRefusesTheHostileCorpus(t *testing.T) {
	hostiletext.Run(t, eraseName)
	for _, n := range []string{"Alice Smith", "José", "Jose\u0301", "O'Brien", "O\u2019Brien", "alice@example.com", "Zoë & Ana", "李雷", "राम", "प्रिया", "สมศรี", "தமிழ்", "রবীন্দ্রনাথ"} {
		if !eraseName(n) {
			t.Errorf("refuses %q", n)
		}
	}
	// Invisible marks stay refused (Security on #5092).
	for _, n := range []string{"na\u034fme", "na\ufe0fme", "na\U000E0100me", "na\U0001D173me", "na\u200cme"} {
		if eraseName(n) {
			t.Errorf("takes %q", n)
		}
	}
}
