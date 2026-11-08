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
	// Invisible marks and fillers stay refused (Security on #5092; #5097
	// item 12), and so does a name of marks alone or one that starts with
	// a mark, which is no name (#5097 item 13).
	for _, n := range []string{"na\u034fme", "na\ufe0fme", "na\U000E0100me", "na\U0001D173me", "na\u200cme",
		"na\U00016FE4me", "\U00016FE4", "\u0301", "\u0301\u0302", "\u0301Alice", "\u093fराम"} {
		if eraseName(n) {
			t.Errorf("takes %q", n)
		}
	}
}
