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
	for _, n := range []string{"Alice Smith", "José", "O'Brien", "alice@example.com", "Zoë & Ana", "李雷"} {
		if !eraseName(n) {
			t.Errorf("refuses %q", n)
		}
	}
}
