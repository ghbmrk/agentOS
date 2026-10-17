package owner

import (
	"sort"
	"strings"
	"unicode"

	"github.com/ghbmrk/agentos/broker/modem"
)

// maxAgentSegments is how many segments one agent text may take, in
// whichever encoding it needs (CH-12): 459 GSM-7 septets or 201 UCS-2 units.
const maxAgentSegments = 3

// CleanAgentText removes control characters other than LF, and the bidi
// controls, from agent text before the CH-19 and CH-21 checks run on it
// (CH-12). Joiners and variation selectors stay, so 👩‍💻 arrives whole.
func CleanAgentText(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n':
			return r
		case unicode.Is(unicode.Cc, r),
			r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069,
			r == 0x200E, r == 0x200F, r == 0x061C:
			return -1
		}
		return r
	}, s)
}

// oneText says one text can carry s in its own encoding.
func oneText(s string) bool {
	n, _ := modem.Segments(s)
	return n <= maxAgentSegments
}

// Room is the largest rune-boundary byte index p for which
// AgentPrefix+s[:p]+suffix fits one text in its own encoding (CH-12). A
// longer prefix never needs fewer segments, so the search halves.
func Room(s, suffix string) int {
	var cuts []int // rune boundaries after the first rune, then len(s)
	for i := range s {
		if i > 0 {
			cuts = append(cuts, i)
		}
	}
	cuts = append(cuts, len(s))
	n := sort.Search(len(cuts), func(i int) bool { return !oneText(AgentPrefix + s[:cuts[i]] + suffix) })
	if n == 0 {
		return 0
	}
	return cuts[n-1]
}
