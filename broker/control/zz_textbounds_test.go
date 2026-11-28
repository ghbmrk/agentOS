package control

import (
	"strings"
	"testing"
)

// REQ: CH-12, CH-19

// TestTextBidiRangeEnds: JoinControls drops each end of both bidi ranges
// (U+202A-E, U+2066-9) and keeps the characters just outside them
// (mutgate on #6625).
func TestTextBidiRangeEnds(t *testing.T) {
	for _, r := range []rune{0x202A, 0x202E, 0x2066, 0x2069, 0x200E, 0x200F, 0x061C} {
		if got := JoinControls("a" + string(r) + "b"); got != "ab" {
			t.Errorf("JoinControls kept U+%04X: %q", r, got)
		}
	}
	for _, r := range []rune{0x2029, 0x202F, 0x2065, 0x206A} {
		in := "a" + string(r) + "b"
		if got := JoinControls(in); got != in {
			t.Errorf("JoinControls dropped U+%04X: %q", r, got)
		}
	}
}

// TestTextLeadingGapLeavesNoSpace: a Cc before the first kept character
// leaves no space, as the gap splits nothing.
func TestTextLeadingGapLeavesNoSpace(t *testing.T) {
	if got := StripControls("\x01ab"); got != "ab" {
		t.Fatalf("StripControls = %q", got)
	}
}

// TestTextPrefixUnits: a start that fits is the whole string; U+FFFF is
// one UTF-16 unit and U+10000 two; a cut inside a joined emoji backs off
// to before it.
func TestTextPrefixUnits(t *testing.T) {
	for s, units := range map[string]int{"ab": 5, "ab😀": 4, "a👍": 3} {
		if got := Prefix(s, units); got != len(s) {
			t.Errorf("Prefix(%q, %d) = %d, want %d", s, units, got, len(s))
		}
	}
	ffff := strings.Repeat("\uFFFF", 3) + "😀"
	if got := Prefix(ffff, 2); got != 2*len("\uFFFF") {
		t.Errorf("Prefix(U+FFFF x3, 2) = %d, want %d", got, 2*len("\uFFFF"))
	}
	if got := Prefix("a👩\u200d💻", 4); got != 1 {
		t.Errorf("Prefix cut inside a joined emoji: %d, want 1", got)
	} // A byte that is not UTF-8 is one unit, and a cut after it falls
	// where the next rune starts.
	if got := Prefix("\xffab", 1); got != 1 {
		t.Errorf("Prefix after an invalid byte = %d, want 1", got)
	}
}

// TestTextJoinableEdges: either end of s is always a cut point; a cut
// inside a rune, next to a joiner, or before a skin tone (U+1F3FB-F) is
// not; the characters beside the skin-tone range are ordinary.
func TestTextJoinableEdges(t *testing.T) {
	for _, c := range []struct {
		s    string
		p    int
		want bool
	}{
		{"\u0301a", 0, true},
		{"ab", 2, true},
		{"ab", 1, true},
		{"a\u200db", 1, false},
		{"\u00e9", 1, false},
		{"a\U0001F3FB", 1, false},
		{"a\U0001F3FF", 1, false},
		{"a\U0001F3FA", 1, true},
		{"a\U0001F400", 1, true},
	} {
		if got := Joinable(c.s, c.p); got != c.want {
			t.Errorf("Joinable(%q, %d) = %v, want %v", c.s, c.p, got, c.want)
		}
	}
}

// TestTextTokenAlphabets: safeToken and plainLine keep each end of their
// letter and digit ranges and every listed mark, drop the characters
// beside the ranges, and stop at max characters.
func TestTextTokenAlphabets(t *testing.T) {
	if got := safeToken("azAZ._/@-`{[09 ,", 32); got != "azAZ._/@-" {
		t.Errorf("safeToken = %q", got)
	}
	if got := safeToken("abcd", 2); got != "ab" {
		t.Errorf("safeToken max = %q", got)
	}
	if got := plainLine("azAZ09 .,;:()-`{@[/\n", 32); got != "azAZ09 .,;:()-" {
		t.Errorf("plainLine = %q", got)
	}
	if got := plainLine("abcd", 2); got != "ab" {
		t.Errorf("plainLine max = %q", got)
	}
}
