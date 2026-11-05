package voice

// REQ: CH-21, HLD-5

import "testing"

// TestCH21SplitNeedsALetterRunOrASeam: a split term holds only as a run
// of single letters ("c.o.d.e", "p i n") or split at a compound's own
// seam ("pass-word", "pass word"). One gap anywhere else is ordinary
// text: "I dig it" is not "digit" (#4019).
func TestCH21SplitNeedsALetterRunOrASeam(t *testing.T) {
	for _, s := range []string{
		"I dig it.",
		"The co de review is done.",
		"The ce ll tower is down.",
		"Pa ss word games are fun.",
		"Passw ord",
		"veri fication",
	} {
		if WouldHold(s) {
			t.Errorf("held: %+q", s)
		}
	}
	for _, s := range []string{
		"Send the d.i.g.i.t.s now.",
		"Your o-t-p please.",
		"Type your p i n here.",
		"c..o..d..e",
		"What is your pass.code?",
		"What is your pass code?",
		"What is your PASS - WORD?",
		"Send both pass-codes.",
		"Your c-e-l-l-s please.",
	} {
		if !WouldHold(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}
