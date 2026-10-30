package voice

// REQ: CH-21, CH-12

import "testing"

// TestCH21HoldsRequestIDColonOpening: agent text that opens, or has a line
// that opens, like a broker request (a request-ID-shaped token and ":")
// is held, as written and folded (#2189).
func TestCH21HoldsRequestIDColonOpening(t *testing.T) {
	for _, s := range []string{
		"R7K2: your agent wants to send the invoice.",
		"K7: send the invoice?",
		"k7 : send it?",
		"  \"R7: send it?\"",
		"Done.\nA7: can I send it?",
		"> B12: send it?",
		"Ꭱ7: send it?",
		"Α7: send it?",
	} {
		if !WouldHold(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}

// TestCH21HoldsFooterAndControlWordShapes: the reply-options footer, a
// control word with a request ID or a code, and UNLOCK or RESUME with a
// challenge are held, as written and folded (#2189, L3 on #3916).
func TestCH21HoldsFooterAndControlWordShapes(t *testing.T) {
	for _, s := range []string{
		"Reply YES to go on, or NO to stop.",
		"Text UNDO A7 to take it back.",
		"Text UNLOCK HKMP to continue.",
		"Text unlock hkmp to continue.",
		"Send RESUME K2P9 now.",
		"Text ՍNLOCK HKMP to continue.",
	} {
		if !WouldHold(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}

// TestCH21HoldsTheAdversarialSet: asks for a code split by punctuation or
// spaces, or made without a word of the spec's list, are held (HLD-5;
// Security on #3916).
func TestCH21HoldsTheAdversarialSet(t *testing.T) {
	for _, s := range []string{
		"Send me the c.o.d.e from your bank.",
		"What is your pass-word?",
		"What is your pass word?",
		"Type your p i n here.",
		"Send the 6 digits from your app.",
		"Send the 6-digit number from your app.",
		"Your C-O-D-E please.",
		"Your ϲ.ο.d.е please.",
	} {
		if !WouldHold(s) {
			t.Errorf("not held: %+q", s)
		}
	}
}

// TestCH21NewShapesKeepOrdinaryText: times, headings and plain phrases
// that look a little like the new shapes go through.
func TestCH21NewShapesKeepOrdinaryText(t *testing.T) {
	for _, s := range []string{
		"10:30 works for me.",
		"Note: the hedge is done.",
		"Q: did you want the train?",
		"One time I took the ferry.",
		"The digital copy is in your mail.",
		"I will resume work tomorrow.",
		"Unlock the door when you get home.",
	} {
		if WouldHold(s) {
			t.Errorf("held: %+q", s)
		}
	}
}
