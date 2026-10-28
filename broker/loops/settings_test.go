package loops

import "testing"

// The settings vocabulary left after the scheduler went with the change
// pipeline (#2785): the owner-text parser agentosd's learn-state sweep
// reads.

func TestParseTextTakesWholeMessagesOnly(t *testing.T) {
	cases := []struct {
		msg  string
		ok   bool
		want Request
	}{
		{"loops off", true, Request{Kind: KindLoops}},
		{"Loops on!", true, Request{Kind: KindLoops, On: true}},
		{"LOOP 2 OFF", true, Request{Kind: KindLoops, Loop: Secure}},
		{"loop 3 on.", true, Request{Kind: KindLoops, Loop: Maintain, On: true}},
		{"spare budget 40", true, Request{Kind: KindBudget, Calls: 40}},
		{"stop sharing", true, Request{Kind: KindSharing}},
		{"START SHARING", true, Request{Kind: KindSharing, On: true}},
		{"learning off", true, Request{Kind: KindLoops, Loop: Improve}},
		{"Security tests on", true, Request{Kind: KindLoops, Loop: Secure, On: true}},
		{"UPDATE CHECKS OFF.", true, Request{Kind: KindLoops, Loop: Maintain}},
		{"help loops", true, Request{Kind: KindHelp}},
		{"learning off now", false, Request{}},
		{"loop 4 off", false, Request{}},
		{"loop 02 off", false, Request{}},
		{"spare budget 999999", true, Request{Kind: KindBudget, Calls: MaxSpareCalls + 1}}, // answered with the limit (UX-57-2)
		{"spare budget -3", true, Request{Kind: KindBudget, Calls: 3}},                     // punctuation is ignored (CH-11)
		{"turn the loops off please", false, Request{}},
		{"loops off and book a table", false, Request{}},
	}
	for _, c := range cases {
		got, ok := ParseText(c.msg)
		if ok != c.ok || got != c.want {
			t.Errorf("ParseText(%q) = %+v, %v; want %+v, %v", c.msg, got, ok, c.want, c.ok)
		}
	}
}
