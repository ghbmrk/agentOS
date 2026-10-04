package owner

import "testing"

// REQ: ADP-11

// commitFail must become approval requests.
var commitFail = map[string]string{
	"Sure, I can confirm the booking.": "commitment",
	"We agree to the terms.":           "commitment",
	"I will pay the invoice.":          "commitment",
	"I'll pay it.":                     "commitment",
	"We've signed the contract.":       "commitment",
	"I accept.":                        "commitment",
	"I promise it is done.":            "commitment",
	"We'll book the room.":             "commitment",
	"I аgree":                          "commitment", // Cyrillic а
	"We ассept":                        "commitment", // Cyrillic а, с
	"That works for $40.":              "amount",
	"Fine at 300 EUR.":                 "amount",
	"OK for 500$":                      "amount",
	"OK for 500 CHF":                   "amount",
	"Costs €40":                        "amount",
	"Ok for ５００ EUR":                   "amount", // fullwidth digits
	"Fine, 500 dollars":                "amount",
	"I'll send it by Friday.":          "deadline",
	"Done before 10/12.":               "deadline",
	"Will have it by tomorrow.":        "deadline",
	"The deadline is fine.":            "deadline",
	"Payment is due.":                  "deadline",
	"It's due on Jan 12.":              "deadline",
	"Ready by 3pm.":                    "deadline",
	"No later than 2026-10-09.":        "deadline",
	"My code is 482913":                "secret",
}

// commitPass are routine replies that must stay auto-replies. The target
// false-positive rate is at most 5% of such replies (O11); this fixture
// set holds it at zero.
var commitPass = []string{
	"Thanks, got it. Talk soon.",
	"Sounds good, I'll take a look at the design.",
	"You may want to check with Sam.",
	"Version 2.1 fixes that.",
	"See section 3.2 of the doc.",
	"Sorry, slow to reply due to travel.",
	"That is a significant improvement.",
	"The signal was weak on the call.",
	"Acceptable for a first draft.",
	"Thanks Jan!",
	"I sat in on the meeting.",
	"Great, thanks for the update.",
	"Will do, I'll look into it.",
	"Looping in Alex who knows more.",
	"See you Friday!",
	"Approved by legal last week, FYI.",
	"Happy to help.",
	"Yes, that makes sense.",
	"Ok, sure.",
	"Can you confirm the address?",
	"Did they sign it yet?",
	"Let me know if you agree.",
	"Back tomorrow, will reply then.",
	"The meeting notes are attached to the thread.",
}

func TestCommitmentFilterFailFixtures(t *testing.T) {
	var c Commitments
	for s, want := range commitFail {
		if got := c.Match(s); got != want {
			t.Errorf("%q: got %q want %q", s, got, want)
		}
	}
	if (Commitments{Phrases: []string{"zusagen"}}).Match("Ich kann zusagen.") != "commitment" {
		t.Error("owner phrase list ignored")
	}
}

func TestCommitmentFilterPassFixtures(t *testing.T) {
	var c Commitments
	flagged := 0
	for _, s := range commitPass {
		if got := c.Match(s); got != "" {
			flagged++
			t.Errorf("%q: false positive %q", s, got)
		}
	}
	if rate := float64(flagged) / float64(len(commitPass)); rate > 0.05 {
		t.Errorf("false-positive rate %.0f%% exceeds the 5%% target", rate*100)
	}
}
