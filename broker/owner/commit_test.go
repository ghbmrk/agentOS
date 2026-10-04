package owner

import "testing"

// REQ: ADP-11

// commitFail must become approval requests.
var commitFail = map[string]string{
	"Sure, I can confirm the booking.":  "commitment",
	"We agree to the terms.":            "commitment",
	"I will pay the invoice.":           "commitment",
	"I'll pay it.":                      "commitment",
	"We've signed the contract.":        "commitment",
	"I accept.":                         "commitment",
	"I promise it is done.":             "commitment",
	"We'll book the room.":              "commitment",
	"I аgree":                           "commitment", // Cyrillic а
	"We ассept":                         "commitment", // Cyrillic а, с
	"That works for $40.":               "amount",
	"Fine at 300 EUR.":                  "amount",
	"OK for 500$":                       "amount",
	"OK for 500 CHF":                    "amount",
	"Costs €40":                         "amount",
	"Ok for ５００ EUR":                    "amount", // fullwidth digits
	"Fine, 500 dollars":                 "amount",
	"I'll send it by Friday.":           "date",
	"Done before 10/12.":                "date",
	"Will have it by tomorrow.":         "date",
	"The deadline is fine.":             "date",
	"Payment is due.":                   "date",
	"It's due on Jan 12.":               "date",
	"Ready by 3pm.":                     "date",
	"No later than 2026-10-09.":         "date",
	"See you Friday!":                   "date",
	"Tuesday 3pm works for me":          "date",
	"Back tomorrow, will reply then.":   "date",
	"Let's talk next week.":             "date",
	"Can do in 2 days.":                 "date",
	"Call at 14:30?":                    "date",
	"Can you confirm the address?":      "commitment",
	"Did they sign it yet?":             "commitment",
	"Let me know if you agree.":         "commitment",
	"Approved by legal last week, FYI.": "date",
	"Approved by legal, FYI.":           "commitment",
	"Approved from my side.":            "commitment",
	"Will pay on receipt.":              "commitment",
	"My code is 482913":                 "secret",
}

// commitPass are routine replies that stay auto-replies. Whole-word
// matching keeps "significant", "signal" and "acceptable" from matching
// sign and accept, and numeric dates need / or -, so "version 2.1" passes.
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
	"Happy to help.",
	"Yes, that makes sense.",
	"Ok, sure.",
	"The meeting notes are attached to the thread.",
}

func TestCommitmentFilterFailFixtures(t *testing.T) {
	var c Commitments
	for s, want := range commitFail {
		if got := c.Match(s); got != want {
			t.Errorf("%q: got %q want %q", s, got, want)
		}
	}
	own := Commitments{Phrases: []string{"zusagen"}}
	if own.Match("Ich kann zusagen.") != "commitment" {
		t.Error("owner phrase list ignored")
	}
	if own.Match("We agree.") != "commitment" {
		t.Error("an owner list replaced the defaults")
	}
}

func TestCommitmentFilterPassFixtures(t *testing.T) {
	var c Commitments
	for _, s := range commitPass {
		if got := c.Match(s); got != "" {
			t.Errorf("%q: false positive %q", s, got)
		}
	}
}
