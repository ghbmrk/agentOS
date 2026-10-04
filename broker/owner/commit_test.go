package owner

import "testing"

// REQ: ADP-11

func TestCommitmentFilterTurnsCommitmentsIntoApprovals(t *testing.T) {
	var c Commitments
	hits := map[string]string{
		"Sure, I can confirm the booking.": "commitment",
		"We agree to the terms.":           "commitment",
		"I will pay the invoice.":          "commitment",
		"I'll pay it.":                     "commitment",
		"Approved from my side.":           "commitment",
		"Happy to sign it.":                "commitment",
		"We accept.":                       "commitment",
		"Thanks, signed copy attached.":    "commitment",
		"I promise it is done.":            "commitment",
		"That works for $40.":              "amount",
		"Fine at 300 EUR.":                 "amount",
		"OK for 500$":                      "amount",
		"OK for 500 CHF":                   "amount",
		"Costs €40":                        "amount",
		"Let's do Friday.":                 "date",
		"See you on 10/12.":                "date",
		"Can we meet tomorrow at 3pm?":     "date",
		"The deadline is fine.":            "date",
		"Meet on 2026-10-04.":              "date",
		"Meet Jan 12.":                     "date",
		"The report is due Friday.":        "date",
		"Payment is due.":                  "date",
		"My code is 482913":                "secret",
		// Look-alike letters and digits do not slip past.
		"I аgree":           "commitment", // Cyrillic а
		"We ассept":         "commitment", // Cyrillic а, с
		"Ok for ５００ EUR":    "amount",     // fullwidth digits
		"Fine, 500 dollars": "amount",
	}
	for s, want := range hits {
		if got := c.Match(s); got != want {
			t.Errorf("%q: got %q want %q", s, got, want)
		}
	}
	if (Commitments{Phrases: []string{"zusagen"}}).Match("Ich kann zusagen.") != "commitment" {
		t.Error("owner phrase list ignored")
	}
}

// The pass corpus pins routine replies that must stay auto-replies.
func TestCommitmentFilterPassCorpus(t *testing.T) {
	var c Commitments
	for _, s := range []string{
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
	} {
		if got := c.Match(s); got != "" {
			t.Errorf("%q: false positive %q", s, got)
		}
	}
}
