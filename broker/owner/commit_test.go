package owner

import "testing"

// REQ: ADP-11

func TestCommitmentFilterTurnsCommitmentsIntoApprovals(t *testing.T) {
	var c Commitments
	hits := map[string]string{
		"Sure, I can confirm the booking.": "commitment",
		"We agree to the terms.":           "commitment",
		"I will pay the invoice.":          "commitment",
		"Approved from my side.":           "commitment",
		"Happy to sign it.":                "commitment",
		"We accept.":                       "commitment",
		"That works for $40.":              "amount",
		"Fine at 300 EUR.":                 "amount",
		"Let's do Friday.":                 "date",
		"See you on 10/12.":                "date",
		"Can we meet tomorrow at 3pm?":     "date",
		"The deadline is fine.":            "date",
		"Meet on 2026-10-04.":              "date",
		"My code is 482913":                "secret",
		"Thanks, signed copy attached.":    "commitment",
	}
	for s, want := range hits {
		if got := c.Match(s); got != want {
			t.Errorf("%q: got %q want %q", s, got, want)
		}
	}
	passes := []string{
		"Thanks, got it. Talk soon.",
		"Sounds good, I'll take a look at the design.",
		"You may want to check with Sam.",
	}
	for _, s := range passes {
		if got := c.Match(s); got != "" {
			t.Errorf("%q: false positive %q", s, got)
		}
	}
	if (Commitments{Phrases: []string{"zusagen"}}).Match("Ich kann zusagen.") != "commitment" {
		t.Error("owner phrase list ignored")
	}
}
