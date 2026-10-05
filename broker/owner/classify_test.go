package owner

import (
	"testing"
	"time"
)

// REQ: CH-10, CH-3

func TestClassifyLowOnlyWhenEveryVerifiedConditionHolds(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	lim := Limits{Hold: 7 * 24 * time.Hour, AmountLimit: 10000, ExcludedVerbs: []string{"delete"}}
	low := Facts{Verb: "send", RecipientChecked: true, RecipientExists: true, RecipientByOwner: true, HasAmount: true, Amount: 9999}
	if Classify(low, lim, now) != Low {
		t.Fatal("owner-created recipient under the limit should be low")
	}
	old := low
	old.RecipientByOwner, old.RecipientSince = false, now.Add(-8*24*time.Hour)
	if Classify(old, lim, now) != Low {
		t.Fatal("recipient older than the hold should be low")
	}
	cases := map[string]func(*Facts){
		"amount at limit":      func(f *Facts) { f.Amount = 10000 },
		"negative amount":      func(f *Facts) { f.Amount = -1 },
		"excluded verb":        func(f *Facts) { f.Verb = "delete" },
		"no verb":              func(f *Facts) { f.Verb = "" },
		"recipient unchecked":  func(f *Facts) { f.RecipientChecked = false },
		"recipient missing":    func(f *Facts) { f.RecipientExists = false },
		"auto-added":           func(f *Facts) { f.RecipientAutoAdded = true },
		"new, not by owner":    func(f *Facts) { f.RecipientByOwner, f.RecipientSince = false, now.Add(-time.Hour) },
		"unknown age":          func(f *Facts) { f.RecipientByOwner, f.RecipientSince = false, time.Time{} },
		"grant change":         func(f *Facts) { f.Kind = GrantChange },
		"secret reveal CRED-6": func(f *Facts) { f.Kind = SecretReveal },
		"recovery":             func(f *Facts) { f.Kind = Recovery },
		"tier change":          func(f *Facts) { f.Kind = TierChange },
	}
	for name, mut := range cases {
		f := low
		mut(&f)
		if Classify(f, lim, now) != High {
			t.Errorf("%s: want high", name)
		}
	}
	if Classify(Facts{Verb: "send", NoRecipient: true, HasAmount: true, Amount: 1}, Limits{}, now) != High {
		t.Error("zero limit must make every amount high")
	}
}
