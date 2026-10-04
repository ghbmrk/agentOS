package owner

import (
	"strings"
	"time"
)

// Tier is CH-10's approval tier.
type Tier int

const (
	// Low: a texted one-time code from the request, replied from the
	// owner's number.
	Low Tier = iota
	// High: a code-generator code or a paper-grid cell.
	High
)

func (t Tier) String() string {
	if t == Low {
		return "low"
	}
	return "high"
}

// Facts are what the broker itself verified about one item (CH-10). The
// agent's claims never fill them: whoever builds Facts reads them from the
// source system or the broker's own records.
type Facts struct {
	// Kind marks items that are high risk by kind: new or wider grants or
	// pre-allowances, CRED-6 actions, recovery, tier changes.
	Kind Kind
	// Verb is the operation's verb (ADP-2 label).
	Verb string
	// RecipientChecked: the broker looked the recipient up in the owner's
	// account. False means the recipient is unclassifiable.
	RecipientChecked bool
	// NoRecipient: the item has no recipient (e.g. archive a file).
	NoRecipient      bool
	RecipientExists  bool
	RecipientByOwner bool
	RecipientSince   time.Time
	// RecipientAutoAdded: the service added it, not the owner.
	RecipientAutoAdded bool
	// Amount in the account's minor units; HasAmount if money moves.
	HasAmount bool
	Amount    int64
}

// Kind is an item's risk kind.
type Kind int

const (
	Ordinary Kind = iota
	GrantChange
	SecretReveal // CRED-6
	Recovery
	TierChange
)

// Limits are the owner-set tier boundaries. Changing them is itself a
// high-risk intent (Kind TierChange).
type Limits struct {
	// Hold is how long a recipient the owner did not create must have
	// existed (ADP-9's hold period).
	Hold time.Duration
	// AmountLimit: amounts at or above it are high risk. Zero means every
	// amount is high risk.
	AmountLimit int64
	// ExcludedVerbs are always high risk.
	ExcludedVerbs []string
}

// Classify applies CH-10. Low risk needs all of: an existing recipient
// created by the owner or older than the hold and not added automatically;
// any amount under the limit; a verb the owner did not exclude. Anything
// else, including anything unverified, is high risk.
func Classify(f Facts, l Limits, now time.Time) Tier {
	if f.Kind != Ordinary || f.Verb == "" {
		return High
	}
	for _, v := range l.ExcludedVerbs {
		if strings.EqualFold(v, f.Verb) {
			return High
		}
	}
	if f.HasAmount && (f.Amount < 0 || f.Amount >= l.AmountLimit) {
		return High
	}
	if f.NoRecipient {
		return Low
	}
	if !f.RecipientChecked || !f.RecipientExists || f.RecipientAutoAdded {
		return High
	}
	if f.RecipientByOwner {
		return Low
	}
	if f.RecipientSince.IsZero() || now.Sub(f.RecipientSince) < l.Hold {
		return High
	}
	return Low
}
