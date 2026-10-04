package owner

import (
	"regexp"
	"strings"
)

// Commitment patterns for context-scoped auto-replies (ADP-11, Mark's D2
// decision; narrowed by the PR #22 arbitration). A reply becomes a normal
// approval request when it carries secret-shaped content (CH-19), money,
// an explicit deadline, or a first-person commitment verb. These are fixed
// patterns with no inference (ARC-2), run on folded text so look-alike
// letters and Unicode digits cannot slip past; Loop 2 regressions add to
// them (LOOP-10). Target: at most 5% of routine replies flagged, measured
// on the pass fixtures in commit_test.go.
var (
	currency  = `usd|eur|gbp|chf|jpy|cny|cad|aud|nzd|inr|mxn|brl|sek|nok|dkk|pln|czk|huf|sgd|hkd|krw|zar|try|ils|aed|dollars?|euros?|pounds?|bucks|cents?|francs?|yen|rupees?`
	amountPat = regexp.MustCompile(`(?i)[$€£¥₹₩₪₺]\s?\d|\d[\d,.]*\s?[$€£¥₹₩₪₺]|\b\d[\d,.]*\s?(` + currency + `|k)\b|\b(` + currency + `)\s?\d`)

	month    = `jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|june?|july?|aug(ust)?|sep(t|tember)?|oct(ober)?|nov(ember)?|dec(ember)?`
	weekday  = `monday|tuesday|wednesday|thursday|friday|saturday|sunday`
	when     = `(` + weekday + `|today|tonight|tomorrow|noon|midnight|eod|eow|end of (the )?(day|week|month)|next (week|month)|(` + month + `)\.?\s+\d{1,2}(st|nd|rd|th)?|\d{1,2}(st|nd|rd|th)?\s+(of\s+)?(` + month + `)|\d{1,2}[/-]\d{1,2}([/-]\d{2,4})?|\d{4}-\d{2}-\d{2}|\d{1,2}(:\d{2})?\s?(am|pm))`
	deadline = regexp.MustCompile(`(?i)\b(by|before|until|no later than|due( on| by)?)\s+(the\s+)?` + when + `\b|\b(deadline|deadlines|overdue)\b|\b(is|are|was|were|be)\s+due\b`)
)

// DefaultVerbs are commitment verbs with their inflections. They count only
// after a first-person subject (I, we, and their contractions), within
// three words: "I'll confirm", "we agree", "I have signed".
var DefaultVerbs = []string{
	"confirm", "confirms", "confirmed",
	"agree", "agrees", "agreed",
	"pay", "paid",
	"approve", "approves", "approved",
	"sign", "signed",
	"accept", "accepts", "accepted",
	"commit", "committed",
	"promise", "promised",
	"guarantee", "guaranteed",
	"book", "booked", "order", "ordered", "reserve", "reserved",
}

var firstPerson = map[string]bool{"i": true, "we": true, "im": true, "ill": true, "ive": true, "id": true,
	"were": true, "weve": true, "well": true, "wed": true}

// Commitments is the owner's commitment-verb list (their languages). Verbs
// match as whole words after a first-person subject; list each inflection.
// Phrases match as whole words anywhere, for languages where the subject
// is part of the verb.
type Commitments struct {
	Verbs   []string
	Phrases []string
}

// Match returns which class the reply hits: "secret", "amount", "deadline",
// or "commitment". Empty means it may go as an auto-reply.
func (c Commitments) Match(reply string) string {
	f := fold(reply)
	switch {
	case SecretShaped(f):
		return "secret"
	case amountPat.MatchString(f):
		return "amount"
	case deadline.MatchString(f):
		return "deadline"
	}
	// Words: letters and digits only, so "I'll" reads "ill" and "we're"
	// reads "were".
	words := strings.FieldsFunc(strings.ToLower(strings.ReplaceAll(f, "'", "")), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127)
	})
	verbs := c.Verbs
	if verbs == nil {
		verbs = DefaultVerbs
	}
	isVerb := map[string]bool{}
	for _, v := range verbs {
		isVerb[strings.ToLower(fold(v))] = true
	}
	for i, w := range words {
		if !isVerb[w] {
			continue
		}
		for j := i - 1; j >= 0 && j >= i-3; j-- {
			if firstPerson[words[j]] {
				return "commitment"
			}
		}
	}
	joined := " " + strings.Join(words, " ") + " "
	for _, p := range c.Phrases {
		p = strings.Join(strings.Fields(strings.ToLower(fold(p))), " ")
		if p != "" && strings.Contains(joined, " "+p+" ") {
			return "commitment"
		}
	}
	return ""
}
