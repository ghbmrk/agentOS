package owner

import (
	"regexp"
	"strings"
)

// Commitment patterns for context-scoped auto-replies (ADP-11, Mark's D2
// decision). A match turns the reply into a normal approval request. They
// are fixed patterns with no inference (ARC-2), run on folded text so
// look-alike letters and Unicode digits cannot slip past; Loop 2
// regressions add to them (LOOP-10).
var (
	currency  = `usd|eur|gbp|chf|jpy|cny|cad|aud|nzd|inr|mxn|brl|sek|nok|dkk|pln|czk|huf|sgd|hkd|krw|zar|try|ils|aed|dollars?|euros?|pounds?|bucks|cents?|francs?|yen|rupees?`
	amountPat = regexp.MustCompile(`(?i)[$€£¥₹₩₪₺]\s?\d|\d[\d,.]*\s?[$€£¥₹₩₪₺]|\b\d[\d,.]*\s?(` + currency + `|k)\b|\b(` + currency + `)\s?\d`)
	month     = `jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|june?|july?|aug(ust)?|sep(t|tember)?|oct(ober)?|nov(ember)?|dec(ember)?`
	datePat   = regexp.MustCompile(`(?i)` + strings.Join([]string{
		// A month counts only next to a day number, so "Thanks Jan" and
		// "you may" pass.
		`\b(` + month + `)\.?\s+\d{1,2}(st|nd|rd|th)?\b`,
		`\b\d{1,2}(st|nd|rd|th)?\s+(of\s+)?(` + month + `)\b`,
		`\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)s?\b`,
		// Numeric dates use / or - only, so "version 2.1" passes.
		`\b\d{1,2}[/-]\d{1,2}([/-]\d{2,4})?\b`,
		`\b\d{4}-\d{2}-\d{2}\b`,
		`\b\d{1,2}(:\d{2})?\s?(am|pm)\b`,
		`\b\d{1,2}:\d{2}\b`,
		`\b(today|tonight|tomorrow|next (week|month|year)|end of (the )?(day|week|month)|eod|eow|deadline|deadlines|by noon|by midnight|overdue)\b`,
		// "due" only as a deadline, so "due to travel" passes.
		`\bdue\s+(on|by|date|today|tomorrow|tonight|next)\b|\b(is|are|was|were|be)\s+due\b`,
	}, "|"))
)

// DefaultPhrases are ADP-11's commitment phrases with their inflections.
// Each matches as whole words, so "significant", "signal" and "acceptable"
// pass.
var DefaultPhrases = []string{
	"confirm", "confirms", "confirmed", "confirming", "confirmation",
	"agree", "agrees", "agreed", "agreeing", "agreement",
	"will pay", "ll pay", "shall pay", "pay you", "pay the",
	"approve", "approves", "approved", "approving", "approval",
	"sign", "signs", "signed", "signing", "signature", "sign off",
	"accept", "accepts", "accepted", "accepting", "acceptance",
	"promise", "promised", "promises", "guarantee", "guaranteed",
}

// Commitments is the owner's commitment-phrase list (their languages).
// Phrases match as whole words; list each inflection.
type Commitments struct {
	Phrases []string
}

// Match returns which pattern class the reply hits: "secret" (CH-19 applies
// too), "amount", "date", or "commitment". Empty means no match.
func (c Commitments) Match(reply string) string {
	f := fold(reply)
	switch {
	case SecretShaped(f):
		return "secret"
	case amountPat.MatchString(f):
		return "amount"
	case datePat.MatchString(f):
		return "date"
	}
	phrases := c.Phrases
	if phrases == nil {
		phrases = DefaultPhrases
	}
	words := " " + strings.Join(strings.FieldsFunc(strings.ToLower(f), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127)
	}), " ") + " "
	for _, p := range phrases {
		p = strings.Join(strings.Fields(strings.ToLower(fold(p))), " ")
		if p != "" && strings.Contains(words, " "+p+" ") {
			return "commitment"
		}
	}
	return ""
}
