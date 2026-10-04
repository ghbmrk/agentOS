package owner

import (
	"regexp"
	"strings"
)

// Commitment patterns for context-scoped auto-replies (ADP-11, Mark's D2
// decision). A reply becomes a normal approval request when it carries
// secret-shaped content (CH-19), money, any date or time reference, one of
// ADP-11's commitment phrases in any person or a question, or a further
// commitment verb after a first-person subject. A false positive costs one
// approval prompt, which Mark accepted. These are fixed patterns with no
// inference (ARC-2), run on folded text so look-alike letters and Unicode
// digits cannot slip past; Loop 2 regressions add to them (LOOP-10).
var (
	currency  = `usd|eur|gbp|chf|jpy|cny|cad|aud|nzd|inr|mxn|brl|sek|nok|dkk|pln|czk|huf|sgd|hkd|krw|zar|try|ils|aed|dollars?|euros?|pounds?|bucks|cents?|francs?|yen|rupees?`
	amountPat = regexp.MustCompile(`(?i)[$€£¥₹₩₪₺]\s?\d|\d[\d,.]*\s?[$€£¥₹₩₪₺]|\b\d[\d,.]*\s?(` + currency + `|k)\b|\b(` + currency + `)\s?\d`)

	month   = `jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may|june?|july?|aug(ust)?|sep(t|tember)?|oct(ober)?|nov(ember)?|dec(ember)?`
	datePat = regexp.MustCompile(`(?i)` + strings.Join([]string{
		// A month counts next to a day number, so "Thanks Jan" and "you
		// may" pass.
		`\b(` + month + `)\.?\s+\d{1,2}(st|nd|rd|th)?\b`,
		`\b\d{1,2}(st|nd|rd|th)?\s+(of\s+)?(` + month + `)\b`,
		`\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)s?\b`,
		// Numeric dates use / or - only, so "version 2.1" passes.
		`\b\d{1,2}[/-]\d{1,2}([/-]\d{2,4})?\b`,
		`\b\d{4}-\d{2}-\d{2}\b`,
		`\b\d{1,2}(:\d{2})?\s?(am|pm)\b`,
		`\b\d{1,2}:\d{2}\b`,
		`\b(today|tonight|tomorrow|yesterday|noon|midnight|weekend|eod|eow|deadline|deadlines|overdue)\b`,
		`\b(next|this|last)\s+(week|month|year|morning|afternoon|evening)\b`,
		`\bend of (the )?(day|week|month)\b`,
		`\bin\s+\d+\s+(minutes?|hours?|days?|weeks?|months?)\b`,
		// "due" as a deadline, so "due to travel" passes.
		`\bdue\s+(on|by|date|today|tomorrow|tonight|next)\b|\b(is|are|was|were|be)\s+due\b`,
	}, "|"))
)

// DefaultPhrases are ADP-11's commitment phrases with their inflections.
// They match as whole words in any person and in questions, so "can you
// confirm?" holds the reply, but "significant", "signal" and "acceptable"
// do not.
var DefaultPhrases = []string{
	"confirm", "confirms", "confirmed", "confirming", "confirmation",
	"agree", "agrees", "agreed", "agreeing", "agreement",
	"will pay", "ll pay", "shall pay",
	"approve", "approves", "approved", "approving", "approval",
	"sign", "signs", "signed", "signing", "signature", "sign off",
	"accept", "accepts", "accepted", "accepting", "acceptance",
}

// DefaultVerbs are further commitment verbs, additions to ADP-11's
// phrases. They count only after a first-person subject (I, we, and their
// contractions), within three words: "we'll book", "I paid".
var DefaultVerbs = []string{
	"pay", "paid",
	"commit", "committed",
	"promise", "promised",
	"guarantee", "guaranteed",
	"book", "booked", "order", "ordered", "reserve", "reserved",
}

var firstPerson = map[string]bool{"i": true, "we": true, "im": true, "ill": true, "ive": true, "id": true,
	"were": true, "weve": true, "well": true, "wed": true}

// Commitments holds the owner's additions to the defaults (their
// languages). Phrases match as whole words anywhere; Verbs match after a
// first-person subject. List each inflection.
type Commitments struct {
	Verbs   []string
	Phrases []string
}

// Match returns which class the reply hits: "secret", "amount", "date",
// or "commitment". Empty means it may go as an auto-reply.
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
	// Words: letters and digits only, so "I'll" reads "ill" and "we're"
	// reads "were".
	words := strings.FieldsFunc(strings.ToLower(strings.ReplaceAll(f, "'", "")), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127)
	})
	verbs := append(append([]string(nil), DefaultVerbs...), c.Verbs...)
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
	phrases := append(append([]string(nil), DefaultPhrases...), c.Phrases...)
	for _, p := range phrases {
		p = strings.Join(strings.Fields(strings.ToLower(fold(p))), " ")
		if p != "" && strings.Contains(joined, " "+p+" ") {
			return "commitment"
		}
	}
	return ""
}
