package owner

import (
	"regexp"
	"strings"
)

// Commitment patterns for context-scoped auto-replies (ADP-11, Mark's D2
// decision). A match turns the reply into a normal approval request. They
// are fixed patterns with no inference (ARC-2); Loop 2 regressions add to
// them (LOOP-10).
var (
	amountPat = regexp.MustCompile(`(?i)[$€£¥]\s?\d|\b\d[\d,.]*\s?(usd|eur|gbp|cad|aud|dollars?|euros?|pounds?|bucks|cents?|k)\b|\b(usd|eur|gbp|cad|aud)\s?\d`)
	datePat   = regexp.MustCompile(`(?i)\b(jan(uary)?|feb(ruary)?|mar(ch)?|apr(il)?|may\s+\d|june?|july?|aug(ust)?|sep(t|tember)?|oct(ober)?|nov(ember)?|dec(ember)?)\b|` +
		`\b(mon|tues?|wed(nes)?|thu(rs?)?|fri|sat(ur)?|sun)(day)?\b|` +
		`\b\d{1,2}[/.-]\d{1,2}([/.-]\d{2,4})?\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}(:\d{2})?\s?(am|pm)\b|\b\d{1,2}:\d{2}\b|` +
		`\b(today|tonight|tomorrow|next (week|month|year)|end of (the )?(day|week|month)|eod|eow|deadline|due|by noon|by midnight)\b`)
)

// DefaultPhrases are the commitment phrases named in ADP-11, as stems.
var DefaultPhrases = []string{"confirm", "agree", "will pay", "approve", "sign", "accept"}

// Commitments is the owner's commitment-phrase list (their languages).
type Commitments struct {
	Phrases []string
}

// Match returns which pattern class the reply hits: "amount", "date",
// "commitment", or "secret" (CH-19 applies too). Empty means no match.
func (c Commitments) Match(reply string) string {
	switch {
	case SecretShaped(reply):
		return "secret"
	case amountPat.MatchString(reply):
		return "amount"
	case datePat.MatchString(reply):
		return "date"
	}
	phrases := c.Phrases
	if phrases == nil {
		phrases = DefaultPhrases
	}
	low := " " + strings.Join(strings.FieldsFunc(strings.ToLower(reply), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 127)
	}), " ")
	for _, p := range phrases {
		// A phrase matches at a word start, so "sign" catches "signed"
		// and "sign-off" but not "design".
		if p != "" && strings.Contains(low, " "+strings.ToLower(p)) {
			return "commitment"
		}
	}
	return ""
}
