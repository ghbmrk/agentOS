package owner

import (
	"regexp"
	"strings"
)

// Hidden replaces an outbound text that looks like it carries a code or a
// key (CH-19).
const Hidden = "A message was held back because it may contain a code or key. Read it on the box's Wi-Fi page."

// tokenFormats are known secret formats. They are fixed patterns, not
// inference (ARC-2); Loop 2 regressions add to them (LOOP-10).
var tokenFormats = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`\bAKIA[0-9A-Z]{16}\b`,                                         // AWS access key ID
	`\bgh[pousr]_[A-Za-z0-9]{30,}`,                                 // GitHub tokens
	`\bgithub_pat_[A-Za-z0-9_]{20,}`,                               // GitHub fine-grained token
	`\bxox[abprs]-[A-Za-z0-9-]{10,}`,                               // Slack
	`\bsk-[A-Za-z0-9_-]{20,}`,                                      // OpenAI, Anthropic and similar
	`\b[rs]k_(live|test)_[A-Za-z0-9]{16,}`,                         // Stripe
	`\bAIza[0-9A-Za-z_-]{35}`,                                      // Google API key
	`\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}`, // JWT
	`-----BEGIN [A-Z ]*PRIVATE KEY-----`,
	`otpauth://`,
}, "|"))

// codeWords anchor short codes: a 4-10 character token with a digit counts
// only within codeReach words of one of these, so amounts, dates, and order
// numbers pass.
var codeWords = map[string]bool{
	"CODE": true, "CODES": true, "OTP": true, "VERIFICATION": true, "VERIFY": true,
	"PIN": true, "PASSCODE": true, "2FA": true, "MFA": true, "ONE-TIME": true,
	"SECURITY": true, "LOGIN": true, "TOKEN": true, "PASSWORD": true, "PASS": true,
	"KEY": true, "SIGN-IN": true, "SIGNIN": true,
}

const codeReach = 4

// SecretShaped reports whether s carries a known token format or a short
// code next to a code word (CH-19). It runs on folded text, so fullwidth
// or other Unicode digits and look-alike letters do not slip past, and it
// joins adjacent digit groups, so "482 913" and "4 8 2 9 1 3" read as one
// code.
func SecretShaped(s string) bool {
	s = fold(s)
	if tokenFormats.MatchString(s) {
		return true
	}
	var words []string
	for _, w := range strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-')
	}) {
		if n := len(words); n > 0 && allDigits(w) && allDigits(words[n-1]) && len(words[n-1])+len(w) <= 10 {
			words[n-1] += w
			continue
		}
		words = append(words, w)
	}
	for i, w := range words {
		if !codeWords[strings.ToUpper(w)] {
			continue
		}
		for j := i - codeReach; j <= i+codeReach; j++ {
			if j >= 0 && j < len(words) && j != i && codeLike(words[j]) {
				return true
			}
		}
	}
	return false
}

// codeLike is a 4-10 character token of letters, digits and dashes with at
// least one digit (e.g. 482913, G-482913, A1B2C3).
func codeLike(w string) bool {
	if len(w) < 4 || len(w) > 10 {
		return false
	}
	digit := false
	for _, r := range w {
		if r >= '0' && r <= '9' {
			digit = true
		}
	}
	return digit
}

// Disclose is the filter for owner-bound text whose content did not come
// from the broker's own templates: secret-shaped text becomes a pointer to
// the local UI. Broker-rendered texts carrying the broker's own CH-10 codes
// do not pass through it.
func Disclose(s string) string {
	if SecretShaped(s) {
		return Hidden
	}
	return s
}
