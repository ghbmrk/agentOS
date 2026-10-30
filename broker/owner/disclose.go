package owner

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ghbmrk/agentos/broker/control"
)

// Hidden replaces an outbound text that looks like it carries a code or a
// key when it could not be kept for the owner page: it names no page
// (CH-19, D-079). HiddenPointer replaces it once it is kept (keep.go).
const (
	Hidden        = "I held back a message because it may contain a code or key, and I could not keep it. Ask me to put it another way."
	HiddenPointer = "I held back a message because it may contain a code or key. Read it on my Wi-Fi page."
)

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

// signIn joins "sign in" into the code word SIGNIN.
var signIn = regexp.MustCompile(`(?i)\bsign\s+in\b`)

// SecretShaped reports whether s carries a known token format or a short
// code next to a code word (CH-19): TokenShaped or CodeShaped.
func SecretShaped(s string) bool {
	return TokenShaped(s) || CodeShaped(s)
}

// TokenShaped reports whether s, folded, carries a known token format.
func TokenShaped(s string) bool {
	return tokenFormats.MatchString(fold(s))
}

// CodeShaped reports whether s carries a short code next to a code word
// (CH-19). It runs on folded text, so fullwidth or other Unicode digits
// and look-alike letters do not slip past, and it joins adjacent digit
// groups, so "482 913" and "4 8 2 9 1 3" read as one code. The check also
// runs on each of CheckFolds' CH-12 folds (#2181), with the code words
// matched by their folds.
func CodeShaped(s string) bool {
	if codeNearWord(signIn.ReplaceAllString(fold(s), "signin"), func(w string) bool { return codeWords[strings.ToUpper(w)] }) {
		return true
	}
	for _, f := range CheckFolds(s) {
		if codeNearWord(foldSignIn.ReplaceAllString(f, "signin"), foldCodeWord.MatchString) {
			return true
		}
	}
	return false
}

// foldCodeWord matches a whole word that is a fold of a code word, and
// foldSignIn a fold of "sign in".
var foldCodeWord, foldSignIn = func() (*regexp.Regexp, *regexp.Regexp) {
	var alts []string
	for w := range codeWords {
		alts = append(alts, FoldPattern(w))
	}
	sort.Strings(alts)
	return regexp.MustCompile(`^(?:` + strings.Join(alts, "|") + `)$`),
		regexp.MustCompile(`\b` + FoldPattern("sign in") + `\b`)
}()

// codeNearWord reports whether a code-like token lies within codeReach
// words of a word isCodeWord accepts.
func codeNearWord(s string, isCodeWord func(string) bool) bool {
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
		if !isCodeWord(w) {
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
// from the broker's own templates: secret-shaped text becomes Hidden, which
// says it was not kept; the channel's own filter keeps it and points to it
// (Channel.disclose). Broker-rendered texts carrying the broker's own CH-10
// codes do not pass through it.
func Disclose(s string) string {
	if SecretShaped(s) {
		return Hidden
	}
	return s
}

// AgentToken and AgentCode split AgentSecret into its two classes, in the
// same three readings (CH-19, #906).
func AgentToken(text string) bool {
	return TokenShaped(text) || TokenShaped(control.StripControls(text)) || TokenShaped(control.JoinControls(text))
}

func AgentCode(text string) bool {
	return CodeShaped(text) || CodeShaped(control.StripControls(text)) || CodeShaped(control.JoinControls(text))
}

// ExpiredCode stands in for a code once its hours have passed (CH-19,
// #906). It holds no code word and no digit, so it adds no code shape.
const ExpiredCode = "[expired]"

// ExpireCodes returns text with its codes replaced by ExpiredCode, the
// rest left readable (CH-19, #906). It replaces the code-like words next
// to a code word, then, if a code shape is still found, every code-like
// word, and then, if one still is, the whole text, so what it returns is
// never AgentCode.
func ExpireCodes(text string) string {
	words := textWords(text)
	for _, all := range []bool{false, true} {
		out := text
		for _, w := range slices.Backward(codesIn(words, all)) {
			out = out[:w.i] + ExpiredCode + out[w.j:]
		}
		if !AgentCode(out) {
			return out
		}
	}
	return ExpiredCode
}

// CodeKind names the kind of code text carries, never its value: "a
// code of 6 digits" when every code next to a code word is that many digits,
// otherwise "a code" (CH-19, #906).
func CodeKind(text string) string {
	n := 0
	for _, w := range codesIn(textWords(text), false) {
		d := utf8.RuneCountInString(w.digits)
		if d == 0 || n != 0 && d != n {
			return "a code"
		}
		n = d
	}
	if n == 0 {
		return "a code"
	}
	return fmt.Sprintf("a code of %d digits", n)
}

// word is one word of a text, at bytes [i, j). digits holds its digits
// when it is digits only, adjacent digit groups joined as codeNearWord
// joins them.
type word struct {
	i, j   int
	text   string
	digits string
}

// textWords splits text into words as codeNearWord does, keeping where
// each is, with Unicode letters, digits and marks as word characters.
func textWords(text string) []word {
	var out []word
	start := -1
	end := func(j int) {
		w := word{i: start, j: j, text: text[start:j]}
		if allNumber(w.text) {
			w.digits = w.text
			if n := len(out); n > 0 && out[n-1].digits != "" && utf8.RuneCountInString(out[n-1].digits+w.text) <= 10 {
				out[n-1].j, out[n-1].digits = j, out[n-1].digits+w.text
				out[n-1].text = text[out[n-1].i:j]
				return
			}
		}
		out = append(out, w)
	}
	for i, r := range text {
		in := unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r) || r == '-'
		switch {
		case in && start < 0:
			start = i
		case !in && start >= 0:
			end(i)
			start = -1
		}
	}
	if start >= 0 {
		end(len(text))
	}
	return out
}

// codesIn returns the code-like words of words: those within codeReach of
// a code word, or with all, every one.
func codesIn(words []word, all bool) []word {
	near := make([]bool, len(words))
	for i, w := range words {
		if !isCodeWord(w.text) && !(strings.EqualFold(w.text, "sign") && i+1 < len(words) && strings.EqualFold(words[i+1].text, "in")) {
			continue
		}
		for j := max(0, i-codeReach); j <= min(len(words)-1, i+codeReach+1); j++ {
			near[j] = true
		}
	}
	var out []word
	for i, w := range words {
		if (all || near[i]) && codeLikeWord(w) {
			out = append(out, w)
		}
	}
	return out
}

// isCodeWord reports whether w, or one of its folds, is a code word.
func isCodeWord(w string) bool {
	if codeWords[strings.ToUpper(fold(w))] {
		return true
	}
	return slices.ContainsFunc(CheckFolds(w), func(f string) bool { return foldCodeWord.MatchString(strings.TrimSpace(f)) })
}

// codeLikeWord is codeLike on a word's folded text, or 4-10 joined
// digits.
func codeLikeWord(w word) bool {
	if n := utf8.RuneCountInString(w.digits); n > 0 {
		return n >= 4 && n <= 10
	}
	return codeLike(fold(w.text)) || hasNumber(w.text) && utf8.RuneCountInString(w.text) >= 4 && utf8.RuneCountInString(w.text) <= 10
}

func allNumber(s string) bool {
	for _, r := range s {
		if !unicode.IsNumber(r) {
			return false
		}
	}
	return s != ""
}

func hasNumber(s string) bool {
	return strings.IndexFunc(s, unicode.IsNumber) >= 0
}
