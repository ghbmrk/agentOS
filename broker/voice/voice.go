// Package voice measures the closed check CH-21 describes for agent text
// sent to the owner. WouldHold does not withhold anything. A real hold has
// to keep the text on the Wi-Fi page, and that store is not here.
//
// The vocabulary and the reply grammar are the spec's, not a model (ARC-2).
package voice

import (
	"regexp"
	"strings"

	"github.com/ghbmrk/agentos/broker/owner"
)

// Words the spec lists. Ordinary task text that uses them is counted as a
// hold; the spec says those false holds will be common until measured.
var wordRE = regexp.MustCompile(`(?i)(?:\bcode generator\b|\bone-time\b|\b(?:code|passcode|pin|otp|authenticator|verification|grid|cell|password)\b)`)

// A control word followed by a request id or a 4 to 8 digit token.
var grammarRE = regexp.MustCompile(`(?i)\b(?:STOP|YES|NO|RUN|UNDO|MORE|HELP|STATUS|RESUME|UNLOCK|NAME)\s+(?:[A-Z][0-9]{1,2}|[0-9]{4,8})\b`)

var (
	vocabulary = []string{"code generator", "one-time", "code", "passcode", "pin", "otp", "authenticator", "verification", "grid", "cell", "password"}
	controls   = []string{"STOP", "YES", "NO", "RUN", "UNDO", "MORE", "HELP", "STATUS", "RESUME", "UNLOCK", "NAME"}
)

// The same three on the CH-12 folds (#2181), each literal replaced by its
// folds, since a fold changes the literals too (MORE folds to rnore, 0 to
// o). The fold maps space runs to one space.
var foldWordRE, foldGrammarRE, foldReplyYes, foldOrNo = func() (w, g, y, n *regexp.Regexp) {
	alt := func(lits []string) string {
		ps := make([]string, len(lits))
		for i, l := range lits {
			ps[i] = owner.FoldPattern(l)
		}
		return "(?:" + strings.Join(ps, "|") + ")"
	}
	var letters, digits []string
	for c := 'a'; c <= 'z'; c++ {
		letters = append(letters, string(c))
	}
	for c := '0'; c <= '9'; c++ {
		digits = append(digits, string(c))
	}
	l, d := alt(letters), alt(digits)
	return regexp.MustCompile(`\b` + alt(vocabulary) + `\b`),
		regexp.MustCompile(`\b` + alt(controls) + ` +(?:` + l + d + `{1,2}|` + d + `{4,8})\b`),
		regexp.MustCompile(owner.FoldPattern("reply yes")),
		regexp.MustCompile(owner.FoldPattern("or no"))
}()

// WouldHold reports whether text, or any of its CH-12 folds, matches that
// check. The footer counts when its two halves are in any folds.
func WouldHold(text string) bool {
	if wordRE.MatchString(text) || grammarRE.MatchString(text) {
		return true
	}
	low := strings.ToLower(text)
	yes, no := strings.Contains(low, "reply yes"), strings.Contains(low, "or no")
	for _, f := range owner.CheckFolds(text) {
		if foldWordRE.MatchString(f) || foldGrammarRE.MatchString(f) {
			return true
		}
		yes = yes || foldReplyYes.MatchString(f)
		no = no || foldOrNo.MatchString(f)
	}
	return yes && no
}

// Count is how many of lines WouldHold matches.
func Count(lines []string) (held, total int) {
	for _, s := range lines {
		total++
		if WouldHold(s) {
			held++
		}
	}
	return held, total
}
