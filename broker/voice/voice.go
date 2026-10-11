// Package voice measures the closed check CH-21 describes for agent text
// sent to the owner. WouldHold does not withhold anything. A real hold has
// to keep the text on the Wi-Fi page, and that store is not here.
//
// The vocabulary and the reply grammar are the spec's, not a model (ARC-2).
package voice

import (
	"regexp"
	"strings"
)

// Words the spec lists. Ordinary task text that uses them is counted as a
// hold; the spec says those false holds will be common until measured.
var wordRE = regexp.MustCompile(`(?i)(?:\bcode generator\b|\bone-time\b|\b(?:code|passcode|pin|otp|authenticator|verification|grid|cell|password)\b)`)

// A control word followed by a request id or a 4 to 8 digit token.
var grammarRE = regexp.MustCompile(`(?i)\b(?:STOP|YES|NO|RUN|UNDO|MORE|HELP|STATUS|RESUME|UNLOCK|NAME)\s+(?:[A-Z][0-9]{1,2}|[0-9]{4,8})\b`)

// WouldHold reports whether text matches that check.
func WouldHold(text string) bool {
	if wordRE.MatchString(text) || grammarRE.MatchString(text) {
		return true
	}
	low := strings.ToLower(text)
	return strings.Contains(low, "reply yes") && strings.Contains(low, "or no")
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
