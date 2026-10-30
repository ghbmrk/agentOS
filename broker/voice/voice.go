// Package voice measures the closed check CH-21 describes for agent text
// sent to the owner. The check itself is owner.VoiceShaped, which the
// owner channel runs on every agent text (CH-21e); this package keeps the
// measurement of its false holds and the literal sweep.
package voice

import "github.com/ghbmrk/agentos/broker/owner"

// WouldHold reports whether text, or any of its CH-12 folds, matches the
// CH-21 check (owner.VoiceShaped).
func WouldHold(text string) bool { return owner.VoiceShaped(text) }

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
