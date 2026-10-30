package browser

import (
	"strings"

	"github.com/ghbmrk/agentos/broker/decoy/match"
)

// Redacted replaces every value the filter removes; it matches the vault's
// placeholder so agents see one marker.
const Redacted = match.Redacted

// MaxSnapshot bounds the snapshot text returned per request, in bytes.
const MaxSnapshot = 256 * 1024

// Scrubber removes known secret values (the vault's Redactor: exact values and
// their common encodings).
type Scrubber interface {
	Redact([]byte) []byte
}

// Detect is CLK-4's fixed-pattern detector, which lives in broker/decoy/match
// with the decoy table's matcher (KRN-12, #3762).
func Detect(text string) (string, int) { return match.Detect(text) }

// filter applies the vault's exact values first, then the detector.
type filter struct{ scrub Scrubber }

func (f filter) text(s string) (string, int) {
	n := 0
	if f.scrub != nil {
		before := strings.Count(s, Redacted)
		s = string(f.scrub.Redact([]byte(s)))
		if d := strings.Count(s, Redacted) - before; d > 0 {
			n += d
		}
	}
	s, k := Detect(s)
	return s, n + k
}
