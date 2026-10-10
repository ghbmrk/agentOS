package recall

import (
	"strings"
	"testing"
)

// Known token shapes are removed even when they are the published examples,
// which are not especially random. A tracking number and the word "token" stay.
func TestKnownTokenShapesAreRemoved(t *testing.T) {
	sc := NewScrubber(nil)
	in := "see AKIAIOSFODNN7EXAMPLE and ghp_1234567890abcdefABCDEF and xoxb-1234567890-abcdefghij"
	out := sc.Scrub(in)
	for _, leak := range []string{"AKIAIOSFODNN7EXAMPLE", "ghp_1234567890abcdefABCDEF", "xoxb-1234567890-abcdefghij"} {
		if strings.Contains(out, leak) {
			t.Fatalf("kept %s in %q", leak, out)
		}
	}
	jwt := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1c2VyIn0.signature"
	if got := sc.Scrub("header " + jwt); strings.Contains(got, "eyJhbGciOiJub25lIn0") {
		t.Fatalf("jwt kept: %q", got)
	}
	plain := "parcel 1Z999AA10123456784 and the word token"
	if got := sc.Scrub(plain); got != plain {
		t.Fatalf("ordinary text changed: %q", got)
	}
}
