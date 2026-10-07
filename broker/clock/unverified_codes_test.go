package clock

import (
	"strings"
	"testing"
)

// REQ: HW-8, CH-4
//
// HOST-1b-c2 (potency C2 / K15): fixed wording while codes run against an
// unverified clock; empty once verified.

func TestHOST1bC2UnverifiedCodesWording(t *testing.T) {
	if !strings.Contains(UnverifiedCodesText, "isn't set yet") || !strings.Contains(UnverifiedCodesText, "Wi-Fi page") {
		t.Fatalf("wording %q", UnverifiedCodesText)
	}
	if got := UnverifiedCodesPrefix(true); got != "" {
		t.Fatalf("verified prefix %q", got)
	}
	if got := UnverifiedCodesPrefix(false); !strings.HasPrefix(got, UnverifiedCodesText) || !strings.HasSuffix(got, " ") {
		t.Fatalf("unverified prefix %q", got)
	}
}
