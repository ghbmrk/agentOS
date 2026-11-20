package page

// REQ: NET-4

import "testing"

// spanWords names a zero span in seconds, never an empty string.
func TestSpanWordsZero(t *testing.T) {
	if got := spanWords(0); got != "0 seconds" {
		t.Errorf("spanWords(0) = %q", got)
	}
}
