package kernel_test

// REQ: OWN-6

import (
	"testing"

	"github.com/ghbmrk/agentos/broker/kernel"
)

// KindList is the one table of household words, which the ask and the
// owner side's after-erase notice both read (#5378): counts by word, other
// items last, a name's own label never counted, and nothing for no items.
func TestOWN6KindListSaysKindsInHouseholdWords(t *testing.T) {
	for _, c := range []struct {
		in   map[string]int
		want string
	}{
		{map[string]int{"message": 2, "vision-wrap-key": 1}, "1 face, 2 messages"},
		{map[string]int{"x-novel": 1, "a-novel": 1, "photo": 1, "retrieve-vectors": 2}, "1 photo, 2 search entries, 2 other items"},
		{map[string]int{"z-novel": 1, kernel.ClassLabel: 1}, "1 other item"},
		{map[string]int{kernel.ClassLabel: 1}, ""},
		{nil, ""},
	} {
		if got := kernel.KindList(c.in); got != c.want {
			t.Errorf("KindList(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
