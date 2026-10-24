package key

// REQ: KEY-8

import (
	"math"
	"testing"
)

// A hold's due time saturates: past int64 it is never due, so a holder who
// narrows a key to a hold near MaxInt64 waits forever rather than wrapping
// to a time already past (KEY-8, #2952).
func TestHoldDueNeverWraps(t *testing.T) {
	o, h, k := root(t)
	h2 := gen(3)
	d, _ := Derive(k, h.priv, h2.pub, LimitHold(10, math.MaxInt64))
	l := verified(t, d, o, h2).Limits
	for _, tc := range []struct {
		at    int64
		novel bool
		want  int64
	}{
		{5, false, 15},
		{-5, true, math.MaxInt64 - 5},
		{0, true, math.MaxInt64},
		{1, true, math.MaxInt64},
		{math.MaxInt64 - 3, false, math.MaxInt64},
	} {
		if got := l.Due(tc.at, tc.novel); got != tc.want {
			t.Errorf("Due(%d, %v) = %d, want %d", tc.at, tc.novel, got, tc.want)
		}
	}
}
