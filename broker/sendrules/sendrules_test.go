package sendrules

import (
	"testing"
	"time"
)

// REQ: ADP-12

// L3 SHOULD-4 on #164: calls stop at exactly CallsPerHour in an hour and
// CallsPerDay in a day, a refused call spends nothing, and texts still go
// once calls are capped.
func TestCallCapsAtTheirBoundaries(t *testing.T) {
	var b Budget
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	n := 0
	call := func(at time.Time) error {
		n++
		return b.TakeCall("+1555020"+string(rune('0'+n%10))+"000", at)
	}
	for i := 0; i < CallsPerHour; i++ {
		if err := call(now); err != nil {
			t.Fatalf("call %d: %v", i+1, err)
		}
	}
	if err := call(now); err != ErrLimited {
		t.Fatalf("call %d in an hour: %v", CallsPerHour+1, err)
	}
	if len(b.sent) != CallsPerHour {
		t.Fatalf("a refused call was spent: %d", len(b.sent))
	}
	if err := b.Take("+15550209999", now); err != nil {
		t.Fatalf("a text after the call cap: %v", err)
	}
	at := now
	for len(b.sent) < CallsPerDay+1 { // +1 for the text
		at = at.Add(time.Hour)
		for i := 0; i < CallsPerHour && len(b.sent) < CallsPerDay+1; i++ {
			if err := call(at); err != nil {
				t.Fatalf("call %d: %v", len(b.sent), err)
			}
		}
	}
	at = at.Add(time.Hour)
	if err := call(at); err != ErrLimited {
		t.Fatalf("call %d in a day: %v", CallsPerDay+1, err)
	}
	if err := call(now.Add(24 * time.Hour)); err != nil {
		t.Fatalf("the first hour's calls have aged out: %v", err)
	}
}
