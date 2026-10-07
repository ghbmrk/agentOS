package clock

import (
	"testing"
	"time"
)

// REQ: HW-8
//
// HOST-1b-o2 (Security O2 on #177): a plain sync may raise the floor by at
// most MaxPlainFloorRaise; NTS is uncapped. Wire into Guard.check next.

func TestHOST1bO2PlainFloorRaiseCapped(t *testing.T) {
	floor := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	far := floor.Add(48 * time.Hour)
	got := plainFloorRaise(floor, far, false)
	want := floor.Add(MaxPlainFloorRaise)
	if !got.Equal(want) {
		t.Fatalf("plain raise %v, want capped %v", got, want)
	}
	near := floor.Add(time.Hour)
	if got := plainFloorRaise(floor, near, false); !got.Equal(near) {
		t.Fatalf("plain within cap: %v", got)
	}
	if got := plainFloorRaise(floor, far, true); !got.Equal(far) {
		t.Fatalf("NTS uncapped: %v", got)
	}
	if got := plainFloorRaise(time.Time{}, far, false); !got.Equal(far) {
		t.Fatalf("empty floor: %v", got)
	}
	if got := plainFloorRaise(floor, floor.Add(-time.Hour), false); !got.Equal(floor.Add(-time.Hour)) {
		t.Fatalf("behind floor uses now: %v", got)
	}
}
