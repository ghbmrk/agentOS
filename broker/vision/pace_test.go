package vision

// REQ: RES-2

import (
	"testing"
	"time"
)

// TestFrameRateDropsUnderAdmission (RES-2): while admission has headroom
// a camera's frames go at its declared rate; once admission refuses
// headroom they fall to its floor rate, and detection goes on at it.
func TestFrameRateDropsUnderAdmission(t *testing.T) {
	headroom := true
	p := &Pace{
		Rates:    map[string]Rate{"front": {Every: 100 * time.Millisecond, Floor: time.Second}},
		Headroom: func() bool { return headroom },
	}
	// A 30 fps camera for 10 s with headroom, then 10 s without, then
	// 10 s with again.
	taken := func(from, to int) int {
		n := 0
		for i := from; i < to; i++ {
			if p.Take("front", t0.Add(time.Duration(i)*time.Second/30)) {
				n++
			}
		}
		return n
	}
	if n := taken(0, 300); n < 95 || n > 101 {
		t.Fatalf("%d frames in 10 s at 10 fps", n)
	}
	headroom = false
	if n := taken(300, 600); n < 9 || n > 11 {
		t.Fatalf("%d frames in 10 s under admission, want the floor's 10", n)
	}
	headroom = true
	if n := taken(600, 900); n < 95 || n > 101 {
		t.Fatalf("%d frames in 10 s once headroom is back", n)
	}
	// A camera with no declared rate, or a bad one, has the default;
	// a floor is never slower than maxFloorEvery.
	headroom = false
	p.Rates["slow"] = Rate{Every: time.Second, Floor: time.Hour}
	for _, cam := range []string{"side", "slow"} {
		n := 0
		for i := range 300 {
			if p.Take(cam, t0.Add(time.Duration(i)*time.Second/30)) {
				n++
			}
		}
		if want := int(10 * time.Second / DefaultFloorEvery); n < want-1 || n > want+1 {
			t.Fatalf("%s: %d frames in 10 s under admission, want %d", cam, n, want)
		}
	}
	// Frames stamped backwards are not taken (#3730 reviews).
	back := 0
	for i := range 100 {
		if p.Take("front", t0.Add(time.Hour-time.Duration(i)*time.Second)) {
			back++
		}
	}
	if back != 1 {
		t.Fatalf("%d of 100 frames stamped backwards taken, want the first only", back)
	}
	if p.Take("Front Door", t0) {
		t.Fatal("a camera id outside the alphabet")
	}
}
