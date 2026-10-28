//go:build sitl

package drone

import (
	"testing"
)

// REQ: NET-2
// TestFollowStaysInsideBoundary (brief acceptance test 10, decision 9): a
// target moving inside the boundary, off the route, is followed (the
// aircraft reaches it), and the aircraft's track never leaves the boundary
// polygon by more than the fence margin. A record that names no animals does
// not follow at all.
func TestFollowStaysInsideBoundary(t *testing.T) {
	r, obs := flightRig(t)
	p := testPolicy()
	pr := newProjection(testDock)
	boundary, err := polygon(pr, p.Boundary)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.h.Fly(signFlight(t, newFlight(t, "north"), r.owner)); err != nil {
		t.Fatalf("starting a flight that follows nothing: %v\nlog:\n%s", err, r.logs)
	}
	airborne(t, obs)
	if err := r.h.Follow(at(0, 100)); err == nil {
		t.Fatal("a flight whose record names no animals followed a target")
	}
	if err := r.h.Return("test: end of the no-follow flight"); err != nil {
		t.Fatal(err)
	}
	requireLandedAtDock(t, obs, "the no-follow flight")

	waitReady(t, obs)
	if err := r.h.Fly(signFlight(t, newFlight(t, "north", "deer"), r.owner)); err != nil {
		t.Fatalf("starting the follow flight: %v\nlog:\n%s", err, r.logs)
	}
	airborne(t, obs)
	// Off the route (north is y=150): north from the dock, east along y=100,
	// south toward the notch and back west, all inside the boundary.
	path := []Point{testDock, at(0, 100), at(150, 100), at(150, 60), at(0, 60)}
	track, err := follow(t, r, obs, path, 3, 0)
	if err != nil {
		t.Fatalf("following a target inside the boundary: %v\nlog:\n%s", err, r.logs)
	}
	reached := false
	for _, w := range track {
		v := pr.local(w.At)
		if !inside(v, boundary) && edgeDist(v, boundary) > p.FenceMarginM {
			t.Errorf("the track left the boundary by %.1f m at %+v", edgeDist(v, boundary), w)
		}
		if metres(at(150, 100), w.At) < 10 {
			reached = true
		}
	}
	if !reached {
		t.Errorf("the aircraft did not follow the target off the route (%d track points)", len(track))
	}
	if err := r.h.Return("test: end of the follow flight"); err != nil {
		t.Fatal(err)
	}
	requireLandedAtDock(t, obs, "the follow flight")
}
