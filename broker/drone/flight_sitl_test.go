//go:build sitl

package drone

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// REQ: NET-6
// TestFlightOnlyFromOneSignedRecord (brief acceptance test 7, P4): an
// expired record, an unsigned one and one naming a route the policy lacks are
// refused with the aircraft left disarmed; a valid record flies its named
// route and returns to the dock; the same record again is refused, and the
// aircraft stays disarmed.
func TestFlightOnlyFromOneSignedRecord(t *testing.T) {
	r, obs := flightRig(t)
	refusals := []struct {
		name string
		env  func() []byte
	}{
		{"expired", func() []byte {
			f := newFlight(t, "north")
			f.NotAfter = time.Now().Add(-time.Minute).Unix()
			return signFlight(t, f, r.owner)
		}},
		{"unsigned", func() []byte {
			return bytes.Replace(signFlight(t, newFlight(t, "north"), r.owner), []byte(`"sig":"`), []byte(`"sig":"x`), 1)
		}},
		{"signed by another key", func() []byte { return signFlight(t, newFlight(t, "north"), testOwner(t, 2)) }},
		{"route the policy lacks", func() []byte { return signFlight(t, newFlight(t, "west"), r.owner) }},
	}
	for _, c := range refusals {
		mark := len(r.logs.String())
		if err := r.h.Fly(c.env()); err == nil {
			t.Fatalf("%s: the record flew", c.name)
		}
		if !r.logged(mark, "flight refused") {
			t.Errorf("%s: the refusal was not logged", c.name)
		}
		time.Sleep(2 * time.Second)
		requireDisarmed(t, obs, c.name)
	}

	p := testPolicy()
	route, _ := p.Route("north")
	f := newFlight(t, "north")
	env := signFlight(t, f, r.owner)
	if err := r.h.Fly(env); err != nil {
		t.Fatalf("a valid record: %v\nlog:\n%s", err, r.logs)
	}
	airborne(t, obs)
	for i, w := range route.Waypoints {
		target := Point{Lat: w.Lat, Lon: w.Lon}
		waitFor(t, obs, "reaching waypoint", 2*time.Minute, func(hb Heartbeat, at where) bool {
			if !hb.Armed {
				t.Fatalf("the aircraft disarmed before waypoint %d", i)
			}
			return metres(target, at.At) < 5
		})
	}
	requireLandedAtDock(t, obs, "the flight's return")

	mark := len(r.logs.String())
	if err := r.h.Fly(env); err == nil || !strings.Contains(err.Error(), "already flown") {
		t.Fatalf("the same record again: %v", err)
	}
	if !r.logged(mark, "flight refused") {
		t.Error("the replayed record's refusal was not logged")
	}
	time.Sleep(3 * time.Second)
	requireDisarmed(t, obs, "the replayed record")
}
