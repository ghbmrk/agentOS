//go:build sitl

package drone

import (
	"testing"
	"time"
)

// REQ: NET-2
// TestBreachLowBatteryLostLinkReturn (brief acceptance test 9, P3): the
// follow stand-in leads the aircraft past the boundary, the key-holder dies
// mid-flight, and the simulated battery falls below the policy's threshold;
// each time the aircraft returns by itself, lands at the dock and disarms.
// The returns are the flight controller's own: in the lost-link case nothing
// holds the key while it returns.
func TestBreachLowBatteryLostLinkReturn(t *testing.T) {
	r, obs := flightRig(t)
	ports := r.sim.Ports()
	parent := t

	// Each case starts where the last one landed; a failed case ends the test.
	if !t.Run("breach", func(t *testing.T) {
		if err := r.h.Fly(signFlight(t, newFlight(t, "north", "deer"), r.owner)); err != nil {
			t.Fatalf("starting the flight: %v\nlog:\n%s", err, r.logs)
		}
		airborne(t, obs)
		// A target that walks east out of the boundary (its east edge is 200 m out).
		path := []Point{testDock, at(0, 100), at(300, 100)}
		_, err := follow(t, r, obs, path, 4, time.Minute)
		if err == nil {
			t.Fatal("the aircraft followed the target out of the boundary for a minute without a breach")
		}
		if hb := heartbeat(t, obs); hb.CustomMode != ModeRTL {
			t.Fatalf("follow stopped (%v) but the mode is %d, not the fence's RTL", err, hb.CustomMode)
		}
		requireLandedAtDock(t, obs, "the breach return")
	}) {
		return
	}

	if !t.Run("lost link", func(t *testing.T) {
		waitReady(t, obs)
		if err := r.h.Fly(signFlight(t, newFlight(t, "north"), r.owner)); err != nil {
			t.Fatalf("starting the flight: %v\nlog:\n%s", err, r.logs)
		}
		airborne(t, obs)
		r.link.Close() // the key-holder is killed: its heartbeat stops with it
		waitFor(t, obs, "the lost-link return", time.Duration(testPolicy().LostLinkS+15)*time.Second,
			func(hb Heartbeat, _ where) bool { return hb.CustomMode == ModeRTL })
		requireLandedAtDock(t, obs, "the lost-link return")
		r.attach(ports[0], r.sim.Dial(ports[0]))
		parent.Cleanup(r.link.KeepAlive())
	}) {
		return
	}

	t.Run("low battery", func(t *testing.T) {
		waitReady(t, obs)
		if err := r.h.Fly(signFlight(t, newFlight(t, "north"), r.owner)); err != nil {
			t.Fatalf("starting the flight: %v\nlog:\n%s", err, r.logs)
		}
		airborne(t, obs)
		// The simulator's battery, below BATT_LOW_VOLT (10.5): physics, not policy.
		if _, err := obs.SetParam("SIM_BATT_VOLTAGE", 10.2); err != nil {
			t.Fatal(err)
		}
		waitFor(t, obs, "the low-battery return", time.Duration(battLowTimerS+20)*time.Second,
			func(hb Heartbeat, _ where) bool { return hb.CustomMode == ModeRTL })
		requireLandedAtDock(t, obs, "the low-battery return")
	})
}
