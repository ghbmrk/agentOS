//go:build sitl

package drone

import (
	"testing"
	"time"
)

// REQ: NET-2
// TestGPSCameraDisagreementReturns (brief acceptance test 11, decision 10):
// with the aircraft holding still, one camera fix far off is an outlier and
// does not return it; then a GPS glitch injected in the simulator moves the
// aircraft's reported position away from steady camera fixes, and after
// cameraFixesToRTL fixes beyond the policy's bound the key-holder returns it.
func TestGPSCameraDisagreementReturns(t *testing.T) {
	r, obs := flightRig(t)
	if err := r.h.Fly(signFlight(t, newFlight(t, "north", "deer"), r.owner)); err != nil {
		t.Fatalf("starting the flight: %v\nlog:\n%s", err, r.logs)
	}
	airborne(t, obs)
	hold := at(0, 120)
	if _, err := follow(t, r, obs, []Point{testDock, hold}, 4, 20*time.Second); err != nil {
		t.Fatalf("moving to the hold point: %v", err)
	}
	camera := position(t, obs).At // where the cameras see it, from here on

	for i, fix := range []Point{camera, at(0, 170), camera, camera} {
		sent, err := r.h.CameraFix(fix)
		if err != nil || sent {
			t.Fatalf("fix %d (a single outlier among agreeing fixes) returned the aircraft: %v, %v", i, sent, err)
		}
		time.Sleep(time.Second)
	}
	if hb := heartbeat(t, obs); hb.CustomMode != ModeGuided {
		t.Fatalf("after one outlier the mode is %d, want GUIDED (holding)", hb.CustomMode)
	}

	// The glitch: the simulated GPS reads 0.0005 degrees (about 55 m) south.
	// The EKF takes it after its glitch handling, so the reported position
	// moves while the cameras still see the aircraft where it is.
	if _, err := r.link.SetParam("SIM_GPS1_GLTCH_X", -0.0005); err != nil {
		t.Fatal(err)
	}
	mark := len(r.logs.String())
	fixes, returned := 0, false
	for deadline := time.Now().Add(90 * time.Second); time.Now().Before(deadline) && !returned; {
		sent, err := r.h.CameraFix(camera)
		if err != nil && !sent {
			t.Fatalf("camera fix: %v", err)
		}
		if err != nil {
			// The EKF's own failsafe may have landed it first, and a landing
			// aircraft can refuse RTL: either way it is coming down.
			t.Logf("the return was sent and the aircraft answered: %v", err)
		}
		fixes++
		returned = sent
		time.Sleep(time.Second)
	}
	if !returned {
		t.Fatalf("%d steady camera fixes against a glitched GPS did not return the aircraft\nlog:\n%s", fixes, r.logs)
	}
	if !r.logged(mark, "camera fixes disagree") {
		t.Error("the return was not logged with its reason")
	}
	if hb := heartbeat(t, obs); hb.CustomMode != ModeRTL && hb.CustomMode != ModeLand {
		t.Errorf("after the check sent a return the mode is %d", hb.CustomMode)
	}
	if _, err := r.link.SetParam("SIM_GPS1_GLTCH_X", 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, obs, "landed and disarmed", 5*time.Minute, func(hb Heartbeat, _ where) bool { return !hb.Armed })
}
