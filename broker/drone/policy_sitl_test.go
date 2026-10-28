//go:build sitl

package drone

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// REQ: NET-2
// TestLoadedPolicyReadsBack (brief acceptance test 3, P3): a signed policy
// loads and reads back equal, after the load and after the aircraft reboots;
// then each value changed out of band (by the test, signed with the key, so
// the aircraft takes it) makes the key-holder refuse to arm and log the
// mismatch, a parameter, the fence, the rally point and SCR_ENABLE alike,
// and across a reboot.
func TestLoadedPolicyReadsBack(t *testing.T) {
	r := newRig(t, true)
	ports := r.sim.Ports()
	if err := r.h.ArmCheck(); err != nil {
		t.Fatalf("a freshly loaded policy does not read back: %v", err)
	}
	if v, err := r.link.GetParam("FENCE_ALT_MAX"); err != nil || v != 60 {
		t.Fatalf("FENCE_ALT_MAX reads %v (%v), want the policy's 60", v, err)
	}

	// Every boot reads back: a power cycle keeps the policy, and a fresh
	// key-holder from its stored record finds it equal.
	r.link.Close()
	r.sim.Restart()
	r.attach(ports[0], r.sim.Dial(ports[0]))
	if err := r.h.ArmCheck(); err != nil {
		t.Fatalf("after a reboot: %v", err)
	}

	// An out-of-band writer that holds the key (the test) on another port,
	// on its own signing stream so it does not race the key-holder's.
	oob, err := dial(r.sim.Dial(ports[1]), r.key, time.Now, holderLinkID+1)
	if err != nil {
		t.Fatal(err)
	}
	defer oob.Close()
	if _, err := oob.WaitHeartbeat(time.Time{}, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	reload := func() {
		t.Helper()
		if err := r.h.Load(signPolicy(t, testPolicy(), r.owner)); err != nil {
			t.Fatalf("reloading the policy in force: %v", err)
		}
	}
	far := at(150, 150)
	cases := []struct {
		name   string
		change func() error
		names  string
	}{
		{"ceiling raised", func() error { _, err := oob.SetParam("FENCE_ALT_MAX", 80); return err }, "FENCE_ALT_MAX"},
		{"low-battery action off", func() error { _, err := oob.SetParam("BATT_FS_LOW_ACT", 0); return err }, "BATT_FS_LOW_ACT"},
		{"scripting on", func() error { _, err := oob.SetParam("SCR_ENABLE", 1); return err }, "SCR_ENABLE"},
		{"fence cleared", func() error { return oob.Upload(MissionFence, nil) }, "FENCE"},
		{"rally point moved", func() error {
			return oob.Upload(MissionRally, []Item{{Command: cmdRallyPoint, Lat: e7(far.Lat), Lon: e7(far.Lon), AltM: 56}})
		}, "RALLY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.change(); err != nil {
				t.Fatalf("the out-of-band change failed, so the check proves nothing: %v", err)
			}
			mark := len(r.logs.String())
			err := r.h.ArmCheck()
			if err == nil || !errors.Is(err, ErrMismatch) {
				t.Fatalf("arming allowed after %s: %v", c.name, err)
			}
			if !strings.Contains(strings.ToUpper(err.Error()), c.names) {
				t.Errorf("the refusal %q does not name %s", err, c.names)
			}
			if logged := r.logs.String()[mark:]; !strings.Contains(logged, "mismatch, arming refused") ||
				!strings.Contains(strings.ToUpper(logged), c.names) {
				t.Errorf("the mismatch is not logged: %q", logged)
			}
			reload()
			if err := r.h.ArmCheck(); err != nil {
				t.Fatalf("after reloading: %v", err)
			}
		})
	}

	// A change made while the key-holder is away is found at the next boot.
	if _, err := oob.SetParam("FS_GCS_TIMEOUT", 60); err != nil {
		t.Fatal(err)
	}
	oob.Close()
	r.link.Close()
	time.Sleep(3 * time.Second) // past ArduPilot's parameter save
	r.sim.Restart()
	r.attach(ports[0], r.sim.Dial(ports[0]))
	if err := r.h.ArmCheck(); err == nil || !strings.Contains(err.Error(), "FS_GCS_TIMEOUT") {
		t.Errorf("a changed parameter survived a reboot unnoticed: %v", err)
	}
}
