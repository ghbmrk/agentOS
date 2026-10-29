package channel

import (
	"reflect"
	"testing"

	"github.com/ghbmrk/agentos/broker/enforcer/policy"
	"github.com/ghbmrk/agentos/broker/enforcer/wire"
)

// REQ: NET-2

// TestTableByClass (NET-2 Safety devices, #3748): the table keys on the
// device's class as well as its name, so a device whose Secure names a
// direction its class does not allow takes reads only, even if a policy
// reached the channel without the policy's own check. Catches a camera or
// an alarm named off, or primary heating named at all, being turned off
// by the core. Revert mutant: Allowed ignoring the class passes the
// camera's off.
func TestTableByClass(t *testing.T) {
	for _, c := range []struct {
		class, secure string
		v             wire.Verb
		ok            bool
	}{
		{policy.ClassHeater, SecureOff, wire.VerbOff, true},
		{policy.ClassValve, SecureShut, wire.VerbShut, true},
		{policy.ClassLock, SecureLock, wire.VerbLock, true},
		{policy.ClassCamera, SecureOff, wire.VerbOff, false},
		{policy.ClassMicrophone, SecureOff, wire.VerbOff, false},
		{policy.ClassAlarm, SecureOff, wire.VerbOff, false},
		{policy.ClassSiren, SecureOff, wire.VerbOff, false},
		{policy.ClassSensor, SecureOff, wire.VerbOff, false},
		{policy.ClassPrimaryHeating, SecureOff, wire.VerbOff, false},
		{policy.ClassFeedValve, SecureShut, wire.VerbShut, false},
		{policy.ClassLock, SecureOff, wire.VerbOff, false},
		{policy.ClassHeater, SecureShut, wire.VerbShut, false},
		{"", SecureOff, wire.VerbOff, false},
	} {
		dev := policy.Device{ID: "d", Network: policy.NetDevices, Class: c.class, Secure: c.secure}
		if got := Allowed(dev, c.v); got != c.ok {
			t.Errorf("a %q named %q, %s: %v, want %v", c.class, c.secure, verbWords[c.v], got, c.ok)
		}
	}
}

// TestTextsByClass (NET-2 Safety devices, #3748; ASSUMPTIONS ENF-d-2):
// only a heater turned off or a valve shut texts the owner; a plug's, a
// relay's or an oven's off does not. Catches a text that says a heater
// went off when a lamp's plug did, and a silent heater. Revert mutant:
// texting every safety-list off and shut sends the plug's.
func TestTextsByClass(t *testing.T) {
	r := newRig(t, nil)
	cl := r.dial()
	for i, m := range []wire.Command{
		cmd(1, "plug", wire.VerbOff),
		cmd(2, "relay", wire.VerbOff),
		cmd(3, "oven", wire.VerbOff),
		cmd(4, "heater", wire.VerbOff),
		cmd(5, "valve", wire.VerbShut),
	} {
		if c := cl.code(m); c != wire.OK {
			t.Fatalf("%d: %v", i, c)
		}
	}
	if want := []string{"heater off", "valve shut"}; !reflect.DeepEqual(r.alerts.off, want) {
		t.Errorf("texts %v, want %v", r.alerts.off, want)
	}
}
