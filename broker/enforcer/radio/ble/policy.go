package ble

import (
	"fmt"
	"regexp"
	"strings"
)

var reUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// driverCalls is every bus driver method the stack calls (Dial, stack.start).
var driverCalls = []string{"Hello", "GetNameOwner", "AddMatch"}

// BusPolicy is the system bus policy for the stack's user, by name
// (dbus-daemon refuses a numeric uid as an unknown user name), for the image to install under /etc/dbus-1/system.d/. It
// denies every message the user sends, then allows exactly driverCalls to
// the bus driver and busCalls to BlueZ; and it denies every message the
// user receives except from the bus driver and BlueZ. A user policy is
// applied after the default and group policies, so it holds however the
// distribution's BlueZ policy reads, and it holds against the stack's
// process itself: an exploit with its own D-Bus encoder still cannot start
// discovery, pair, power the adapter or reach another service on the bus,
// and no other bus peer can flood it.
func BusPolicy(user string) (string, error) {
	if !reUser.MatchString(user) {
		return "", fmt.Errorf("ble: bus policy user %q", user)
	}
	var b strings.Builder
	b.WriteString(`<!-- agentOS enforcer BLE stack (broker/enforcer/radio/ble.BusPolicy); generated, do not edit. -->
<busconfig>
  <policy user="` + user + `">
    <deny own="*"/>
    <deny send_destination="*"/>
    <deny receive_sender="*"/>
`)
	for _, m := range driverCalls {
		fmt.Fprintf(&b, "    <allow send_destination=%q send_type=\"method_call\" send_interface=%q send_member=%q/>\n", busDriver, busDriver, m)
	}
	for _, c := range busCalls {
		fmt.Fprintf(&b, "    <allow send_destination=%q send_type=\"method_call\" send_interface=%q send_member=%q/>\n", bluez, c.Iface, c.Member)
	}
	fmt.Fprintf(&b, "    <allow receive_sender=%q/>\n    <allow receive_sender=%q/>\n", busDriver, bluez)
	b.WriteString("  </policy>\n</busconfig>\n")
	return b.String(), nil
}
