package ble

import (
	"fmt"
	"regexp"
	"strings"
)

var reUser = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// BusPolicy is the system bus policy for the stack's user, by name
// (dbus-daemon refuses a numeric uid as an unknown user name), for the image to install under /etc/dbus-1/system.d/: it denies
// every message to BlueZ, then allows exactly busCalls. A user policy is
// applied after the default and group policies, so it holds however the
// distribution's BlueZ policy reads, and it holds against the stack's
// process itself: an exploit with its own D-Bus encoder still cannot start
// discovery, pair, or power the adapter.
func BusPolicy(user string) (string, error) {
	if !reUser.MatchString(user) {
		return "", fmt.Errorf("ble: bus policy user %q", user)
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<!-- agentOS enforcer BLE stack (broker/enforcer/radio/ble.BusPolicy); generated, do not edit. -->
<busconfig>
  <policy user="` + user + `">
    <deny own="*"/>
    <deny send_destination="` + bluez + `"/>
`)
	for _, c := range busCalls {
		fmt.Fprintf(&b, "    <allow send_destination=%q send_type=\"method_call\" send_interface=%q send_member=%q/>\n", bluez, c.Iface, c.Member)
	}
	b.WriteString("  </policy>\n</busconfig>\n")
	return b.String(), nil
}
