package localui

import (
	"context"
	"fmt"
	"strings"
)

// ExemptUnitTemplate is the image's systemd template that adds an access
// point interface to the inbound exempt set (DEV-net-f, DEV-2, CH-7). Its
// script fails, and so fails bring-up, if the add does not take.
const ExemptUnitTemplate = "agentos-ap-exempt@.service"

// ExemptUnit names the instance of ExemptUnitTemplate for iface, escaped
// the way systemd escapes an instance name. It refuses any name ifaceRe
// refuses, so nothing else can reach the unit's argument.
func ExemptUnit(iface string) (string, error) {
	if !ifaceRe.MatchString(iface) {
		return "", fmt.Errorf("localui: %q is not an interface name", iface)
	}
	var b strings.Builder
	for i, r := range iface {
		switch {
		case r == '-', r == '.' && i == 0:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return strings.Replace(ExemptUnitTemplate, "@.", "@"+b.String()+".", 1), nil
}

// BringUp starts the access point only after its interface is in the
// inbound exempt set: start runs a systemd unit and returns when it has
// finished (systemctl start of a oneshot). If the add fails, the access
// point is not started and the error is returned, so the box never runs an
// access point the inbound drop would silently cut off, and never opens
// anything else to let it through. The P2-1 loader calls this in place of
// ap.Start.
func BringUp(ctx context.Context, ap AccessPoint, cfg APConfig, start func(context.Context, string) error) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	unit, err := ExemptUnit(cfg.Iface)
	if err != nil {
		return err
	}
	if err := start(ctx, unit); err != nil {
		return fmt.Errorf("localui: %s failed, access point not started: %w", unit, err)
	}
	return ap.Start(ctx, cfg)
}
