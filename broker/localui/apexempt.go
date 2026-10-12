package localui

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ghbmrk/agentos/broker/netguard"
)

// ExemptUnitTemplate is the image's systemd template that adds an access
// point interface to the inbound exempt set (DEV-net-f, DEV-2, CH-7) and,
// on stop, takes it out again (DEV-net-g). Its script fails, and so fails
// bring-up, if the add does not take, or if agentos_ap does not already
// end its input chain in a drop for that interface.
const ExemptUnitTemplate = "agentos-ap-exempt@.service"

// ExemptUnit names the instance of ExemptUnitTemplate for iface, escaped
// the way systemd escapes an instance name. It refuses any name ifaceRe
// refuses, and "lo", so nothing else can reach the unit's argument.
func ExemptUnit(iface string) (string, error) {
	if !ifaceRe.MatchString(iface) || iface == "lo" {
		return "", fmt.Errorf("localui: %q is not an access point interface", iface)
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

// APHost is what BringUp and BringDown ask of the host. The P2-1 loader
// supplies the real one.
type APHost interface {
	// Nft runs script as one nftables transaction (nft -f -).
	Nft(ctx context.Context, script string) error
	// StartUnit runs a oneshot unit's ExecStart and returns when it has
	// finished, even if the unit was left active (systemctl restart).
	StartUnit(ctx context.Context, unit string) error
	// StopUnit stops a unit, running its ExecStop.
	StopUnit(ctx context.Context, unit string) error
}

// APTableUnload removes agentos_ap whether or not it is loaded.
const APTableUnload = "table inet agentos_ap {}\ndelete table inet agentos_ap\n"

// APTableLoad is the script that loads agentos_ap (NftRules) for cfg,
// replacing any earlier copy in the same transaction.
func APTableLoad(cfg APConfig) (string, error) {
	rules, err := NftRules(cfg)
	if err != nil {
		return "", err
	}
	return APTableUnload + rules, nil
}

// BringUp lets the access point's interface through the inbound drop only
// while agentos_ap holds it to the page, DHCP and DNS (DEV-2, CH-9,
// DEV-net-g): it loads agentos_ap, then starts the exempt unit, then the
// access point. If agentos_ap does not load, nothing is exempted. If the
// unit or the access point fails, the interface is taken out of the set
// again and the error returned, so the box never runs an access point the
// inbound drop would silently cut off, and never leaves an interface
// exempt with no access point behind it. The P2-1 loader calls this in
// place of ap.Start, and BringDown in place of ap.Stop.
func BringUp(ctx context.Context, ap AccessPoint, cfg APConfig, h APHost) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	unit, err := ExemptUnit(cfg.Iface)
	if err != nil {
		return err
	}
	load, err := APTableLoad(cfg)
	if err != nil {
		return err
	}
	if err := h.Nft(ctx, load); err != nil {
		return fmt.Errorf("localui: agentos_ap did not load, access point not started: %w", err)
	}
	if err := h.StartUnit(ctx, unit); err != nil {
		return errors.Join(fmt.Errorf("localui: %s failed, access point not started: %w", unit, err),
			unexempt(ctx, cfg.Iface, unit, h))
	}
	if err := ap.Start(ctx, cfg); err != nil {
		return errors.Join(fmt.Errorf("localui: access point did not start: %w", err),
			unexempt(ctx, cfg.Iface, unit, h))
	}
	return nil
}

// BringDown stops the access point on iface, takes iface out of the
// inbound exempt set, and then unloads agentos_ap (DEV-net-g b). The
// removal runs even if ap.Stop fails: with the access point gone, the
// interface (on a single radio, the one that next joins the home Wi-Fi)
// falls back to the inbound drop.
func BringDown(ctx context.Context, ap AccessPoint, iface string, h APHost) error {
	unit, err := ExemptUnit(iface)
	if err != nil {
		return err
	}
	var errs []error
	if err := ap.Stop(); err != nil {
		errs = append(errs, fmt.Errorf("localui: access point stop: %w", err))
	}
	return errors.Join(append(errs, unexempt(ctx, iface, unit, h))...)
}

// unexempt stops the unit (its ExecStop removes iface too, and the stop
// lets the next StartUnit run it again), then removes iface itself: systemd
// skips ExecStop for a unit whose start failed and may report a stop whose
// ExecStop failed as done. Only once the removal succeeds is agentos_ap
// unloaded; if it fails, agentos_ap stays, so the interface stays limited
// to the page, DHCP and DNS.
func unexempt(ctx context.Context, iface, unit string, h APHost) error {
	var errs []error
	if err := h.StopUnit(ctx, unit); err != nil {
		errs = append(errs, fmt.Errorf("localui: stop %s: %w", unit, err))
	}
	rm, err := netguard.InboundExemptRemove(iface)
	if err == nil {
		err = h.Nft(ctx, rm)
	}
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("localui: %s may still be exempt, agentos_ap kept: %w", iface, err))...)
	}
	if err := h.Nft(ctx, APTableUnload); err != nil {
		errs = append(errs, fmt.Errorf("localui: unload agentos_ap: %w", err))
	}
	return errors.Join(errs...)
}
