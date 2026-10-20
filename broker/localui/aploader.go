package localui

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
)

// APLoader is how the P2-1 loader drives BringUp and BringDown so that no
// interface is left exempt from the inbound drop without agentos_ap holding
// it to the page, DHCP and DNS (DEV-2, A14, DEV-net-h):
//
//   - Start brings down each interface the loader may run the access point
//     on, before any bring-up (a): a loader that died with
//     the access point up left it exempt and agentos_ap loaded. It first
//     brings down the interface agentos_ap holds, if Start does not name
//     it, so a dead loader's radio is not left exempt with no table
//     (DEV-net-i).
//   - Start refuses StationIface, the station EnsureStation creates beside
//     the access point (#936): it is never the access point's, so the
//     loader never brings it down. NetworkManager joins the home Wi-Fi on
//     it, never on an interface the access point may run on (b; netjoin
//     ASSUMPTIONS N13).
//   - Up refuses while another interface is up, any BringDown last failed,
//     or agentos_ap holds it (c): BringUp(wl1) replaces agentos_ap, so wl0
//     would stay exempt with no table and every box port open to its
//     network.
//   - BringUp and BringDown run their teardown on context.WithoutCancel (d).
//   - Rekey restarts a running access point with a rotated Wi-Fi password
//     (REC-4), under the same rules.
//
// Its methods are serialised.
type APLoader struct {
	AP   AccessPoint
	Host APHost
	// Radio, if set, is how EnsureStation creates StationIface.
	Radio Radio

	mu     sync.Mutex
	named  map[string]bool  // interfaces a Start brought down, or tried to
	up     string           // the interface running the access point
	cfg    APConfig         // what the access point on up runs with
	failed map[string]error // interfaces whose BringDown last failed

	station  bool   // the last EnsureStation left StationIface there
	channels uint32 // its combination's channels; 0 with no station
}

// Start runs BringDown for each interface, idempotent whether or not it was
// up. Before them it runs BringDown for the interface agentos_ap holds, if
// any, without naming it: a loader that died with the access point up on a
// radio this list leaves out left that radio exempt (DEV-net-i). If that
// BringDown fails, the radio blocks Up on any other interface until a Down
// succeeds for it. Up refuses an interface no Start named, since its
// exemption state is unknown. Start refuses StationIface without touching
// it.
func (l *APLoader) Start(ctx context.Context, ifaces ...string) error {
	if len(ifaces) == 0 {
		return errors.New("localui: the loader's Start names no access point interface")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed == nil {
		l.failed = map[string]error{}
		l.named = map[string]bool{}
	}
	var errs []error
	held, err := l.Host.APTableIface(context.WithoutCancel(ctx))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("localui: cannot read which interface agentos_ap holds: %w", err))
	case held != "" && !slices.Contains(ifaces, held):
		errs = append(errs, l.bringDown(ctx, held))
	}
	for _, iface := range ifaces {
		if iface == StationIface {
			errs = append(errs, fmt.Errorf("localui: %s is the station, never the access point's", iface))
			continue
		}
		if _, err := ExemptUnit(iface); err != nil {
			errs = append(errs, err)
			continue
		}
		l.named[iface] = true
		errs = append(errs, l.bringDown(ctx, iface))
	}
	return errors.Join(errs...)
}

// Up brings the access point up on cfg.Iface. It refuses an interface no
// Start named, while an access point is up, while any interface's BringDown
// last failed (its own included: hostapd may still run there), and while agentos_ap holds another interface or cannot be
// read. If BringUp fails, the loader runs BringDown again, and an
// interface it cannot bring down blocks Up on any other.
func (l *APLoader) Up(ctx context.Context, cfg APConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.upLocked(ctx, cfg)
}

// Rekey restarts the running access point with password, after a Wi-Fi
// rotation commit (REC-4), so the phone joins with the new card. The SSID
// and interface stay; the access point comes back WPA3-SAE only, with MFP
// required (CH-7). With no access point up it does nothing: the next Up
// takes the stored password from its caller. But while any interface's
// BringDown last failed, Rekey returns an error instead: hostapd may still
// run there with the old password, which a rotation presumes lost, so a
// retry is never told it is gone. A Down that succeeds clears it. A
// password Validate refuses,
// or the one already in use, leaves the access point untouched. The
// restart drops every client, so the caller applies it only after the
// commit's reply has reached the phone.
//
// If the bring-down fails, the access point is not brought up again
// (DEV-net-h c). If the bring-up fails, it stays down: the old password,
// which a rotation presumes lost, is never brought back.
func (l *APLoader) Rekey(ctx context.Context, password string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.stuck(); err != nil {
		return err
	}
	if l.up == "" {
		return nil
	}
	cfg := l.cfg
	cfg.Password = password
	cfg.WPA2 = false
	if err := cfg.Validate(); err != nil {
		return err
	}
	if !l.cfg.WPA2 && subtle.ConstantTimeCompare([]byte(password), []byte(l.cfg.Password)) == 1 {
		return nil
	}
	if err := l.bringDown(ctx, l.up); err != nil {
		return fmt.Errorf("localui: the access point did not come down, so it does not restart with the new password: %w", err)
	}
	return l.upLocked(ctx, cfg)
}

// upLocked is Up with l.mu held.
func (l *APLoader) upLocked(ctx context.Context, cfg APConfig) error {
	if !l.named[cfg.Iface] {
		return notNamed(cfg.Iface)
	}
	if l.up != "" {
		return fmt.Errorf("localui: the access point is already up on %s", l.up)
	}
	if err := l.failed[cfg.Iface]; err != nil {
		return fmt.Errorf("localui: %s did not come down, so an access point with the old password may still run there: %w", cfg.Iface, err)
	}
	for iface := range l.failed {
		return fmt.Errorf("localui: %s may still be exempt, so %s cannot run the access point", iface, cfg.Iface)
	}
	// BringUp replaces agentos_ap, so a table held for another interface
	// (one a Start could not bring down or read) would leave that
	// interface exempt with none (DEV-net-i).
	held, err := l.Host.APTableIface(context.WithoutCancel(ctx))
	if err != nil {
		return fmt.Errorf("localui: cannot read which interface agentos_ap holds, so %s cannot run the access point: %w", cfg.Iface, err)
	}
	if held != "" && held != cfg.Iface {
		return fmt.Errorf("localui: agentos_ap holds %s, which may still be exempt, so %s cannot run the access point", held, cfg.Iface)
	}
	if err := BringUp(ctx, l.AP, cfg, l.Host); err != nil {
		return errors.Join(err, l.bringDown(ctx, cfg.Iface))
	}
	l.up = cfg.Iface
	l.cfg = cfg
	return nil
}

// Down brings down the access point's interface and retries every
// interface whose BringDown last failed.
func (l *APLoader) Down(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	todo := map[string]bool{}
	if l.up != "" {
		todo[l.up] = true
	}
	for iface := range l.failed {
		todo[iface] = true
	}
	names := make([]string, 0, len(todo))
	for iface := range todo {
		names = append(names, iface)
	}
	sort.Strings(names)
	var errs []error
	for _, iface := range names {
		errs = append(errs, l.bringDown(ctx, iface))
	}
	l.up, l.cfg = "", APConfig{}
	return errors.Join(errs...)
}

// stuck reports the interfaces whose BringDown last failed, in order, as
// the reason a Rekey with no access point up cannot say the old password
// is off the air. The caller holds l.mu.
func (l *APLoader) stuck() error {
	if len(l.failed) == 0 {
		return nil
	}
	names := make([]string, 0, len(l.failed))
	for iface := range l.failed {
		names = append(names, iface)
	}
	sort.Strings(names)
	errs := make([]error, 0, len(names))
	for _, iface := range names {
		errs = append(errs, fmt.Errorf("localui: %s did not come down, so an access point with the old password may still run there: %w", iface, l.failed[iface]))
	}
	return errors.Join(errs...)
}

func notNamed(iface string) error {
	return fmt.Errorf("localui: the loader's Start has not brought %s down, so it may still be exempt", iface)
}

// bringDown runs BringDown for iface and records whether it failed. A
// name ExemptUnit refuses reaches nothing, so it is only reported. The
// caller holds l.mu.
func (l *APLoader) bringDown(ctx context.Context, iface string) error {
	if _, err := ExemptUnit(iface); err != nil {
		return err
	}
	err := BringDown(ctx, l.AP, iface, l.Host)
	if l.up == iface {
		l.up, l.cfg = "", APConfig{}
	}
	if err != nil {
		l.failed[iface] = err
		return err
	}
	delete(l.failed, iface)
	return nil
}
