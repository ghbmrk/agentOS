package localui

import (
	"context"
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
//     on, before any bring-up or station join (a): a loader that died with
//     the access point up left it exempt and agentos_ap loaded. It first
//     brings down the interface agentos_ap holds, if Start does not name
//     it, so a dead loader's radio is not left exempt with no table
//     (DEV-net-i).
//   - Station refuses an interface whose BringDown last failed, or that runs
//     the access point (b): on a single radio it would join the home Wi-Fi
//     still exempt.
//   - Up refuses while another interface is up, its BringDown last failed,
//     or agentos_ap holds it (c): BringUp(wl1) replaces agentos_ap, so wl0
//     would stay exempt with no table and every box port open to its
//     network.
//   - BringUp and BringDown run their teardown on context.WithoutCancel (d).
//
// Its methods are serialised; Station holds the lock for the join.
type APLoader struct {
	AP   AccessPoint
	Host APHost

	mu     sync.Mutex
	named  map[string]bool  // interfaces a Start brought down, or tried to
	up     string           // the interface running the access point
	failed map[string]error // interfaces whose BringDown last failed
}

// Start runs BringDown for each interface, idempotent whether or not it was
// up. Before them it runs BringDown for the interface agentos_ap holds, if
// any, without naming it: a loader that died with the access point up on a
// radio this list leaves out left that radio exempt (DEV-net-i). If that
// BringDown fails, the radio blocks Up on any other interface until a Down
// succeeds for it. Up and Station refuse an interface no Start named, since
// its exemption state is unknown. BringDown must succeed for an interface
// before Station takes it; one whose BringDown fails stays refused until a
// Down succeeds for it.
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
// Start named, while an access point is up, while any other interface's BringDown
// last failed, and while agentos_ap holds another interface or cannot be
// read. If BringUp fails, the loader runs BringDown again, and an
// interface it cannot bring down stays refused for Station and blocks Up
// on any other.
func (l *APLoader) Up(ctx context.Context, cfg APConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.named[cfg.Iface] {
		return notNamed(cfg.Iface)
	}
	if l.up != "" {
		return fmt.Errorf("localui: the access point is already up on %s", l.up)
	}
	for iface := range l.failed {
		if iface != cfg.Iface {
			return fmt.Errorf("localui: %s may still be exempt, so %s cannot run the access point", iface, cfg.Iface)
		}
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
	l.up = ""
	return errors.Join(errs...)
}

// Station runs join, which puts iface into station mode, only after a
// Start named iface, while iface is not running the access point and its last BringDown
// succeeded.
func (l *APLoader) Station(ctx context.Context, iface string, join func(context.Context) error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case !l.named[iface]:
		return notNamed(iface)
	case iface == l.up:
		return fmt.Errorf("localui: %s runs the access point", iface)
	case l.failed[iface] != nil:
		return fmt.Errorf("localui: %s may still be exempt, so it does not join a network: %w", iface, l.failed[iface])
	}
	return join(ctx)
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
		l.up = ""
	}
	if err != nil {
		l.failed[iface] = err
		return err
	}
	delete(l.failed, iface)
	return nil
}
