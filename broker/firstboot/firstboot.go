// Package firstboot holds AI and account connection on a new box until it
// runs a verified, current stable release (UPD-3).
//
// On first network contact the gate checks the update mirrors on the stable
// channel. A newer release goes to the applier (apply.ScheduleFirstBoot),
// which activates it A/B with fallback; the gate opens only when a fresh,
// verified check finds nothing newer than the installed release. Offline,
// the box runs the image it shipped with, says so, and checks when next
// online. Once open, the gate stays open: later updates are Loop 3's.
//
// The gate bypasses Loop 3 and the change pipeline on purpose: at first
// boot there is no owner to approve, no tasks to soak and no held-out
// cases to evaluate, and waiting for them would leave credentials waiting
// on an outdated image (ASSUMPTIONS.md F1).
package firstboot

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ghbmrk/agentos/broker/apply"
	"github.com/ghbmrk/agentos/broker/update"
)

// ErrUpdating is what Hold returns while setup steps that connect an AI
// or personal account must wait.
var ErrUpdating = errors.New("firstboot: the box is updating first")

// Scheduler is the applier's first-boot side (apply.Applier).
type Scheduler interface {
	ScheduleFirstBoot(*update.Verified) error
}

// Store persists the gate's state (change.MemStore, change.FileStore).
type Store interface {
	Load() ([]byte, error)
	Save([]byte) error
}

// Config configures New. Every field but Now is required.
type Config struct {
	Store   *update.Store
	Applier Scheduler
	State   Store
	// Mirrors are tried in order; the first verified answer counts.
	Mirrors func() []update.Source
	// Online reports an uplink. Offline, no mirror is contacted.
	Online func() bool
	Now    func() time.Time
}

// Kinds of the last step's outcome, for Status.
const (
	kindStarting   = ""
	kindOffline    = "offline"
	kindUnreached  = "unreached"
	kindUnverified = "unverified"
	kindInstalling = "installing"
	kindFellBack   = "fell_back"
)

type state struct {
	// Trusted is the latch: set once, never cleared.
	Trusted   bool      `json:"trusted"`
	TrustedAt time.Time `json:"trusted_at,omitzero"`
	TrustedOn int64     `json:"trusted_on,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Version   int64     `json:"version,omitempty"`
}

// Gate is the first-boot trust gate.
type Gate struct {
	cfg Config
	mu  sync.Mutex
	st  state
}

// New loads the gate's state.
func New(cfg Config) (*Gate, error) {
	if cfg.Store == nil || cfg.Applier == nil || cfg.State == nil || cfg.Mirrors == nil || cfg.Online == nil {
		return nil, errors.New("firstboot: incomplete config")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	g := &Gate{cfg: cfg}
	b, err := cfg.State.Load()
	if err != nil {
		return nil, err
	}
	if b != nil {
		if err := json.Unmarshal(b, &g.st); err != nil {
			return nil, fmt.Errorf("firstboot: state: %w", err)
		}
	}
	// What the last run saw before a restart is stale, except the latch.
	g.st.Kind, g.st.Version = kindStarting, 0
	return g, nil
}

// Step runs one check. It returns only errors the daemon should log; the
// gate stays held on any failure.
func (g *Gate) Step(context.Context) error {
	if g.Trusted() {
		return nil
	}
	if !g.cfg.Online() {
		return g.set(kindOffline, 0)
	}
	o := update.Options{Channel: update.ChannelStable, Now: g.cfg.Now}
	var (
		res     update.Result
		lastErr error
		ok      bool
	)
	for _, src := range g.cfg.Mirrors() {
		r, err := g.cfg.Store.Check(src, o)
		if err == nil {
			res, ok = r, true
			break
		}
		lastErr = err
	}
	if !ok {
		kind := kindUnreached
		for _, e := range []error{update.ErrExpired, update.ErrSignatures, update.ErrRollback, update.ErrWeakThreshold, update.ErrTrustMoved} {
			if errors.Is(lastErr, e) {
				kind = kindUnverified
			}
		}
		if err := g.set(kind, 0); err != nil {
			return err
		}
		if lastErr == nil {
			return errors.New("firstboot: no update mirror configured")
		}
		return lastErr
	}
	if res.Release != nil {
		m, err := res.Release.Manifest()
		if err != nil {
			return err
		}
		err = g.cfg.Applier.ScheduleFirstBoot(res.Release)
		switch {
		case errors.Is(err, apply.ErrFellBack):
			return g.set(kindFellBack, m.Version)
		case err == nil, errors.Is(err, apply.ErrApplying):
			return g.set(kindInstalling, m.Version)
		}
		_ = g.set(kindInstalling, m.Version)
		return err
	}
	// Nothing newer. Trust only a release whose freshness is confirmed: a
	// drive install the fresh metadata does not list stays held (UPD-8).
	in, err := g.cfg.Store.Installed()
	if err != nil {
		return err
	}
	if res.FreshnessFailed || in.UnconfirmedFreshness {
		return g.set(kindUnverified, 0)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.st = state{Trusted: true, TrustedAt: g.cfg.Now().UTC(), TrustedOn: in.Version}
	return g.saveLocked()
}

func (g *Gate) set(kind string, version int64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.st.Kind, g.st.Version = kind, version
	return g.saveLocked()
}

func (g *Gate) saveLocked() error {
	b, err := json.Marshal(g.st)
	if err != nil {
		return err
	}
	return g.cfg.State.Save(b)
}

// Trusted reports whether the box has run a verified current release.
func (g *Gate) Trusted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.st.Trusted
}

// Hold returns ErrUpdating, with the owner's reason, while AI and account
// connection must wait; nil once trusted. Every path that connects an AI
// provider or personal account calls it first.
func (g *Gate) Hold() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st.Trusted {
		return nil
	}
	if g.st.Kind == kindOffline {
		return fmt.Errorf("%w: the box is offline and has not updated yet; AI and accounts can be connected once it is online and updated", ErrUpdating)
	}
	return fmt.Errorf("%w: AI and accounts can be connected when the update finishes", ErrUpdating)
}

// Progress is the gate as the local page's phase: "offline", "updating"
// or "ready", and whether AI and account steps are open.
func (g *Gate) Progress() (phase string, updated bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case g.st.Trusted:
		return "ready", true
	case g.st.Kind == kindOffline:
		return "offline", false
	}
	return "updating", false
}

// Status is the STATUS line while the gate is held; "" once trusted.
func (g *Gate) Status() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.st.Trusted {
		return ""
	}
	const wait = " AI and accounts can be connected after that."
	switch g.st.Kind {
	case kindOffline:
		return "First start: the box is offline, so it runs the version it shipped with. It updates when it is next online." + wait
	case kindUnreached:
		return "First start: the box could not reach the update server. It will try again." + wait
	case kindUnverified:
		return "First start: the update server's answer could not be verified, so the box cannot tell it is current. It will try again." + wait
	case kindInstalling:
		return fmt.Sprintf("First start: updating to version %d. The box will restart once.", g.st.Version) + wait
	case kindFellBack:
		return fmt.Sprintf("First start: update %d did not start cleanly, so the box went back to the version it shipped with. AI and accounts stay closed until a newer update is out.", g.st.Version)
	}
	return "First start: checking for updates before AI and accounts can be connected."
}
