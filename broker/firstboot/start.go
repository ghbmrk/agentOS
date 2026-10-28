package firstboot

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/ghbmrk/agentos/broker/card"
	"github.com/ghbmrk/agentos/broker/claim"
)

// Route is the first-boot path a start takes (HW-10).
type Route string

const (
	// RouteDownload is a box flashed from the download: no claim code;
	// the flasher's QR pairs the phone and the card step starts at once.
	RouteDownload Route = "download"
	// RouteClaim is a preloaded box: the claim screen first, the card
	// step only after the claim.
	RouteClaim Route = "claim"
	// RouteReinstall is a box that held a claim code and has lost its
	// claim state: it says "already claimed, reinstall me" and nothing
	// else (R4).
	RouteReinstall Route = "reinstall"
)

// ErrReinstall is what a box on RouteReinstall answers to every setup
// step.
var ErrReinstall = errors.New("firstboot: I am already claimed; reinstall me to set me up again")

// BoxConfig configures Begin. Every field is required but Download and
// Card's optional ones.
type BoxConfig struct {
	// Claim opens the claim state; its Store is the seller flow's.
	Claim claim.Config
	// Latch is the card step's latch.
	Latch Store
	// Reset removes a vault made from a card nobody confirmed
	// (ResetUnlatched).
	Reset func() error
	// Card is the card step's display config.
	Card card.DisplayConfig
	// Download is set only on the download's image (agentos-localui
	// -download-box), the one image that ships no claim state. Unset, a
	// missing claim state routes to reinstall, so a preloaded box whose
	// claim state is lost or hidden never serves setup without the claim
	// gate (#1270).
	Download bool
}

// ClaimScreen is what the claim screen needs (localui.BoxClaim).
type ClaimScreen interface {
	Status() claim.Status
	Claim(code string) (string, error)
	Claimant(tok string) bool
}

// CardHold is the Owner Card step as the page and the finish path see it
// (localui.OwnerCard).
type CardHold interface {
	Display() *card.Display
	Hold() error
}

// FirstBoot is one start's first-boot path.
type FirstBoot struct {
	Route Route
	// Claim is the claim screen; nil on RouteDownload.
	Claim ClaimScreen
	// Card is the card step.
	Card CardHold

	reset func() error
}

// Begin picks the start's route and builds its steps. It reads the latch
// first: a latch it cannot read stops the start and resets nothing. A box
// whose claim state opens is marked preloaded on the latch before
// anything else, so losing the claim state later routes to reinstall,
// never to the download path's pairing (ASSUMPTIONS.md F15). A box
// without a claim state routes to reinstall unless the config says it is
// the download's (BoxConfig.Download). An owned box
// never reaches Begin (agentosd checks its record first).
func Begin(cfg BoxConfig) (*FirstBoot, error) {
	fb, err := begin(cfg)
	if err != nil {
		return nil, err
	}
	fb.reset = cfg.Reset
	return fb, nil
}

// Again reruns the route's card step with BoxConfig.Reset when the vault
// holds no card although the step is confirmed (#1330, CardStep.Again).
// The reinstall route has no card step and answers ErrReinstall.
func (f *FirstBoot) Again() error {
	a, ok := f.Card.(interface{ Again(func() error) error })
	if !ok {
		return f.Card.Hold()
	}
	return a.Again(f.reset)
}

func begin(cfg BoxConfig) (*FirstBoot, error) {
	if cfg.Latch == nil || cfg.Reset == nil || cfg.Claim.Store == nil {
		return nil, errors.New("firstboot: incomplete first-boot config")
	}
	b, err := cfg.Latch.Load()
	if err != nil {
		return nil, err
	}
	var cs cardState
	if b != nil {
		if err := json.Unmarshal(b, &cs); err != nil {
			return nil, fmt.Errorf("firstboot: card state: %w", err)
		}
	}
	cl, err := claim.Open(cfg.Claim)
	switch {
	case errors.Is(err, claim.ErrNoCode) && (cs.Preloaded || !cfg.Download):
		return &FirstBoot{Route: RouteReinstall, Claim: reinstall{}, Card: reinstall{}}, nil
	case errors.Is(err, claim.ErrNoCode):
		if err := ResetUnlatched(cfg.Latch, cfg.Reset); err != nil {
			return nil, err
		}
		s, err := NewCardStep(cfg.Latch, cfg.Card)
		if err != nil {
			return nil, err
		}
		return &FirstBoot{Route: RouteDownload, Card: s}, nil
	case err != nil:
		return nil, err
	}
	if !cs.Preloaded {
		cs.Preloaded = true
		m, err := json.Marshal(cs)
		if err != nil {
			return nil, err
		}
		if err := cfg.Latch.Save(m); err != nil {
			return nil, fmt.Errorf("firstboot: marking a preloaded box: %w", err)
		}
	}
	if err := ResetUnlatched(cfg.Latch, cfg.Reset); err != nil {
		return nil, err
	}
	c, err := NewClaimedCard(cl, cfg.Latch, cfg.Card)
	if err != nil {
		return nil, err
	}
	return &FirstBoot{Route: RouteClaim, Claim: c, Card: c}, nil
}

// reinstall is RouteReinstall's claim screen and card step: claimed to
// everyone, a claimant to no one, no card.
type reinstall struct{}

func (reinstall) Status() claim.Status { return claim.Status{Claimed: true, Reinstall: true} }
func (reinstall) Claim(string) (string, error) {
	return "", claim.ErrAlreadyClaimed
}
func (reinstall) Claimant(string) bool   { return false }
func (reinstall) Display() *card.Display { return nil }
func (reinstall) Hold() error            { return ErrReinstall }
