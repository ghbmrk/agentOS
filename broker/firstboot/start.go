package firstboot

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

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

// BoxConfig configures Begin. Every field is required but SetupNet and
// Card's optional ones.
type BoxConfig struct {
	// Claim opens the claim state; its Store is the seller flow's.
	Claim claim.Config
	// Latch is the card step's latch.
	Latch Store
	// SetupNet holds the seller's setup network (claim.SetupNetPath): the
	// Wi-Fi the phone joins before the card exists. Nil on an image that
	// keeps none, which serves no network before the card.
	SetupNet Store
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

	setup Store
	reset func() error
	mu    sync.Mutex
	net   *claim.SetupNet // nil once burned, or when the box has none
}

// Network is the Wi-Fi the access point serves before the Owner Card
// exists: the sticker's setup network until the card is confirmed (§8.1
// step 4), nil after it and on a box that has none. Once the card step no
// longer holds it burns the setup file, so the seller's copy of the
// password opens nothing on a set-up box (CTRL-claim-ap). The loader
// calls it each time it brings the access point up; nil means the card's
// network. A burn that fails returns the error and still no network.
func (f *FirstBoot) Network() (*claim.SetupNet, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.net == nil {
		return nil, nil
	}
	if f.Card.Hold() != nil {
		n := *f.net
		return &n, nil
	}
	if err := f.setup.Save(nil); err != nil {
		return nil, fmt.Errorf("firstboot: burning the setup network: %w", err)
	}
	f.net = nil
	return nil, nil
}

// loadSetupNet reads the setup network, nil when st is nil or empty (a
// burned file is empty). A file that does not parse is an error.
func loadSetupNet(st Store) (*claim.SetupNet, error) {
	if st == nil {
		return nil, nil
	}
	b, err := st.Load()
	if err != nil {
		return nil, fmt.Errorf("firstboot: setup network: %w", err)
	}
	if len(b) == 0 {
		return nil, nil
	}
	n, err := claim.ParseSetupNet(b)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// SetupNetwork is what the access point's loader (agentos-ap) serves
// before the Owner Card exists, read from the card step's latch and the
// setup file at the loader's start: nil once the latch says the card is
// confirmed or the box is owned (agentosd's owner state exists), when it
// burns a setup file that is not yet empty (CTRL-claim-ap), and nil on a
// box with none. owned covers a latch the page could rewrite: once setup
// has finished, no latch keeps the seller's network. A latch or setup
// file that does not parse, or a burn that fails, is an error and no
// network.
func SetupNetwork(latch []byte, owned bool, setup Store) (*claim.SetupNet, error) {
	var cs cardState
	if len(latch) != 0 && !owned {
		if err := json.Unmarshal(latch, &cs); err != nil {
			return nil, fmt.Errorf("firstboot: card state: %w", err)
		}
	}
	net, err := loadSetupNet(setup)
	if owned && err != nil {
		// An owned box burns even a setup file that does not parse.
		net, err = &claim.SetupNet{}, nil
	}
	if err != nil || net == nil {
		return nil, err
	}
	if cs.Confirmed || owned {
		if err := setup.Save(nil); err != nil {
			return nil, fmt.Errorf("firstboot: burning the setup network: %w", err)
		}
		return nil, nil
	}
	return net, nil
}

// CardConfirmed says whether the card step's latch records the card
// confirmed: agentos-ap serves the card's network from then on (#1185).
// The latch is page-writable, so a forged one only serves the network the
// page itself wrote (ASSUMPTIONS.md). An empty latch is unconfirmed; one
// that does not parse is an error.
func CardConfirmed(latch []byte) (bool, error) {
	if len(latch) == 0 {
		return false, nil
	}
	var cs cardState
	if err := json.Unmarshal(latch, &cs); err != nil {
		return false, fmt.Errorf("firstboot: card state: %w", err)
	}
	return cs.Confirmed, nil
}

// Begin picks the start's route and builds its steps. It reads the latch
// first: a latch it cannot read stops the start and resets nothing. A box
// whose claim state opens is marked preloaded on the latch before
// anything else, so losing the claim state later routes to reinstall,
// never to the download path's pairing (ASSUMPTIONS.md F15). A setup
// network on a confirmed box is burned before anything else; a setup
// network without a claim state marks a sealed box too, so it routes to
// reinstall (F16), and so does any box without a claim state unless the
// config says it is the download's (BoxConfig.Download). An owned box
// never reaches Begin (agentosd checks its record first).
func Begin(cfg BoxConfig) (*FirstBoot, error) {
	fb, err := begin(cfg)
	if err != nil {
		return nil, err
	}
	fb.setup = cfg.SetupNet
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
	net, err := loadSetupNet(cfg.SetupNet)
	if err != nil {
		return nil, err
	}
	if cs.Confirmed && net != nil {
		if err := cfg.SetupNet.Save(nil); err != nil {
			return nil, fmt.Errorf("firstboot: burning the setup network: %w", err)
		}
		net = nil
	}
	cl, err := claim.Open(cfg.Claim)
	switch {
	case errors.Is(err, claim.ErrNoCode) && (cs.Preloaded || net != nil || !cfg.Download):
		return &FirstBoot{Route: RouteReinstall, Claim: reinstall{}, Card: reinstall{}, net: net}, nil
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
	return &FirstBoot{Route: RouteClaim, Claim: c, Card: c, net: net}, nil
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
